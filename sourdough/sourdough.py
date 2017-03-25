#!/usr/bin/env python
#
# Copyright 2017 Joe Block <jpb@unixorn.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import boto.utils
import haze.ec2
import json
import logging
import os
import subprocess
import sys

import pytoml as toml
from subprocess import check_call

# this is a pointer to the module object instance itself. We'll attach
# a logger to it later.
this = sys.modules[__name__]

# Set some module constants
CHEF_D = '/etc/chef'

def amRoot():
  """Are we root?

  :rtype: bool
  """
  if os.getuid() == 0:
    return True
  else:
    return False


def system_call(command):
  """Run a command and return stdout.

  Would be better to use subprocess.check_output, but this works on 2.6,
  which is still the system Python on CentOS 7.

  :param str command: Command to run
  :rtype: str
  """
  p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
  return p.stdout.read()


def getCustomLogger(name):
  """Set up logging
  :param str name: What log level to set
  """
  valid_log_levels = ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'WARNING']

  logLevel = readKnob('logLevel')
  if not logLevel:
    logLevel = 'INFO'

  # If they don't specify a valid log level, err on the side of verbosity
  if logLevel.upper() not in valid_log_levels:
    logLevel = 'DEBUG'

  numeric_level = getattr(logging, logLevel.upper(), None)
  if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)
  logging.basicConfig(level=numeric_level, format='%(asctime)s %(levelname)-9s:%(module)s:%(funcName)s: %(message)s')
  logger = logging.getLogger(name)
  return logger


# Helpers for dealing with tag/knob data

def readKnob(knobName, knobDirectory='/etc/knobs'):
  """Read a knob file and return the contents

  :param str name: Which tag/knob to look for
  :rtype: str
  """
  assert isinstance(knobDirectory, basestring), ("knobDirectory must be a string but is %r" % knobDirectory)
  assert isinstance(knobName, basestring), ("knobName must be a string but is %r" % knobName)
  knobpath = "%s/%s" % (knobDirectory, knobName)
  if not os.path.isfile(knobpath):
    return None
  if os.access(knobpath, os.R_OK):
    with open (knobpath, "r") as knobfile:
      # data = knobfile.readlines()
      data="".join(line.rstrip() for line in knobfile)
    return data
  else:
    return None


def readKnobOrTag(name, connection=None):
  """Read a knob file or EC2 instance tag

  :param str name: Which tag/knob to look for
  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  """

  # First, look for a knob file. If that exists, we don't care what the
  # tags say.  This way we work in vagrant VMs or on bare metal.
  data = readKnob(knobName=name)
  if data:
    return data

  if inEC2():
    # No knob file, so check the tags
    myIID = haze.ec2.myInstanceID()

    # We assume AWS credentials are in the environment or the instance is
    # using an IAM role.
    if not connection:
      connection = boto.ec2.connect_to_region(haze.ec2.myRegion())
    try:
      data = haze.ec2.readInstanceTag(instanceID=myIID, tagName=name, connection=connection)
      return data
    except RuntimeError:
      return None


def loadHostname(connection=None):
  """Determine what an instance's hostname should be

  :rtype: str
  """
  hostname = readKnobOrTag(name='Hostname')
  if not hostname:
    this.logger.debug('No hostname tag or knob, falling back to hostname command output')
    hostname = system_call('hostname')
  this.logger.debug("hostname: %s", hostname)
  return hostname


def getEnvironment(connection=None):
  """Determine an instance's Environment

  :rtype: str
  """
  environment = readKnobOrTag(name='Environment')
  this.logger.debug("Environment: %s", environment)
  return environment


def getNodePrefix(connection=None):
  """Determine an instance's node prefix. Will be used in ASGs.

  :rtype: str
  """
  node = readKnobOrTag(name='Node')
  this.logger.debug("Node: %s", node)
  return node


def getRunlist(connection=None):
  """Determine an instance's runlist

  :rtype: str
  """
  runlist = readKnobOrTag(name='Runlist')
  this.logger.debug("Runlist: %s", runlist)
  return runlist


def inEC2():
  """Detect if we're running in EC2.

  This check only works if we're running as root

  :rtype: bool
  """
  dmidata = system_call('dmidecode -s bios-version').strip().lower()
  this.logger.debug("dmidata: %s", dmidata)
  return 'amazon' in dmidata


def generateNodeName(connection=None):
  """Determine what the machine's Chef node name should be.

  If a node prefix has been set (either in TAGS or /etc/knobs/Node), we
  want AWS_REGION-NODE_PREFIX-INSTANCE_ID

  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  """
  logger = this.logger
  logger.info('Determining Chef node name')
  if inEC2():
    logger.info('Running in EC2')
    region = haze.ec2.myRegion()
    node_name = "%s" % region

    node_prefix = getNodePrefix()
    if node_prefix:
      node_name = "%s-%s" % (node_name, node_prefix)
      instanceID = haze.ec2.myInstanceID()
      node_name = "%s-%s" % (node_name, instanceID)
    else:
      node_name = "%s-%s" % (node_name, loadHostname())
  else:
    logger.info('Not in EC2, using hostname')
    node_name = loadHostname()
  return node_name


# Chef helper functions

def isCheffed():
  """Detect if Chef has been installed on a system.

  rtype: bool
  """
  logger = this.logger
  logger.info('Checking for existing Chef installation')
  chef_files = ["%s/client.rb" % CHEF_D, "%s/client.pem" % CHEF_D]
  for chef_file in chef_files:
    logger.debug("  Checking for %s", chef_file)
    if not os.path.isfile(chef_file):
      logger.debug("  %s missing, Chef not installed", chef_file)
      return False
  logger.critical("Chef client files found")
  return True


def generateClientConfiguration(nodeName=None,
                                validationClientName=None,
                                chefOrganization=None):
  """Generate client.rb contents

  :param str nodeName: node's chef name
  :param str validationClientName: what name to use with the cert
  :param str chefOrganization: What organization name to use with Hosted Chef
  :rtype: str
  """

  # We want to share our logger object across the module
  logger = this.logger

  logger.info('Generating Chef client configuration')
  logger.debug("  chefOrganization: %s", chefOrganization)
  logger.debug("  nodeName: %s", nodeName)
  logger.debug("  validationClientName: %s", validationClientName)

  clientConfiguration = """
log_location     STDOUT
chef_server_url  "https://api.chef.io/organizations/%(chefOrganization)s"
validation_client_name "%(validationClientName)s"
node_name "%(nodeName)s"
  """ % { 'chefOrganization': chefOrganization,
          'validationClientName': validationClientName,
          'nodeName': nodeName }

  logger.debug('Client Configuration')
  logger.debug(clientConfiguration)
  return clientConfiguration


def infect(connection=None):
  """Installs chef-client on an instance

  :param boto.ec2.connection connection: A boto connection to ec2
  """
  if not amRoot():
    raise RuntimeError, "This must be run as root"

  # We want to share our logger object across the module
  this.logger = getCustomLogger(name='sourdough-bootstrap')
  logger = this.logger

  if isCheffed():
    raise RuntimeError, "This machine is already Cheffed"

  logger.info('Assimilating instance into Chef')

  # Assume AWS credentials are in the environment or the instance is using an IAM role
  if not connection:
    connection = boto.ec2.connect_to_region(haze.ec2.myRegion())

  region = haze.ec2.myRegion()

  # Determine parameters for initial Chef run
  runlist = getRunlist(connection=connection)

  try:
    environment = getEnvironment(connection=connection)
  except RuntimeError:
    environment = None

  # Load sourdough configuration values
  with open('/etc/sourdough/sourdough.toml','r') as yeastFile:
    yeast = toml.load(yeastFile)['chef-registration']

  # Sanity check
  if not runlist:
    # Use runlist from sourdough starter
    if 'default_runlist'in yeast.keys():
      logger.debug("Using runlist from sourdough starter")
      runlist = yeast['default_runlist']
    else:
      raise RuntimeError, "Could not determine the runlist"
  else:
    logger.info("Using runlist: %s", runlist)

  nodeName = generateNodeName()

  # Configure Chef
  clientConfiguration = generateClientConfiguration(nodeName=nodeName,
    validationClientName=yeast['validation_user_name'],
    chefOrganization=yeast['organization'])

  fb_json_path = '/etc/chef/first-boot.json'
  client_rb_path = '/etc/chef/client.rb'

  if not os.path.exists('/etc/chef'):
    logger.info('Creating /etc/chef')
    os.makedirs('/etc/chef')

  if os.path.exists('/etc/chef/client.pem'):
    logger.warning('Found stale /etc/chef/client.pem')
    os.remove('/etc/chef/client.pem')

  logger.debug("Writing %s", client_rb_path)
  with open(client_rb_path, 'w') as client_rb:
    client_rb.write(clientConfiguration)

  logger.debug("Writing %s", fb_json_path)
  with open(fb_json_path, 'w') as firstboot_json:
    firstboot_json.write('{"run_list":["nucleus"]}')

  # Resistance is futile.
  logger.info('Assimilating node %s...', nodeName)
  logger.debug("  chef-client: %s", system_call('which chef-client'))
  borg_command = ['chef-client', '--json-attributes', fb_json_path, '--validation_key', yeast['validation_key']]
  logger.debug("borg command: %s", borg_command)

  check_call(borg_command)


def runner(connection=None):
  """Run chef-client on an instance, reading Runlist and Enviroment from tags

  :param boto.ec2.connection connection: A boto connection to ec2
  """

  if not amRoot():
    raise RuntimeError, "This must be run as root"

  # We want to share our logger object across all our functions
  this.logger = getCustomLogger(name='sourdough-runner')
  logger = this.logger

  # Assume AWS credentials are in the environment or the instance is using an IAM role
  if not connection:
    connection = boto.ec2.connect_to_region(haze.ec2.myRegion())

  region = haze.ec2.myRegion()
  runlist = getRunlist(connection=connection)
  try:
    environment = getEnvironment(connection=connection)
  except RuntimeError:
    environment = None

  # Sanity check
  if not runlist:
    raise RuntimeError, "Could not determine the runlist"

  chefCommand = ['chef-client', '--runlist', runlist]
  if environment:
    chefCommand = chefCommand + ['--environment', environment]

  logger.debug("chefCommand: %s", chefCommand)

  check_call(chefCommand)


def deregisterFromChef():
  """Deregister a node from Chef"""
  clientID = system_call("awk '/node_name/ {print $2}' < /etc/chef/client.rb").replace('"', '').strip()
  system_call("knife node delete -y -c /etc/chef/client.rb %s" % (clientID))
  system_call("knife client delete -y -c /etc/chef/client.rb %s" % (clientID))


if __name__ == '__main__':
  run()
