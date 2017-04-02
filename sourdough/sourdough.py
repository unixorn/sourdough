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

"""
Sourdough is a utility for EC2 instances running Chef.

It provides methods to make them register on boot, run (getting their
runlist and environment from EC2 tags or files in /etc/knobs), and deregister.
"""

import boto.utils
import haze.ec2
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


def systemCall(command):
  """Run a command and return stdout.

  Would be better to use subprocess.check_output, but this works on 2.6,
  which is still the system Python on CentOS 7.

  :param str command: Command to run
  :rtype: str
  """
  assert isinstance(command, basestring), ("command must be a string but is %r" % command)

  p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
  return p.stdout.read()


def getCustomLogger(name):
  """Set up logging
  :param str name: What log level to set
  """
  assert isinstance(name, basestring), ("name must be a string but is %r" % name)

  validLogLevels = ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'WARNING']

  logLevel = readKnob('logLevel')
  if not logLevel:
    logLevel = 'INFO'

  # If they don't specify a valid log level, err on the side of verbosity
  if logLevel.upper() not in validLogLevels:
    logLevel = 'DEBUG'

  numericLevel = getattr(logging, logLevel.upper(), None)
  if not isinstance(numericLevel, int):
    raise ValueError('Invalid log level: %s' % logLevel)
  logging.basicConfig(level=numericLevel, format='%(asctime)s %(levelname)-9s:%(module)s:%(funcName)s: %(message)s')
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
    with open(knobpath, 'r') as knobfile:
      # data = knobfile.readlines()
      data = ''.join(line.rstrip() for line in knobfile)
    return data
  else:
    return None


def readKnobOrTag(name, connection=None):
  """Read a knob file or EC2 instance tag

  :param str name: Which tag/knob to look for
  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  """

  assert isinstance(name, basestring), ("name must be a string but is %r" % name)

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


def loadHostname():
  """Determine what an instance's hostname should be

  :rtype: str
  """
  hostname = readKnobOrTag(name='Hostname')
  if not hostname:
    this.logger.debug('No hostname tag or knob, falling back to hostname command output')
    hostname = systemCall('hostname').strip()
  this.logger.debug("hostname: %s", hostname)
  return hostname


def getEnvironment():
  """Determine an instance's Environment

  :rtype: str
  """
  environment = readKnobOrTag(name='Environment')
  this.logger.debug("Environment: %s", environment)
  return environment


def getNodePrefix():
  """Determine an instance's node prefix. Will be used in ASGs.

  :rtype: str
  """
  node = readKnobOrTag(name='Node')
  this.logger.debug("Node: %s", node)
  return node


def getRunlist():
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
  dmidata = systemCall('dmidecode -s bios-version').strip().lower()
  this.logger.debug("dmidata: %s", dmidata)
  return 'amazon' in dmidata


def generateNodeName():
  """Determine what the machine's Chef node name should be.

  If a node prefix has been set (either in TAGS or /etc/knobs/Node), we
  want AWS_REGION-NODEPREFIX-INSTANCE_ID

  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  """
  logger = this.logger
  logger.info('Determining Chef node name')
  if inEC2():
    logger.info('Running in EC2')
    region = haze.ec2.myRegion()
    nodeName = "%s" % region

    nodePrefix = getNodePrefix()
    if nodePrefix:
      nodeName = "%s-%s" % (nodeName, nodePrefix)
      instanceID = haze.ec2.myInstanceID()
      nodeName = "%s-%s" % (nodeName, instanceID)
    else:
      nodeName = "%s-%s" % (nodeName, loadHostname())
  else:
    logger.info('Not in EC2, using hostname')
    nodeName = loadHostname()
  return nodeName


# Chef helper functions

def isCheffed():
  """Detect if Chef has been installed on a system.

  rtype: bool
  """
  logger = this.logger
  logger.info('Checking for existing Chef installation')
  chefFiles = ["%s/client.rb" % CHEF_D, "%s/client.pem" % CHEF_D]
  for aChefFile in chefFiles:
    logger.debug("  Checking for %s", aChefFile)
    if not os.path.isfile(aChefFile):
      logger.debug("  %s missing, Chef not installed", aChefFile)
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
  assert isinstance(nodeName, basestring), ("nodeName must be a string but is %r" % nodeName)
  assert isinstance(validationClientName, basestring), ("validationClientName must be a string but is %r" % validationClientName)
  assert isinstance(chefOrganization, basestring), ("chefOrganization must be a string but is %r" % chefOrganization)

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
""" % {'chefOrganization': chefOrganization,
       'validationClientName': validationClientName,
       'nodeName': nodeName}

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
  runlist = getRunlist()

  try:
    environment = getEnvironment()
  except RuntimeError:
    environment = None

  # Load sourdough configuration values
  with open('/etc/sourdough/sourdough.toml', 'r') as yeastFile:
    yeast = toml.load(yeastFile)['chef-registration']

  # Sanity check
  if not runlist:
    # Use runlist from sourdough starter
    if 'default_runlist'in yeast.keys():
      logger.debug('Using runlist from sourdough starter')
      runlist = yeast['default_runlist']
    else:
      raise RuntimeError, 'Could not determine the runlist'
  else:
    logger.info("Using runlist: %s", runlist)

  nodeName = generateNodeName()

  # Configure Chef
  clientConfiguration = generateClientConfiguration(nodeName=nodeName,
    validationClientName=yeast['validation_user_name'],
    chefOrganization=yeast['organization'])

  fbJsonPath = '/etc/chef/first-boot.json'
  clientRbPath = '/etc/chef/client.rb'

  if not os.path.exists('/etc/chef'):
    logger.info('Creating /etc/chef')
    os.makedirs('/etc/chef')

  if os.path.exists('/etc/chef/client.pem'):
    logger.warning('Found stale /etc/chef/client.pem')
    os.remove('/etc/chef/client.pem')

  logger.debug("Writing %s", clientRbPath)
  with open(clientRbPath, 'w') as clientRbFile:
    clientRbFile.write(clientConfiguration)

  logger.debug("Writing %s", fbJsonPath)
  with open(fbJsonPath, 'w') as firstbootJsonFile:
    firstbootJsonFile.write('{"run_list":["nucleus"]}')

  # Resistance is futile.
  logger.info('Assimilating node %s...', nodeName)
  logger.debug("  chef-client: %s", systemCall('which chef-client').strip())
  borgCommand = ['chef-client', '--json-attributes', fbJsonPath, '--validation_key', yeast['validation_key']]
  logger.debug("borg command: %s", borgCommand)

  check_call(borgCommand)


def runner(connection=None):
  """Run chef-client on an instance, reading Runlist and Enviroment from tags

  :param boto.ec2.connection connection: A boto connection to ec2
  """

  # We want to share our logger object across all our functions
  this.logger = getCustomLogger(name='sourdough-runner')
  logger = this.logger

  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  if not isCheffed():
    raise RuntimeError, 'Chef has not been installed'

  # Assume AWS credentials are in the environment or the instance is using an IAM role
  if not connection:
    connection = boto.ec2.connect_to_region(haze.ec2.myRegion())

  region = haze.ec2.myRegion()
  runlist = getRunlist()
  try:
    environment = getEnvironment()
  except RuntimeError:
    environment = None

  # Sanity check
  if not runlist:
    raise RuntimeError, 'Could not determine the runlist'

  chefCommand = ['chef-client', '--run-lock-timeout', '0', '--runlist', runlist]
  if environment:
    chefCommand = chefCommand + ['--environment', environment]

  logger.debug("chefCommand: %s", chefCommand)

  check_call(chefCommand)


def deregisterFromChef():
  """Deregister a node from Chef"""
  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  logger = getCustomLogger(name='sourdough-deregister')
  this.logger = logger

  clientID = systemCall("awk '/node_name/ {print $2}' < /etc/chef/client.rb").replace('"', '').strip()
  logger.info("Deregistering %s from chef", clientID)

  logger.debug("  Deleting node %s", clientID)
  systemCall("knife node delete -y -c /etc/chef/client.rb %s" % (clientID))

  logger.debug("  Deleting client %s", clientID)
  systemCall("knife client delete -y -c /etc/chef/client.rb %s" % (clientID))

  for chefFile in ['client.pem', 'client.rb']:
    if os.path.isfile("/etc/chef/%s" % chefFile):
      this.logger.info("  Scrubbing %s", chefFile)
      os.remove("/etc/chef/%s" % chefFile)


if __name__ == '__main__':
  print "Don't run this on its own."
