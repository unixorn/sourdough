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

'''
Read configuration parameters from instance EC2 tags, then run
chef-client.
'''

import json
import logging
import os
import subprocess
from subprocess import check_call
import sys
import urllib2

import boto.utils
import haze.ec2
import pytoml as toml

# this is a pointer to the module object instance itself. We'll attach
# a logger to it later.
this = sys.modules[__name__]

# Set some module constants
CHEF_D = '/etc/chef'
DEFAULT_ENVIRONMENT = '_default'
DEFAULT_REGION = 'undetermined-region'
DEFAULT_RUNLIST = 'nucleus'

def amRoot():
  '''
  Are we root?

  :rtype: bool
  '''
  if os.getuid() == 0:
    return True
  else:
    return False


def systemCall(command):
  '''
  Run a command and return stdout.

  Would be better to use subprocess.check_output, but this works on 2.6,
  which is still the system Python on CentOS 7.

  :param str command: Command to run
  :rtype: str
  '''
  assert isinstance(command, basestring), ("command must be a string but is %r" % command)

  p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
  return p.stdout.read()


def getCustomLogger(name):
  '''
  Set up logging
  :param str name: What log level to set
  '''
  assert isinstance(name, basestring), ("name must be a string but is %r" % name)

  validLogLevels = ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'WARNING']

  logLevel = readKnobOrTag('logLevel')
  if not logLevel:
    logLevel = 'INFO'

  # If they don't specify a valid log level, err on the side of verbosity
  if logLevel.upper() not in validLogLevels:
    logLevel = 'DEBUG'

  numericLevel = getattr(logging, logLevel.upper(), None)
  if not isinstance(numericLevel, int):
    raise ValueError("Invalid log level: %s" % logLevel)

  logging.basicConfig(level=numericLevel, format='%(asctime)s %(levelname)-9s:%(module)s:%(funcName)s: %(message)s')
  logger = logging.getLogger(name)
  return logger


# Helpers for dealing with tag/knob data

def readKnob(knobName, knobDirectory='/etc/knobs'):
  '''
  Read a knob file and return the contents

  :param str name: Which tag/knob to look for
  :rtype: str
  '''
  assert isinstance(knobDirectory, basestring), ("knobDirectory must be a string but is %r" % knobDirectory)
  assert isinstance(knobName, basestring), ("knobName must be a string but is %r" % knobName)

  knobpath = "%s/%s" % (knobDirectory, knobName)
  if not os.path.isfile(knobpath):
    return None
  if os.access(knobpath, os.R_OK):
    with open(knobpath, 'r') as knobfile:
      data = ''.join(line.rstrip() for line in knobfile)
    return data
  else:
    return None


def getAWSAccountID():
  '''
  Print an instance's AWS account number or 0 when not in EC2
  '''
  link = "http://169.254.169.254/latest/dynamic/instance-identity/document"
  try:
    conn = urllib2.urlopen(url=link, timeout=5)
  except urllib2.URLError:
    return '0'
  jsonData = json.loads(conn.read())
  return jsonData['accountId']


def readKnobOrTag(name, connection=None):
  '''
  Read a knob file or EC2 instance tag

  :param str name: Which tag/knob to look for
  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  '''

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
      print 'Connecting to region'
      connection = getEC2connection()
    try:
      print 'Reading instance tag %s for %s' % (myIID, name)
      data = haze.ec2.readInstanceTag(instanceID=myIID, tagName=name, connection=connection)
      return data
    except RuntimeError:
      return None
  return None # No knobfile and we're either outside EC2 or no tag either


def loadHostname():
  '''
  Determine what an instance's hostname should be

  :rtype: str
  '''
  hostname = readKnobOrTag(name='Hostname')
  if not hostname:
    this.logger.debug('No hostname tag or knob, falling back to hostname command output')
    hostname = systemCall('hostname').strip()
  this.logger.debug("hostname: %s", hostname)
  return hostname


def getEnvironment():
  '''
  Determine an instance's Environment

  :rtype: str
  '''
  environment = readKnobOrTag(name='Environment')
  if not environment:
    # Load sourdough configuration values
    with open('/etc/sourdough/sourdough.toml', 'r') as yeastFile:
      yeast = toml.load(yeastFile)['chef-registration']

    if 'default_environment' in yeast.keys():
      environment = yeast['default_environment']
      this.logger.warning('Cannot read tag or knob file for environment, using %s from sourdough yeast file', environment)
    else:
      environment = DEFAULT_ENVIRONMENT
      this.logger.warning('Cannot read environment from tag or knob file, setting it to %s', environment)
  this.logger.debug('Environment: %s', environment)
  return environment.lower()


def getNodePrefix():
  '''
  Determine an instance's node prefix. Will be used in ASGs.

  :rtype: str
  '''
  node = readKnobOrTag(name='Node')
  this.logger.debug("Node: %s", node)
  return node


def getRunlist():
  '''
  Determine an instance's runlist

  :rtype: str
  '''
  runlist = readKnobOrTag(name='Runlist')
  if not runlist:
    # Load sourdough configuration values
    with open('/etc/sourdough/sourdough.toml', 'r') as yeastFile:
      yeast = toml.load(yeastFile)['chef-registration']

    if 'default_runlist' in yeast.keys():
      runlist = yeast['default_runlist']
      this.logger.warning('Cannot read runlist from tag or knob file, using %s from sourdough yeast file', runlist)
    else:
      runlist = DEFAULT_RUNLIST
      this.logger.warning('Cannot read runlist from tag or knob file, setting it to %s', runlist)

  this.logger.debug('Runlist: %s', runlist)
  return runlist


def inEC2():
  '''Detect if we're running in EC2.

  If the getAWSAccountID() returns a non-zero account ID, we're in EC2.

  :rtype: bool
  '''
  if getAWSAccountID() == '0':
    return False
  else:
    return True


def generateNodeName():
  '''
  Determine what the machine's Chef node name should be.

  If a node prefix has been set (either in TAGS or /etc/knobs/Node), we
  want AWS_REGION-NODE_PREFIX-INSTANCE_ID

  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  '''
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


def getEC2connection():
  '''
  Get a boto EC2 Connection using the keypair from the OS environment.
  '''
  aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
  aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
  return boto.ec2.connect_to_region(haze.ec2.myRegion(),
                                    aws_access_key_id=aws_access_key_id,
                                    aws_secret_access_key=aws_secret_access_key)


# Chef helper functions

def isCheffed():
  '''
  Detect if Chef has been installed on a system.

  rtype: bool
  '''
  logger = this.logger
  logger.info('Checking for existing Chef installation')
  chefFiles = ["%s/client.rb" % CHEF_D, "%s/client.pem" % CHEF_D]
  for aChefFile in chefFiles:
    logger.debug("  Checking for %s", aChefFile)
    if not os.path.isfile(aChefFile):
      logger.debug("  %s missing, Chef not installed", aChefFile)
      return False
  logger.critical('Chef client files found')
  return True


def generateClientConfiguration(nodeName=None,
                                validationClientName=None,
                                chefOrganization=None,
                                chefLogLocation=None,
                                chefServerUrl=None):
  '''
  Generate client.rb contents

  :param str nodeName: node's chef name
  :param str validationClientName: what name to use with the cert
  :param str chefOrganization: What organization name to use with Hosted Chef
  :rtype: str
  '''
  assert isinstance(chefOrganization, basestring), ("chefOrganization must be a string but is %r" % chefOrganization)
  assert isinstance(chefServerUrl, basestring), ("chefServerUrl must be a string but is %r" % chefServerUrl)
  assert isinstance(nodeName, basestring), ("nodeName must be a string but is %r" % nodeName)
  assert isinstance(validationClientName, basestring), ("validationClientName must be a string but is %r" % validationClientName)

  # We want to share our logger object across the module
  logger = this.logger

  logger.info('Generating Chef client configuration')
  logger.debug("  chefOrganization: %s", chefOrganization)
  logger.debug("  chefServerUrl: %s", chefServerUrl)
  logger.debug("  nodeName: %s", nodeName)
  logger.debug("  validationClientName: %s", validationClientName)

  clientConfiguration = """
node_name "%(nodeName)s"
log_location     %(chefLogLocation)s
chef_server_url  "%(chefServerUrl)s/%(chefOrganization)s"
validation_client_name "%(validationClientName)s"
""" % {'chefLogLocation': chefLogLocation,
       'chefOrganization': chefOrganization,
       'chefServerUrl': chefServerUrl,
       'validationClientName': validationClientName,
       'nodeName': nodeName}

  logger.debug('Client Configuration')
  logger.debug(clientConfiguration)
  return clientConfiguration


def infect(connection=None):
  '''
  Installs chef-client on an instance

  :param boto.ec2.connection connection: A boto connection to ec2
  '''
  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  # We want to share our logger object across the module
  this.logger = getCustomLogger(name='sourdough-bootstrap')
  logger = this.logger

  if isCheffed():
    raise RuntimeError, 'This machine is already Cheffed'

  logger.info('Assimilating instance into Chef')

  if inEC2():
    # Assume AWS credentials are in the environment or the instance is using an IAM role
    if not connection:
      connection = getEC2connection()

    region = haze.ec2.myRegion()
  else:
    region = readKnobOrTag('region')
  logger.debug('region: %s', region)

  # Determine parameters for initial Chef run
  runlist = getRunlist()

  try:
    environment = getEnvironment()
  except RuntimeError:
    # Setting environment to None will cause the instance to use the default
    # environment on the Chef server, which is fine.
    environment = None

  # Load sourdough configuration values
  with open('/etc/sourdough/sourdough.toml', 'r') as yeastFile:
    yeast = toml.load(yeastFile)['chef-registration']

  # Sanity checks
  if not region:
    region = DEFAULT_REGION
    logger.warning('Could not determine a region, using %s', region)

  nodeName = generateNodeName()

  # If there is no Chef Server URL specified in sourdough.toml, default to Hosted Chef
  if 'chef_server_url' in yeast.keys():
    chefServerUrl = yeast['chef_server_url']
  else:
    logger.warning('No chef_server_url in sourdough.toml, assuming you want Hosted Chef')
    chefServerUrl = 'https://api.chef.io/organizations'
  logger.info('Setting Chef Server url to %s', chefServerUrl)

  # If there is no Chef log location specified in sourdough.toml, default to STDOUT
  if 'chef_log_location' in yeast.keys():
    chefLogLocation = yeast['chef_log_location']
  else:
    chefLogLocation = 'STDOUT'
  logger.info('Setting Chef Server url to %s', chefServerUrl)

  # Configure Chef
  clientConfiguration = generateClientConfiguration(nodeName=nodeName,
                                                    chefLogLocation=chefLogLocation,
                                                    chefServerUrl=chefServerUrl,
                                                    validationClientName=yeast['validation_user_name'],
                                                    chefOrganization=yeast['organization'])

  firstbootJsonPath = '/etc/chef/first-boot.json'
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

  logger.debug("Writing %s", firstbootJsonPath)
  with open(firstbootJsonPath, 'w') as firstbootJson:
    firstbootJson.write('{"run_list":["nucleus"]}')

  # Resistance is futile.
  logger.info('Assimilating node %s...', nodeName)
  logger.debug("  chef-client: %s", systemCall('which chef-client').strip())
  borgCommand = ['chef-client', '--json-attributes', firstbootJsonPath, '--validation_key', yeast['validation_key']]
  logger.debug("borg command: %s", borgCommand)

  check_call(borgCommand)


def runner(connection=None):
  '''
  Run chef-client on an instance, reading Runlist and Enviroment from tags

  :param boto.ec2.connection connection: A boto connection to ec2
  '''

  # We want to share our logger object across all our functions
  this.logger = getCustomLogger(name='sourdough-runner')
  logger = this.logger

  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  if not isCheffed():
    raise RuntimeError, 'Chef has not been installed'

  if inEC2():
    # Assume AWS credentials are in the environment or the instance is using an IAM role
    if not connection:
      connection = getEC2connection()

    region = haze.ec2.myRegion()
  else:
    region = readKnobOrTag('region')

  if not region:
    region = DEFAULT_REGION
  logger.debug('region: %s', region)

  runlist = getRunlist()
  try:
    environment = getEnvironment()
  except RuntimeError:
    environment = None

  chefCommand = ['chef-client', '--run-lock-timeout', '0', '--runlist', runlist]
  if environment:
    chefCommand = chefCommand + ['--environment', environment]

  logger.debug("chefCommand: %s", chefCommand)
  check_call(chefCommand)


def deregisterFromChef():
  '''
  Deregister a node from Chef
  '''
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
  print 'This is a library, not a stand alone script'
  sys.exit(1)
