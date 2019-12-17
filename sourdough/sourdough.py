#!/usr/bin/env python
#
# Copyright 2017-2019 Joe Block <jpb@unixorn.net>
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
Read configuration parameters from instance EC2 or vSphere tags, then run
chef-client.
'''

import datetime
import json
import logging
import os
import re
import socket
import ssl
import subprocess
from subprocess import check_call
import sys
import urllib2

import boto.utils
import haze.ec2
import pytoml as toml
from pyVim.connect import SmartConnect
from pyVmomi import vim

# This is a pointer to the module object instance itself. We'll attach
# a logger to it later.
this = sys.modules[__name__]

# Set some module constants
CHEF_D = '/etc/chef'
DEFAULT_CONNECTION_TIMEOUT=15
DEFAULT_ENVIRONMENT = '_default'
DEFAULT_KNOB_DIRECTORY = '/etc/knobs'
DEFAULT_NODE_PREFIX = 'chef_node'
DEFAULT_REGION = 'undetermined-region'
DEFAULT_RUNLIST = 'nucleus'
DEFAULT_TOML_FILE = '/etc/sourdough/sourdough.toml'
DEFAULT_VMWARE_CONFIG = '/etc/sourdough/vmware.toml'
DEFAULT_VOLUMES_DIRECTORY = '/etc/device-volumes.d'
DEFAULT_VSPHERE_KNOB = 'vsphere_host.toml'
DEFAULT_WAIT_FOR_ANOTHER_CONVERGE = 600
DISABLE_SOURDOUGH_F = "/etc/sourdough/Disable-Sourdough"
DISABLE_VSPHERE = '/etc/sourdough/disable-vsphere'
ENABLE_SOURDOUGH_DEBUGGING_F = "/etc/sourdough/debug-sourdough"

knobsCache = {}
vmwareTags = {}


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

  It would be better to use subprocess.check_output, but this works on 2.6,
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
  :rtype Logger object
  '''
  assert isinstance(name, basestring), ("name must be a string but is %r" % name)

  validLogLevels = ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'WARNING']

  logLevel = readKnob('LogLevel')
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
    print 'readKnob: No such file: %s. This is normal, not all machines have every tag set.' % (knobpath)
    return None
  if os.access(knobpath, os.R_OK):
    with open(knobpath, 'r') as knobfile:
      data = ''.join(line.rstrip() for line in knobfile)
    return data
  else:
    print 'readKnob: Cannot read %s' % (knobpath)
    return None


def writeKnob(name, value, knobDirectory='/etc/knobs'):
  '''
  Write to a knob file

  :param str name: Which knob to write
  :param str value: What value to write to the knobfile
  '''
  assert isinstance(knobDirectory, basestring), ("knobDirectory must be a string but is %r" % knobDirectory)
  assert isinstance(name, basestring), ("name must be a string but is %r" % name)
  assert isinstance(value, basestring), ("value must be a string but is %r" % value)

  loadSharedLogger()
  knobPath = "%s/%s" % (knobDirectory, name)
  if not os.path.isdir(knobDirectory):
    this.logger.error('directory %s does not exist, creating it', knobDirectory)
    systemCall('mkdir -p %s' % knobDirectory)
  if value is not None:
    with open(knobPath, 'w') as knobFile:
      this.logger.info('Writing %s to %s', value, knobPath)
      knobFile.write(value)
  else:
    this.logger.debug('%s has a value of %s, skipping write', name, value)


def getAWSAccountID():
  '''
  Print an instance's AWS account number or 0 when not in EC2

  :rtype: int
  '''
  link = "http://169.254.169.254/latest/dynamic/instance-identity/document"
  try:
    conn = urllib2.urlopen(url=link, timeout=5)
  except:
    return '0'
  jsonData = json.loads(conn.read())
  return jsonData['accountId']


def readKnobOrTag(name, connection=None, knobDirectory='/etc/knobs'):
  '''
  Read tag/knob data from the knobsCache if present, set the cache if not.

  :param str name: Name of the tag we want to load
  :param str knobDirectory: What directory to search for knob files
  :rtype: str
  '''
  if name not in knobsCache:
    knobValue = readKnobOrTagValue(name, connection, knobDirectory)
    knobsCache[name] = knobValue
  return knobsCache[name]


def readKnobOrTagValue(name, connection=None, knobDirectory='/etc/knobs'):
  '''
  Read a knob file or EC2 instance tag

  :param str name: Which tag/knob to look for
  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  '''
  assert isinstance(name, basestring), ("name must be a string but is %r" % name)

  data = None
  loadSharedLogger()

  if inEC2():
    this.logger.debug('in EC2')
    # Check the tags
    myIID = haze.ec2.myInstanceID()

    # We assume AWS credentials are in the environment or the instance is
    # using an IAM role.
    if not connection:
      this.logger.info('Connecting to region')
      connection = getEC2connection()
    try:
      this.logger.info('Reading %s instance tag on %s', name, myIID)
      data = haze.ec2.readInstanceTag(instanceID=myIID, tagName=name, connection=connection)
      if data:
        this.logger.debug('Caching EC2 tag %s value %s in knob file', name, data)
        writeKnob(name=name, value=data, knobDirectory='/etc/knobs')
    except RuntimeError:
      this.logger.error('Caught RuntimeError reading %s EC2 instance tag', name)

  if inVMware():
    this.logger.info('inVMware')
    try:
      data = readVirtualMachineTag(name)
      if data:
        this.logger.debug('Caching VMware tag %s value %s in knob file', name, data)
        writeKnob(name=name, value=data, knobDirectory='/etc/knobs')
      else:
        this.logger.error('Could not read %s virtual machine tag', name)
    except RuntimeError:
      this.logger.error('Caught RuntimeError reading virtual machine tag')

  if not data:
    # Finally, look for a knob file if we couldn't read tag data.
    # This way we work in vagrant VMs or on bare metal, and we cope if
    # there is a temporary issue getting tags since we rewrite the knobs
    # every time we successfully read tags.
    this.logger.info('Cannot load tag data for %s, attempting load from knob file cache', name)
    data = readKnob(knobName=name, knobDirectory=knobDirectory)

  this.logger.debug('tag %s = %s', name, data)
  return data


def getIP():
  '''
  Determine our IP

  :rtype str:
  '''
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    # doesn't even have to be reachable
    s.connect(('10.255.255.255', 1))
    IP = s.getsockname()[0]
  except:
    IP = '127.0.0.1'
  finally:
    s.close()
  return IP


def loadVSphereSettings(knobName=DEFAULT_VSPHERE_KNOB, knobDirectory=DEFAULT_KNOB_DIRECTORY):
  '''
  Load cached vSphere settings. If there's no cache, use detectVSphereHost
  to create one.

  :param str knobName: What file name to write the vsphere data to
  :param str knobDirectory: What directory to write the knob file in

  :rtype dict:
  '''
  assert isinstance(knobDirectory, basestring), ("knobDirectory must be a string but is %r" % knobDirectory)
  assert isinstance(knobName, basestring), ("knobName must be a string but is %r" % knobName)

  loadSharedLogger()
  fpath = "%s/%s" % (knobDirectory, knobName)
  if os.path.isfile(fpath):
    this.logger.debug('Reading cached vSphere data from %s', fpath)
    try:
      with open(fpath, 'r') as vmwareConfig:
        vsphereSettings = toml.load(vmwareConfig)
        this.logger.debug('Loaded vSphere connection info: %r', vsphereSettings)
        if vsphereSettings['hostname'] and vsphereSettings['password'] and vsphereSettings['username']:
          return vsphereSettings
        else:
          this.logger.critical('Failed to load all parameters from cached vSphereSettings toml file')
          return None

    except RuntimeError:
      this.logger.critical('Error loading %s - is the toml valid?', fpath)
  else:
    this.logger.info('No vSphere cache file at %s', fpath)

  this.logger.warning('Failed to load vSphere settings from cache file, searching for hypervisor.')
  hypervisor = detectVSphereHost()
  this.logger.debug('hypervisor: %r', hypervisor)
  return hypervisor


def writeVSphereSettings(knobName=DEFAULT_VSPHERE_KNOB, knobDirectory=DEFAULT_KNOB_DIRECTORY, hostname=None, username=None, password=None):
  '''
  Write the vsphere host information to a knob file so we don't have to determine it
  every single time we read a tag.

  :param str knobName: What file name to write the vsphere data to
  :param str knobDirectory: What directory to write the knob file in
  :param str hostname: hostname of the vSphere host
  :param str user: username to connect to vSphere
  :param str password: password to connect to vSphere
  '''
  assert isinstance(hostname, basestring), ("hostname must be a string but is %r" % hostname)
  assert isinstance(knobDirectory, basestring), ("knobDirectory must be a string but is %r" % knobDirectory)
  assert isinstance(knobName, basestring), ("knobName must be a string but is %r" % knobName)
  assert isinstance(password, basestring), ("password must be a string but is %r" % password)
  assert isinstance(username, basestring), ("username must be a string but is %r" % username)

  loadSharedLogger()
  knobPath = "%s/%s" % (knobDirectory, knobName)
  if not os.path.isdir(knobDirectory):
    this.logger.info('writeVsphereSettings: directory %s does not exist, creating it', knobDirectory)
    systemCall('mkdir -p %s' % knobDirectory)

  with open(knobPath, 'w') as knobFile:
    this.logger.info('Writing vSphere connection info to %s', knobPath)
    settings = {}
    settings['hostname'] = hostname
    settings['username'] = username
    settings['password'] = password
    knobFile.write(toml.dumps(settings))


def detectVSphereHost():
  '''
  Determine which vsphere host to use, then write it to cache.

  Returns the settings information.

  :rtype dict:
  '''
  loadSharedLogger()
  vm_ip = getIP()

  this.logger.debug('Trying to find a vsphere host')
  this.logger.debug('Cached vmwareTags: %r', vmwareTags)
  this.logger.debug('vm_ip:%s', vm_ip)
  if vm_ip not in vmwareTags:
    vmwareTags['VM_IP'] = vm_ip

  secure=ssl.SSLContext(ssl.PROTOCOL_TLSv1)
  secure.verify_mode=ssl.CERT_NONE

  this.logger.debug('Set secure.verify_mode to ssl.CERT_NONE')

  try:
    with open(DEFAULT_VMWARE_CONFIG, 'r') as vmwareConfig:
      vcenters = toml.load(vmwareConfig)['vcenters']
  except IOError as error:
    this.logger.error('Could not open %s', DEFAULT_VMWARE_CONFIG)
    return None

  this.logger.debug('vcenters: %r', vcenters)
  for k,v in vcenters.iteritems():
    hostname = v.get('hostname')
    username = v.get('user')
    password = v.get('password')
    this.logger.debug('Trying hostname:%s username:%s password:%s',  hostname, username, password)
    try:
      si= SmartConnect(host=hostname, user=username, pwd=password, sslContext=secure)
      settings = {}
      settings['hostname'] = hostname
      settings['password'] = password
      settings['username'] = username
      this.logger.debug('Was able to connect to vSphere hypervisor %s with settings: %r', hostname, settings)
      writeVSphereSettings(hostname=hostname, username=username, password=password)
      return settings
    except socket.error:
      this.logger.info('Cannot connect to vSphere hypervisor %s', hostname)


def connectVcenter():
  '''
  Connect to Vcenter Server

  Returns the UUID and Vcenter Connection objects dict
  :rtype dict:
  '''
  uuid = getUUID()
  loadSharedLogger()
  secure=ssl.SSLContext(ssl.PROTOCOL_TLSv1)
  secure.verify_mode=ssl.CERT_NONE
  vSphereConnetionObjects = {}

  this.logger.debug('secure.verify_mode=ssl.CERT_NONE')

  vSphereSettings = loadVSphereSettings()
  if not vSphereSettings:
    this.logger.error('Could not load vSphereSettings!')
    return None
  this.logger.debug('vSphereSettings: %r', vSphereSettings)

  hostname = vSphereSettings['hostname']
  password = vSphereSettings['password']
  username = vSphereSettings['username']
  this.logger.debug('hostname=%s user=%s password=%s', hostname, username, password)

  try:
    si= SmartConnect(host=hostname, user=username, pwd=password, sslContext=secure)
    this.logger.debug('SmartConnect succeeded')
    searcher = si.content.searchIndex
    this.logger.debug('Searching for VM for UUID %s', uuid)
    vm = searcher.FindByUuid(uuid=uuid, vmSearch=True)
    vSphereConnetionObjects['uuid'] = uuid
    vSphereConnetionObjects['si'] = si
    vSphereConnetionObjects['vm'] = vm
    print "Connection Objects", vSphereConnetionObjects
    return vSphereConnetionObjects
  except socket.error:
    this.logger.info('Cannot connect to vSphere host %s to read VMWare tags', hostname)


def readVirtualMachineTag(tagName):
  '''
  Read Tags / Attributes from VM by UUID

  :param str tagName: tag to read
  :rtype: str
  '''
  # Check the tag cache first to avoid unnecessary vSphere interactions
  if tagName in vmwareTags:
    this.logger.debug('Cache hit for %s: %s', tagName, vmwareTags[tagName])
    return vmwareTags[tagName]
  else:
    this.logger.debug('Cache fail for %s, beginning vSphere tag load', tagName)
    if os.path.isfile(DISABLE_VSPHERE):
      this.logger.warning('Found %s, skipping vSphere reads', DISABLE_VSPHERE)
      return None

    vSphereConnetionObjects = connectVcenter()
    uuid = vSphereConnetionObjects.get('uuid')
    si = vSphereConnetionObjects.get('si')
    vm = vSphereConnetionObjects.get('vm')
    if vm:
      this.logger.debug('Found VM object for UUID %s, loading tags', uuid)
      f = si.content.customFieldsManager.field
      for k, v in [(x.name, v.value) for x in f for v in vm.customValue if x.key == v.key]:
        vmwareTags[k] = v
        this.logger.debug('Caching tag:%s=%s', k, v)


def volumeTag():
  '''
  Read Volume tags and determine the Disk Bus number and Unit number

  Write those values into /etc/device-volumes.d directory
  '''
  loadSharedLogger()
  volumes = readKnobOrTag(name='Volumes')
  vSphereConnetionObjects = connectVcenter()
  uuid = vSphereConnetionObjects.get('uuid')
  si = vSphereConnetionObjects.get('si')
  vm = vSphereConnetionObjects.get('vm')
  if volumes is not None:
    this.logger.debug('volumes = %s', volumes)
    for k,v in dict(item.split("=") for item in volumes.split(",")).iteritems():
      if not os.path.isdir(DEFAULT_VOLUMES_DIRECTORY):
        this.logger.warning("%s missing, creating...", DEFAULT_VOLUMES_DIRECTORY)
        systemCall("mkdir -p %s" % DEFAULT_VOLUMES_DIRECTORY)
      file_path  = DEFAULT_VOLUMES_DIRECTORY + '/' + k
      if not os.path.exists(file_path):
        disk = None
        this.logger.info('Checking Volume %s', v)
        pattern = r".*\/{}.vmdk$".format(v)
        this.logger.debug("vm.config.hardware.device: %s", vm.config.hardware.device)
        for d in vm.config.hardware.device:
          this.logger.info('Checking device %s', d)
          if type(d).__name__ == 'vim.vm.device.VirtualDisk' and re.match(pattern, d.backing.fileName):
            this.logger.info("Found disk match %s", d.backing.fileName)
            disk = d
          else:
            this.logger.info("Did not find disk")
        if disk:
          this.logger.info('Disk name: %s', disk.backing.fileName)
          for c in vm.config.hardware.device:
            if c.key == disk.controllerKey:
               controller = c
          file_content = "scsi:{}:{}".format(str(controller.busNumber), str(disk.unitNumber))
          this.logger.info('Disk %s bus Number: %s', disk.backing.fileName, controller.busNumber)
          this.logger.info('Disk %s unit Number: %s', disk.backing.fileName, disk.unitNumber)
          this.logger.info('Writing %s in the file %s', file_content, file_path)
          with open(file_path, 'w') as f:
            f.write(file_content)
        else:
          this.logger.warning('disk not found!')
  else:
    this.logger.warning('No Volume tag information found, skipping')


def loadHostname():
  '''
  Determine what an instance's hostname should be

  :rtype: str
  '''
  loadSharedLogger()
  hostname = readKnobOrTag(name='Hostname')
  if not hostname:
    this.logger.debug('No hostname tag or knob, falling back to hostname command output')
    hostname = systemCall('hostname').strip()
  this.logger.debug('hostname: %s', hostname)
  return hostname


def getUUID():
  '''
  Get the UUID of this VM

  :rtype: str
  '''
  loadSharedLogger()
  uuid = systemCall("dmidecode | awk '/UUID/ {print $2}'").strip()
  this.logger.info('VM UUID: %s', uuid)
  return uuid


def loadSharedLogger():
  try:
    logger = this.logger
  except AttributeError:
    this.logger = getCustomLogger('no-logger')


def readSetting(setting, fallback=None, tomlFile=DEFAULT_TOML_FILE, knobDirectory='/etc/knobs'):
  '''
  Read a setting value from AWS tag, VMware Tag/attribute, knob file, or sourdough.toml in
  that order, and return the fallback if we can't find another value.

  :param str setting: Which setting to search for
  :param str tomlFie: Path to TOML format settings file

  :rtype: str or int
  '''
  assert isinstance(setting, basestring), ("setting must be a string but is %r" % setting)
  assert isinstance(tomlFile, basestring), ("tomlFile must be a string but is %r" % tomlFile)

  loadSharedLogger()
  v = readKnobOrTag(setting, knobDirectory=knobDirectory)
  if not v:
    # Did they stick it in the toml settings file?
    with open(tomlFile, 'r') as yeastFile:
      yeast = toml.load(yeastFile)['chef-registration']
    if setting in yeast.keys():
      v = yeast[setting]
      this.logger.warning('Cannot read tag or knob file for %s, using %s from sourdough yeast file', setting, v)
    else:
      v = fallback
      this.logger.warning('Cannot read tag or knob file for %s, using fallback value of %s', setting, v)
  this.logger.debug('%s: %s', setting, v)
  return v


def getConnectionWait():
  '''
  How long should we wait for network connections?

  :rtype: int
  '''
  return readSetting(setting='connection_wait', fallback=DEFAULT_CONNECTION_TIMEOUT)


def setConnectionWait():
  '''
  Set network connection timeout
  '''
  loadSharedLogger()
  logger = this.logger
  try:
    connectionWait = getConnectionWait()
    this.logger.debug('Setting socket.setdefaulttimeout to %r', connectionWait)
    socket.setdefaulttimeout(connectionWait)
  except TypeError:
    this.logger.error('Could not set socket.setdefaulttimeout to %r', connectionWait)


def getConvergeWait():
  '''
  How long should we wait for another chef-client converge run to finish?

  :rtype: int
  '''
  return readSetting(setting='converge_wait', fallback=DEFAULT_WAIT_FOR_ANOTHER_CONVERGE)


def getEnvironment():
  '''
  Determine an instance's Chef Environment

  :rtype: str
  '''
  environment = readKnobOrTag(name='Environment')
  if not environment:
    environment = readSetting(setting='default_environment', fallback=DEFAULT_ENVIRONMENT)
  return environment.lower()


def getNodePrefix():
  '''
  Determine an instance's node prefix. Will be used in ASGs.

  :rtype: str
  '''
  node = readSetting(setting='Node', fallback=DEFAULT_NODE_PREFIX)
  return node


def getRunlist():
  '''
  Determine an instance's runlist

  :rtype: str
  '''
  runlist = readKnobOrTag(name='Runlist')
  if not runlist:
    runlist = readSetting(setting='default_runlist', fallback=DEFAULT_RUNLIST)
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


def inVMware():
  '''
  Detect if we're running in VMware.

  Check ohai output - key hostnamectl.virtualization tells us what hypervisor we're on.

  :rtype: bool
  '''
  try:
    hypervisor = subprocess.check_output("ohai | jq '.hostnamectl.virtualization' | grep -c vmware", shell=True).strip()
    if hypervisor == '1':
      return True
    else:
      return False
  except subprocess.CalledProcessError:
    # grep exits 1 when it can't find the search string
    return False


def generateNodeName():
  '''
  Determine what the machine's Chef node name should be.

  If a node prefix has been set (either in TAGS or /etc/knobs/Node), we
  want AWS_REGION-NODE_PREFIX-INSTANCE_ID

  :param boto.ec2.connection connection: A boto connection to ec2
  :rtype: str
  '''
  loadSharedLogger()
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

def loadClientEnvironmentVariables(envFile='/etc/sourdough/environment-variables.json'):
  '''
  See if there are extra environment variables to pass to chef-client

  rtype: dict
  '''
  assert isinstance(envFile, basestring), ("envFile must be a string but is %r" % envFile)

  loadSharedLogger()
  try:
    if os.access(envFile, os.R_OK):
      with open(envFile) as environmentJSON:
        extraEnvironmentVariables = json.load(environmentJSON)
        this.logger.info('Customizing chef-client environment from %s', envFile)
        this.logger.info('  Environment overrides: %s', extraEnvironmentVariables)
        return extraEnvironmentVariables
    else:
      this.logger.warn('%s does not exist, skipping environment customization', envFile)
      return {}
  except Exception as err:
    this.logger.warn("Could not load env vars from %s", envFile)
    this.logger.warn("Error: {0}".format(err))
    return {}


def isCheffed():
  '''
  Detect if Chef has been installed on a system.

  rtype: bool
  '''
  loadSharedLogger()
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


def isDisabled():
  '''
  Detect if Chef converge is deliberately disabled on a system.

  rtype: bool
  '''
  loadSharedLogger()
  logger = this.logger
  logger.info('Checking for disable switch')
  logger.debug("  Checking for %s", DISABLE_SOURDOUGH_F)
  if os.path.isfile(DISABLE_SOURDOUGH_F):
      logger.debug("  %s found", DISABLE_SOURDOUGH_F)
      logger.critical('Chef converge disabled')
      return True
  logger.info('Disable switch not found')
  return False


def isDebugging():
  '''
  Detect if sourdough is being debugged.

  rtype: bool
  '''
  loadSharedLogger()
  logger = this.logger
  logger.debug('Checking for DEBUG switch')
  debugFile = "/etc/sourdough/debug-sourdough"
  logger.debug("  Checking for %s", debugFile)
  if os.path.isfile(debugFile):
      logger.debug("  %s found", debugFile)
      logger.critical('sourdough in DEBUG mode')
      return True
  logger.debug('Debug switch not found')
  return False


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

  loadSharedLogger()
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


def createEnvForClient():
  '''
  Create environment variables for chef-client

  rtype: dict
  '''
  # Start constructing the environment vars for chef-client
  clientEnvVars = {}

  # Load any extra env vars we want to pass
  clientVars = loadClientEnvironmentVariables()

  # Start with our environment
  clientEnvVars.update(os.environ)

  # Override os environment with any vars specified in
  # environment-variables.json, but don't replace, just
  # add from our extras and replace any vars with the same
  # names
  clientEnvVars.update(clientVars)
  return clientEnvVars


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
    logger.error('This machine is already Cheffed')
    raise RuntimeError, 'This machine is already Cheffed'

  logger.info('Assimilating instance into Chef')

  setConnectionWait()

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

  # Use custom environment vars for chef-client
  clientEnvVars = createEnvForClient()

  # How long should we wait for other chef-client processes to finish?
  convergeDelay = "%s" % getConvergeWait() # Convert to string to keep check_call happy

  # Resistance is futile.
  logger.info('Assimilating node %s...', nodeName)
  logger.debug("  chef-client: %s", systemCall('which chef-client').strip())
  borgCommand = ['chef-client',
                 '--json-attributes', firstbootJsonPath,
                 '--validation_key', yeast['validation_key'],
                 '--run-lock-timeout', convergeDelay]
  logger.debug("borg command: %s", borgCommand)
  check_call(borgCommand, env=clientEnvVars)


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

  if isDisabled():
    sys.exit(1)

  setConnectionWait()

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

  if inVMware():
    volumeTag()

  # How long should we wait for other chef-client processes to finish?
  convergeDelay = "%s" % getConvergeWait() # Convert to string to keep check_call happy

  # Use custom environment vars for chef-client
  clientEnvVars = createEnvForClient()

  chefCommand = ['chef-client', '--run-lock-timeout', convergeDelay, '--runlist', runlist]
  if environment:
    chefCommand = chefCommand + ['--environment', environment]

  logger.debug("chefCommand: %s", chefCommand)
  if isDebugging():
    logger.critical('Skipping chef-client, sourdough is in DEBUG mode')
    sys.exit(1)

  check_call(chefCommand, env=clientEnvVars)


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


def enableChefRuns():
  '''
  Remove the toggle file that disables Chef runs if it is present
  '''

  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  if os.path.isfile(DISABLE_SOURDOUGH_F):
    print "Removing %s" % DISABLE_SOURDOUGH_F
    os.remove(DISABLE_SOURDOUGH_F)


def disableChefRuns():
  '''
  Create the toggle file that disables Chef runs
  '''

  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  with open(DISABLE_SOURDOUGH_F, 'w') as disabler:
    print "Creating %s" % DISABLE_SOURDOUGH_F
    disabler.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def enableDebugMode():
  '''
  Remove the toggle file that enables Debug mode
  '''
  ENABLE_SOURDOUGH_DEBUGGING_F = "/etc/sourdough/debug-sourdough"

  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  with open(ENABLE_SOURDOUGH_DEBUGGING_F, 'w') as disabler:
    print "Creating %s" % ENABLE_SOURDOUGH_DEBUGGING_F
    disabler.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def disableDebugMode():
  '''
  Create the toggle file that enables debugging mode
  '''

  if not amRoot():
    raise RuntimeError, 'This must be run as root'

  if os.path.isfile(ENABLE_SOURDOUGH_DEBUGGING_F):
    print "Removing %s" % ENABLE_SOURDOUGH_DEBUGGING_F
    os.remove(ENABLE_SOURDOUGH_DEBUGGING_F)


if __name__ == '__main__':
  print 'This is a library, not a stand alone script'
  sys.exit(1)
