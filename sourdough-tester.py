#!/usr/bin/env python
#
# Sourdough
#
# Copyright 2017-2018 Joe Block <jpb@unixorn.net>
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
Test framework for sourdough

You _really_ do not want to run this in a computer you care about - it will
break your chef install.
'''

import logging
import os
import sys
import unittest
import sourdough

from sourdough.sourdough import getCustomLogger, systemCall

def installSourdoughInContainer():
  installOut = systemCall('cd /test && python setup.py develop')


def injectChefConfigFiles():
    chefFiles = [
      '/etc/chef/client.rb',
      '/etc/chef/client.pem'
    ]
    for chefFile in chefFiles:
      if not os.path.exists(chefFile):
        systemCall("touch %s" % chefFile)


class TestSourdough(unittest.TestCase):

  def setUp(self):
    self.chefFiles = [
      '/etc/chef/client.rb',
      '/etc/chef/client.pem'
    ]

  # Test that the scripts are calling chef-client correctly
  def test_bootstrap(self):
    runBootstrap = systemCall('sourdough-bootstrap')
    self.assertEqual(runBootstrap.strip(), '--json-attributes /etc/chef/first-boot.json --validation_key /etc/OmniConsumerProducts/credentials/chef/OmniConsumerProducts-validator.private.key --run-lock-timeout 900')


  def test_starter_cheffed(self):
    injectChefConfigFiles()
    cheffedRunner = systemCall('sourdough-starter')
    self.assertEqual(cheffedRunner.strip(), "--run-lock-timeout 900 --runlist ocp_base --environment _default")


  def test_starter_cheffed_and_disabled(self):
    injectChefConfigFiles()
    systemCall("touch /etc/sourdough/Disable-Sourdough")
    cheffedRunner = systemCall('sourdough-starter 2>&1 | grep -c converge')
    self.assertEqual(cheffedRunner.strip(), '1')


  def test_starter_uncheffed(self):
    for chefFile in self.chefFiles:
      if os.path.exists(chefFile):
        os.remove(chefFile)
    uncheffedRunner = systemCall('sourdough-starter 2>&1 | grep RuntimeError')
    self.assertEqual(uncheffedRunner.strip(), "raise RuntimeError, 'Chef has not been installed'\nRuntimeError: Chef has not been installed")


  def test_chef_shim(self):
    self.assertEqual(systemCall('/usr/local/bin/chef-client foo bar').strip(), 'foo bar')


  def test_inVMware(self):
    self.assertEqual(sourdough.sourdough.inVMware(), False)

  
  # Test internal functions
  def test_getAWSAccountID(self):
    self.assertEqual(sourdough.sourdough.getAWSAccountID(), '0')


  def test_getConvergeWait(self):
    self.assertEqual(sourdough.sourdough.getConvergeWait(), 900)


  def test_getRunlist(self):
    self.assertEqual(sourdough.sourdough.getRunlist(), 'ocp_base')


  def test_readKnob(self):
    self.assertEqual(sourdough.sourdough.readKnob(knobName='knobtest', knobDirectory='/test/testdata'), 'abcd')


  def test_readSetting(self):
    self.assertEqual(sourdough.sourdough.readSetting(setting='knobtest', fallback='robocop', knobDirectory='/test/testdata'), 'abcd')
    self.assertEqual(sourdough.sourdough.readSetting(setting='organization', fallback='robocop'), 'OmniConsumerProducts')
    self.assertEqual(sourdough.sourdough.readSetting(setting='validation_key', fallback='robocop'), '/etc/OmniConsumerProducts/credentials/chef/OmniConsumerProducts-validator.private.key')
    self.assertEqual(sourdough.sourdough.readSetting(setting='validation_pubkey', fallback='robocop'), '/etc/OmniConsumerProducts/credentials/chef/OmniConsumerProducts-validator.public.key')
    self.assertEqual(sourdough.sourdough.readSetting(setting='validation_user_name', fallback='robocop'), 'OmniConsumerProducts-validator')


if __name__ == '__main__':
  installSourdoughInContainer()
  suite = unittest.TestLoader().loadTestsFromTestCase(TestSourdough)
  unittest.TextTestRunner(verbosity=2).run(suite)
