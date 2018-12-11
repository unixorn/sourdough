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
'''

import logging
import os
import sys
import unittest
import sourdough

from sourdough.sourdough import getCustomLogger

this = sys.modules[__name__]

class TestSourdough(unittest.TestCase):

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
  this.logger = getCustomLogger(name='sourdough-testing')

  suite = unittest.TestLoader().loadTestsFromTestCase(TestSourdough)
  unittest.TextTestRunner(verbosity=2).run(suite)
