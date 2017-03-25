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
#
# Overall driver for sourdough scripts
#
# Work git-style so `sourdough foo` will look for a program named sourdough-foo, and
# `sourdough foo bar` will look for sourdough-foo-bar.

import os
import sys
from subprocess import check_call

from logrus.cli import findSubCommand, isProgram


def sourdoughDriver():
  """
  Process the command line arguments and run the appropriate sourdough subcommand.

  We want to be able to do git-style handoffs to subcommands where if we
  do `sourdough aws foo bar` and the executable sourdough-aws-foo exists, we'll call
  it with the argument bar.

  We deliberately don't do anything with the arguments other than hand
  them off to the sourdough subcommand. Subcommands are responsible for their
  own argument parsing.
  """
  try:
    (command, args) = findSubCommand(sys.argv)

    # If we can't construct a subcommand from sys.argv, it'll still be able
    # to find this sourdough driver script, and re-running ourself isn't useful.
    if os.path.basename(command) == 'sourdough':
      print "Could not find a subcommand for %s" % ' '.join(sys.argv)
      sys.exit(1)
  except StandardError:
    print "Could not find a subcommand for %s" % ' '.join(sys.argv)
    sys.exit(1)
  check_call([command] + args)


if __name__ == '__main__':
  sourdoughDriver()
