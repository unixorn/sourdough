# Sourdough

## 0.9.2

* Update `getAWSAccountID` so it treats any exceptions as not being in EC2, not just `URLError` ones.

## 0.9.1

* Add new `pyvim` and `pyvmomi` dependencies introduced in 0.9 to `setup.py` so they are pulled in automatically by `pip`.

## 0.9

* Add VMware Tags support

## 0.7

* Add ability to set the delay to wait for other converge runs
* Add testing

## 0.5

Clean up code so we work when run out of ec2 now that we have a data center we care about.

* Stop trying to get boto ec2 connections when we aren't in ec2. Oops!

Try really hard to get a runlist and environment

* Load environment from `sourdough.toml` if we can't find a tag or knob file
* Load runlist from `sourdough.toml` if we can't find a tag or knob file
* Add default values for environment, region and runlist if they aren't in `sourdough.toml` and aren't in a tag or knob file.

## 0.4

Cope with rename on github from bigriver.sourdough to sourdough.

## 0.3

Allow specifying a chef server url instead of defaulting to Hosted Chef

## 0.2

First public version

## 0.0.1

* Begin.
