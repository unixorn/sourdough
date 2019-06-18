# Sourdough

## 0.12.0

Fixed version of 0.10.0

Deal with bad behavior by VSphere/VMWare. We sometimes see our VSphere host reject connections, causing some chef runs to get the default runlist instead of the real one.

To deal with this, when we are able to read tag data, we write the tag data to a knob file, so on future runs we can load from there if VSphere is having a tizzy.

## 0.11.0

Revert bad 0.10.0 version

## 0.10.0

Removed. Broke build due to bad testing.

## 0.9.5

* Use correct IP address when searching for tags in VSphere

## 0.9.4

* Fix attribute resolution in VMWare
* Cache knobs and VMWare attributes

## 0.9.3

Missing change notes.

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
