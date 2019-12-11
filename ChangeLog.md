# Sourdough

## 0.12.7

* Revert 0.12.6 until we fix the issues that have come up in EC2

## 0.12.6

* Restrict read volume tags only in VMware environment 

## 0.12.5

* Added support to read volume tags and write the respective SCSI values into the `/etc/device-volumes.d` directory

## 0.12.4

Fix error in writeKnob - we were trying to call this.logger directly instead of this.logger.error

## 0.12.4

Added `sourdough-enable-chef`, `sourdough-disable-chef`, `sourdough-enable-debugging` and `sourdough-disable-debugging` convenience commands.

## 0.12.3

### Yet another vSphere cleanup

* Fix error when no valid vSphere configuration toml file can be found.
* Add disfeature flag file (`/etc/sourdough/disable-vsphere`) to disable vSphere entirely when we know we're not going to be able to reach the vSphere server (don't ask).
* Add ability to set network connection timeout with `connection_wait` in `/etc/sourdough/sourdough.toml` to cope with slow vSphere servers.

## 0.12.2

### Working around more vSphere shenanigans

* Switched from using IP address to UUID when looking up tag data. We were using the VM's IP address as the key when requesting tag information. This turned out to be a bad idea because if the machine has several IPs, the one `getIP()` picked wasn't necessarily the one vSphere was using as the main key, so you wouldn't always be able to get the tag data from vSphere when searching by IP, which sucks.
* For efficiency, we now check the `vmwareTags` dict to see if we've already read a tag value  _before_ reading all the tags from the hypervisor. We also load all available tags into the cache whenever we scan for a tag that isn't already cached.
* Added `detectVSphereHost()`, `loadVSphereSettings()` and `writeVSphereSettings()` so we don't retry connecting to all the vSphere hosts listed in `vmware.toml` every time we read a tag, with the associated delays waiting for timeouts trying to connect to unreachable hypervisors. Now we store that information in a knob file so future `sourdough` runs won't have to grovel through the entire hypervisor list.
* Added a debugging flag file, `/etc/sourdough/debug-sourdough`.  When the flag is present, `sourdough` won't actually start `chef-client` so you can debug vSphere issues faster.
* Renamed `get_ip()` to `getIP()` for naming consistency
* Converted a lot of crappy `print` statements to proper `logger` usage
* Updated and created a bunch of missing/crappy docstrings

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
