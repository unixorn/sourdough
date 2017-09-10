# Sourdough

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://travis-ci.org/unixorn/sourdough.svg?branch=master)](https://travis-ci.org/unixorn/sourdough)
[![Code Climate](https://codeclimate.com/github/unixorn/sourdough/badges/gpa.svg)](https://codeclimate.com/github/unixorn/sourdough)
[![Issue Count](https://codeclimate.com/github/unixorn/sourdough/badges/issue_count.svg)](https://codeclimate.com/github/unixorn/sourdough)
[![GitHub stars](https://img.shields.io/github/stars/unixorn/sourdough.svg)](https://github.com/unixorn/git-extra-commands/stargazers)

Sourdough is a tool to install chef-client during instance boot.

# FAQs

## How are node names generated?

### EC2

If we're in EC2, we look for a Node tag/knob. If the Node tag/knob exists, our node name will be **AWS_REGION-NODE_TAG_KNOB-INSTANCE_ID**

If the node tag/knob doesn't exist, we look for the Hostname tag/knob and set the node name to **AWS_REGION-HOSTNAME_TAGKNOB**.

If the Hostname tag/knob is missing we fail back to reading the output of `hostname`

### Outside EC2

If we aren't in EC2, we look for a `/etc/knobs/Hostname` file and use the
contents of that - if there's no knob file we use the output of
`hostname` so we have at least something sane-ish.

## How is the runlist determined?

### EC2

The first thing we do is check for `/etc/knobs/Runlist`. If that's present, we set the runlist to the contents of that file.

If there is no /etc/knobs/Runlist, we read the instance's Runlist tag and set the runlist to that.

## What Chef environment does Sourdough use

Similarly to how if find the Runlist, sourdough Looks for `/etc/knobs/Environment` and if that is missing, the Environment tag for the instance.
