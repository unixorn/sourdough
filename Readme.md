# Sourdough

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://travis-ci.org/unixorn/sourdough.svg?branch=master)](https://travis-ci.org/unixorn/sourdough)
[![Code Climate](https://codeclimate.com/github/unixorn/sourdough/badges/gpa.svg)](https://codeclimate.com/github/unixorn/sourdough)
[![Issue Count](https://codeclimate.com/github/unixorn/sourdough/badges/issue_count.svg)](https://codeclimate.com/github/unixorn/sourdough)
[![GitHub stars](https://img.shields.io/github/stars/unixorn/sourdough.svg)](https://github.com/unixorn/git-extra-commands/stargazers)

Sourdough is a tool to install `chef-client` during instance boot, or to run `chef-client` after boot.

Sourdough reads the **Environment** and **Runlist** EC2 tags and runs `chef-client` with those settings so you can update an instance's Chef settings just by tweaking its tags. This also lets you see what runlist and environment an instance has using just the AWS webui, so no more having to correlate Chef information for your instances in two places.

# FAQs

## How are node names generated?

### EC2

If we're in EC2, we look for a Node tag/knob. If a Node tag or knob exists, our node name will be **AWS_REGION-NODE_TAG_KNOB-INSTANCE_ID**

If the node tag and knob don't exist, we look for a Hostname tag or knob and set the node name to **AWS_REGION-HOSTNAME_TAGKNOB**.

If the Hostname tag or knob are both missing we fail back to reading the output of `hostname` which is better than nothing.

### Outside EC2

If we aren't in EC2, we look for a `/etc/knobs/Hostname` file and use the
contents of that - if there's no knob file we use the output of
`hostname` so we have at least something sane-ish.

## How is the runlist determined?

### EC2

The first thing we do is check for `/etc/knobs/Runlist`. If that's present, we set the runlist to the contents of that file.

If there is no `/etc/knobs/Runlist` file, we read the instance's **Runlist** tag and set the runlist to that, and if there is no Runlist tag we look for a **default_runlist** entry in `/etc/sourdough/sourdough.toml`

## What Chef environment does Sourdough use

Similarly to how it determines the Runlist, `sourdough` looks for `/etc/knobs/Environment` and if that is missing, the **Environment** tag for the instance, and if that is missing, looks for a **default_environment** entry in `/etc/sourdough/sourdough.toml`

## How do I have sourdough pass environment variables to chef-client?

`sourdough` will look for `/etc/sourdough/environment-variables.json`, and if present and valid JSON, will pass the variables inside to `chef-client` when it runs it.
