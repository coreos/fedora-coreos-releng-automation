#!/usr/bin/python3
import datetime
import fedora_messaging
import os
import re
import requests
from libpagure import Pagure
import logging

import dnf.subject
import hawkey

import sys
import subprocess

# Set local logging 
logger = logging.getLogger(__name__)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(sh)
logger.setLevel(logging.INFO)


# Connect to pagure and set it to point to our repo
PAGURE_REPO='dusty/failed-composes'

# URL for linking to koji tasks by ID
KOJI_TASK_URL='https://koji.fedoraproject.org/koji/taskinfo?taskID='

# The target tag where we want builds to end up. We'll check this tag
# to see if rpms are there.
KOJI_TARGET_TAG = 'coreos-pool'
KOJI_COREOS_USER = 'dustymabe' # for now
#KOJI_INTERMEDIATE_TAG = 'f{release}-coreos-signing-pending'

# We are processing the org.fedoraproject.prod.pungi.compose.status.change topic
# https://apps.fedoraproject.org/datagrepper/raw?topic=org.fedoraproject.prod.pungi.compose.status.change&delta=100000
########import json
########msg = json.loads("""{
########                "msg": {
########                    "status": "DOOMED",
########                    "release_type": "ga",
########                    "compose_label": null,
########                    "compose_respin": 0,
########                    "compose_date": "20180215",
########                    "release_version": "Bikeshed",
########                    "location": "http://kojipkgs.fedoraproject.org/compose/Fedora-Modular-Bikeshed-20180215.n.0/compose",
########                    "compose_type": "nightly",
########                    "release_is_layered": false,
########                    "release_name": "Fedora-Modular",
########                    "release_short": "Fedora-Modular",
########                    "compose_id": "Fedora-Modular-Bikeshed-20180215.n.0"
########                  }}
########"""
########)


# Given a repo (and thus an input JSON) analyze existing koji tag set
# and tag in any missing packages

#json.loads("""
#        kernel
#        htop
#""")

    
class Consumer(object):
    def __init__(self):
        self.tag = KOJI_TARGET_TAG
        self.koji_user = KOJI_COREOS_USER
        self.token = os.getenv('PAGURE_TOKEN')
        if self.token:
            logger.info("Using detected token to talk to pagure.") 
            self.pg = Pagure(pagure_token=token)
        else:
            logger.info("No pagure token was detected.") 
            logger.info("This script will run but won't be able to create new issues.")
            self.pg = Pagure()

        # Set the repo to create new issues against
        self.pg.repo=PAGURE_REPO

        # Used for printing out a value when the day has changed
        self.date = datetime.date.today()

#   def __call__(self, message: fedora_messaging.api.Message):
    def __call__(self):
       #logger.debug(message.topic)
       #logger.debug(message.body)


       ## Grab the raw message body and the status from that
       #msg = message.body

        # set of desired rpms
        desired = {'kernel-5.0.17-300.fc30', 'coreos-installer-0-5.gitd3fc540.fc30', 'cowsay-3.04-12.fc30'}

        # Grab the list of packages that can be tagged into the tag
        pkgs = get_pkgs_in_tag(self.tag)

        # Grab the currently tagged builds and convert it into a set
        current = set(get_tagged_builds(self.tag))

        # Find out the difference between the current set of builds
        # that exist in the koji tag and the desired set of builds to
        # be added to the koji tag.
        totag = desired.difference(current)
        #print(totag)

        for build in totag:
            logger.info(f'{build}')

            # Find the some defining information for this build.
            # Take the first item from the list returned by possibilites func
            subject = dnf.subject.Subject(build)
            buildinfo = subject.get_nevra_possibilities(forms=hawkey.FORM_NEVRA)[0]
            print(buildinfo.name)
            print(buildinfo.version)
            print(buildinfo.epoch)
            print(buildinfo.release)
            print(buildinfo.arch)


            # Check to see if the package is already covered by the tag
            #if i.name 
            if buildinfo.name not in pkgs:
                add_pkg_to_tag(tag=self.tag,
                               pkg=buildinfo.name,
                               owner=self.koji_user)

            # Perform the tagging
            tag_build(tag=self.tag, build=build)

#       if self.token:
#           self.pg.create_issue(title=title, content=content)

def grab_first_column(text):
    # The output is split by newlines (split \n) and contains an 
    # extra newline  at the end (rstrip). We only care about the 1st
    # column (split(' ')[0]) so just grab that and return a list.
    lines = text.rstrip().split('\n')
    return [b.split(' ')[0] for b in lines]


def get_tagged_builds(tag):
    if not tag:
        raise

    # Grab current builds in the koji tag
    # The output with `--quiet` is like this:
    # 
    #   coreos-installer-0-5.gitd3fc540.fc30      coreos-pool           dustymabe
    #   ignition-2.0.0-beta.3.git910e6c6.fc30     coreos-pool           jlebon
    #   kernel-5.0.10-300.fc30                    coreos-pool           labbott
    #   kernel-5.0.11-300.fc30                    coreos-pool           labbott
    # 
    cmd = f'/usr/bin/koji list-tagged {tag} --quiet'.split(' ')
    cp = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return grab_first_column(cp.stdout)

def get_pkgs_in_tag(tag):
    if not tag:
        raise
    cmd = f'/usr/bin/koji list-pkgs --tag={tag} --quiet'.split(' ')
    cp = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return grab_first_column(cp.stdout)

def tag_build(tag, build):
    if not tag or not build:
        raise
    cmd = f'/usr/bin/koji tag-build {tag} {build}'.split(' ')
    cp = subprocess.run(cmd, check=True)

def add_pkg_to_tag(tag, pkg, owner):
    if not tag or not pkg or not owner:
        raise
    cmd = f'/usr/bin/koji add-pkg {tag} {pkg} --owner {owner}'.split(' ')
    cp = subprocess.run(cmd, check=True)

if __name__ == '__main__':
    c = Consumer()
    c.__call__()
