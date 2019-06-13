#!/usr/bin/python3
import fedora_messaging.api
import os
import re
import requests
import logging
import json

import dnf.subject
import hawkey

import sys
import subprocess
import requests

# Set local logging 
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# URL for linking to koji tasks by ID
KOJI_TASK_URL='https://koji.fedoraproject.org/koji/taskinfo?taskID='

# The target tag where we want builds to end up. We'll check this tag
# to see if rpms are there.
KOJI_TARGET_TAG = 'coreos-pool'
KOJI_COREOS_USER = 'coreosbot'
KERBEROS_DOMAIN = 'FEDORAPROJECT.ORG'

GIT_REPO_DOMAIN   = 'https://pagure.io/'
GIT_REPO_FULLNAME = 'dusty/coreos-koji-data'
GIT_REPO_BRANCH   = 'master'

# We are processing the io.pagure.prod.pagure.git.receive topic
# https://apps.fedoraproject.org/datagrepper/raw?topic=io.pagure.prod.pagure.git.receive&delta=100000
EXAMPLE_MESSAGE_BODY = json.loads("""
{
  "msg": {
    "forced": false,
    "agent": "dustymabe",
    "repo": {
      "custom_keys": [],
      "description": "coreos-koji-data",
      "parent": null,
      "date_modified": "1558714988",
      "access_users": {
        "admin": [],
        "commit": [],
        "ticket": [],
        "owner": [
          "dustymabe"
        ]
      },
      "namespace": "dusty",
      "priorities": {},
      "id": 6234,
      "access_groups": {
        "admin": [],
        "commit": [],
        "ticket": []
      },
      "milestones": {},
      "user": {
        "fullname": "Dusty Mabe",
        "name": "dustymabe"
      },
      "date_created": "1558714988",
      "fullname": "dusty/coreos-koji-data",
      "url_path": "dusty/coreos-koji-data",
      "close_status": [],
      "tags": [],
      "name": "coreos-koji-data"
    },
    "end_commit": "db5c806769a5ab35bfeb15e1ac7c727ec1275b23",
    "branch": "master",
    "authors": [
      {
        "fullname": "Dusty Mabe",
        "name": "dustymabe"
      }
    ],
    "total_commits": 1,
    "start_commit": "db5c806769a5ab35bfeb15e1ac7c727ec1275b23"
  }
}
"""
)


# Given a repo (and thus an input JSON) analyze existing koji tag set
# and tag in any missing packages

class Consumer(object):
    def __init__(self):
        self.tag = KOJI_TARGET_TAG
        self.koji_user = KOJI_COREOS_USER
        self.kerberos_domain   = KERBEROS_DOMAIN
        self.git_repo_domain   = GIT_REPO_DOMAIN
        self.git_repo_fullname = GIT_REPO_FULLNAME
        self.git_repo_branch   = GIT_REPO_BRANCH

        # If a keytab was specified let's use it
        self.keytab_file = os.environ.get('COREOS_KOJI_TAGGER_KEYTAB_FILE')
        if self.keytab_file:
            if os.path.exists(self.keytab_file):
                self.kinit()
            else:
                raise
        else:
            logger.info('No keytab file defined in '
                        '$COREOS_KOJI_TAGGER_KEYTAB_FILE')
            logger.info('Will not attempt koji write operations')

    def __call__(self, message: fedora_messaging.api.Message):
        logger.debug(message.topic)
        logger.debug(message.body)

        # Re-attempt to kinit if our authentication has timed out
        if self.keytab_file:
            if check_koji_connection().returncode != 0:
                self.kinit()

        # Grab the raw message body and the status from that
        msg = message.body['msg']
        branch = msg['branch']
        repo   = msg['repo']['fullname']
        commit = msg['end_commit']

        if (repo != self.git_repo_fullname):
            logger.debug(f'Skipping message from unrelated repo: {repo}')
            return

        if (branch != self.git_repo_branch):
            logger.info(f'Skipping message from unrelated branch: {branch}')
            return

        # Now grab data from the commit we should operate on:
        # https://pagure.io/dusty/coreos-koji-data/raw/db5c806769a5ab35bfeb15e1ac7c727ec1275b23/f/data.json
        # This data file is basically a list ['build1NVR', 'build2NVR', 'etc']
        url = f'{self.git_repo_domain}/{self.git_repo_fullname}/raw/{commit}/f/data.json'
        logger.info(f'Attempting to retrieve data from {url}')
        r = requests.get(url)
        data = json.loads(r.text)

        logger.debug('Retrieved JSON data:')
        logger.debug(data)

        # NOMENCLATURE:
        # 
        # In koji there is the concept of a pkg and a build. A pkg
        # is a piece of software (i.e. kernel) whereas a build is a
        # specific build of that software that is unique by NVR (i.e.
        # kernel-5.0.17-300.fc30). RPMs are output of a build. There
        # can be many rpms (including subpackages) output from a build
        # (for example kernel-5.0.17-300.fc30.x86_64.rpm and
        # kernel-devel-5.0.17-300.fc30.x86_64.rpm). So we have:
        #
        # kernel                              --> koji pkg
        # kernel-5.0.17-300.fc30              --> koji build (matches srpm name)
        # kernel-5.0.17-300.fc30.x86_64       --> main rpm package
        # kernel-devel-5.0.17-300.fc30.x86_64 --> rpm subpackage
        #
        # STRATEGY:
        # 
        # The lockfile input gives a list of rpm names in NEVRA format. We 
        # must derive the srpm name (koji build name) from that and compare
        # that with existing koji builds in the tag. Once we have a list of
        # koji builds that aren't in the tag we can add the koji pkg to the
        # tag (if needed) and then tag the koji build into the tag.

        # parse the lockfile and get a set of rpm NEVRAs
        desiredrpms = set(parse_lockfile_data(data))

        # convert the rpm NEVRAs into a list of srpm NVRA (format of koji
        # build name)
        desiredbuilds = set(get_builds_from_rpmnevras(desiredrpms))

        # Grab the list of pkgs that can be tagged into the tag
        pkgsintag = get_pkgs_in_tag(self.tag)

        # Grab the currently tagged builds and convert it into a set
        currentbuilds = set(get_tagged_builds(self.tag))

        # Find out the difference between the current set of builds
        # that exist in the koji tag and the desired set of builds to
        # be added to the koji tag.
        buildstotag = list(desiredbuilds.difference(currentbuilds))


        # compute the package names of each build and determine whether
        # it is in the tag or not. If not we'll need to add the package
        # to the tag before we can add the specific build to the tag
        pkgstoadd = []
        for build in buildstotag:

            # Find the some defining information for this build.
            buildinfo = get_rich_info_for_rpm_string(build)

            # Check to see if the koji pkg is already covered by the tag
            if buildinfo.name not in pkgsintag:
                pkgstoadd.append(buildinfo.name)

        # Log if there is nothing to do
        if not pkgstoadd and not buildstotag:
            logger.info(f'No new builds to tag.. going back to sleep')
            return

        # Add the needed packages to the tag if we have credentials
        if pkgstoadd:
            logger.info(f'Adding packages to tag: {pkgstoadd}')
            if self.keytab_file:
                add_pkgs_to_tag(tag=self.tag,
                                pkgs=pkgstoadd,
                                owner=self.koji_user)
                logger.info('Package adding done')

        # Perform the tagging if we have credentials
        if buildstotag:
            logger.info(f'Tagging builds into tag: {buildstotag}')
            if self.keytab_file:
                tag_builds(tag=self.tag, builds=buildstotag)
                logger.info('Tagging done')

    def kinit(self):
        logger.info(f'Authenticating with keytab: {self.keytab_file}')
        cmd = f'/usr/bin/kinit -k -t {self.keytab_file}'
        cmd += f' {self.koji_user}@{self.kerberos_domain}'
        runcmd(cmd.split(' '), check=True)
        check_koji_connection(check=True) # Make sure it works

def runcmd(cmd: list, **kwargs: int) -> subprocess.CompletedProcess:
    try:
        logger.debug(f'Running command: {cmd}')
        cp = subprocess.run(cmd, **kwargs)
    except subprocess.CalledProcessError:
        logger.error('Running command returned bad exitcode')
        logger.error(f'COMMAND: {cmd}')
        logger.error(f' STDOUT: {cp.stdout}')
        logger.error(f' STDERR: {cp.stderr}')
        raise
    return cp # subprocess.CompletedProcess

def get_rich_info_for_rpm_string(string: str) -> hawkey.NEVRA:

    # get a hawkey.Subject object for the string
    subject = dnf.subject.Subject(string) # returns hawkey.Subject

    # get a list of hawkey.NEVRA objects that are the possibilities
    nevras  = subject.get_nevra_possibilities(forms=hawkey.FORM_NEVRA)

    # return the first hawkey.NEVRA item in the list of possibilities
    info = nevras[0]
    #   print(info.name)
    #   print(info.version)
    #   print(info.epoch)
    #   print(info.release)
    #   print(info.arch)
    return info

def parse_lockfile_data(data: str) -> list:
    # Parse the rpm lockfile format and return a list of rpms in
    # NEVRA form.
    # TODO add link to docs on lockfile format when they exist
    return list(data)

def grab_first_column(text: str) -> list:
    # The output is split by newlines (split \n) and contains an 
    # extra newline  at the end (rstrip). We only care about the 1st
    # column (split(' ')[0]) so just grab that and return a list.
    lines = text.rstrip().split('\n')
    return [b.split(' ')[0] for b in lines]

def get_srpms_from_rpmnvras(rpmnvras: set) -> set:
    if not rpmnvras:
        raise

    # Query koji in a single query to get rpminfo (includes SRPM name)
    # for all rpmnvras
    #
    # Usage: koji rpminfo [options] <n-v-r.a> [<n-v-r.a> ...]
    cmd = f'/usr/bin/koji rpminfo'.split(' ')
    cmd+= rpmnvras
    cp = runcmd(cmd, check=True, capture_output=True, text=True)

    # Outputs `SRPM: E:N-V-R` format like:
    #
    # $ koji rpminfo grub2-efi-x64-2.02-81.fc30.x86_64
    #   RPM: 1:grub2-efi-x64-2.02-81.fc30.x86_64 [17584661]
    #   RPM Path: /mnt/koji/packages/grub2/2.02/81.fc30/x86_64/grub2-efi-x64-2.02-81.fc30.x86_64.rpm
    #   SRPM: 1:grub2-2.02-81.fc30 [1269330]
    #   SRPM Path: /mnt/koji/packages/grub2/2.02/81.fc30/src/grub2-2.02-81.fc30.src.rpm
    #   Built: Mon, 20 May 2019 13:19:34 EDT
    #   SIGMD5: bbfb797611097256c119f99c4480e5a8
    #   Size: 365984
    #   License: GPLv3+
    #   Build ID: 1269330
    #   Buildroot: 16295881 (tag f30-build, arch x86_64, repo 1166504)
    #   Build Host: bkernel03.phx2.fedoraproject.org
    #   Build Task: 34957405

    # Go through each line and get the srpm names
    srpms = set()
    for line in cp.stdout.strip().splitlines():
        if 'SRPM:' in line:
            # The (\d+:)? pulls the epoch off the front of each SRPM value
            # if it exists.
            srpms.add(re.search('SRPM: (\d+:)?([\S]+)', line).group(2))

    logger.debug(f"Found SRPMS: {srpms}")
    return srpms

def get_builds_from_rpmnevras(rpmnevras: set) -> list:
    # Given a list of rpm NEVRAs get the list of srpms (and 
    # thus koji build names) from it
    if not rpmnevras:
        raise

    # Get a set of NVRAs from the list of NEVRAs
    rpmnvras = set()
    for rpmnevra in rpmnevras:
        # Find the some defining information for this rpm.
        rpminfo = get_rich_info_for_rpm_string(rpmnevra)
        # come up with rpm NVRA
        rpmnvra = f"{rpminfo.name}-{rpminfo.version}-{rpminfo.release}.{rpminfo.arch}"
        rpmnvras.add(rpmnvra)

    builds = get_srpms_from_rpmnvras(rpmnvras)
    return builds

def get_tagged_builds(tag: str) -> list:
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
    # Usage: koji list-tagged [options] tag [package]
    cmd = f'/usr/bin/koji list-tagged {tag} --quiet'.split(' ')
    cp = runcmd(cmd, check=True, capture_output=True, text=True)
    return grab_first_column(cp.stdout)

def get_pkgs_in_tag(tag: str) -> list:
    if not tag:
        raise
    # Usage: koji list-pkgs [options]
    cmd = f'/usr/bin/koji list-pkgs --tag={tag} --quiet'.split(' ')
    cp = runcmd(cmd, check=True, capture_output=True, text=True)
    return grab_first_column(cp.stdout)

def tag_builds(tag: str, builds: list):
    if not tag or not builds:
        raise
    # Usage: koji tag-build [options] <tag> <pkg> [<pkg>...]
    cmd = f'/usr/bin/koji tag-build {tag}'.split(' ')
    cmd.extend(builds)
    runcmd(cmd, check=True)

def add_pkgs_to_tag(tag: str, pkgs: list, owner: str):
    if not tag or not pkgs or not owner:
        raise
    # Usage: koji add-pkg [options] tag package [package2 ...]
    cmd = f'/usr/bin/koji add-pkg {tag} --owner {owner}'.split(' ')
    cmd.extend(pkgs)
    runcmd(cmd, check=True)

def check_koji_connection(check: bool = False) -> subprocess.CompletedProcess:
    # Usage: koji moshimoshi [options]
    cmd = f'/usr/bin/koji moshimoshi'.split(' ')
    cp = runcmd(cmd, check=check, capture_output=True)
    return cp

# The code in this file is expected to be run through fedora messaging
# However, you can run the script directly for testing purposes. The
# below code allows us to do that and also fake feeding data to the
# call by updating the json text below.
if __name__ == '__main__':
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logger.addHandler(sh)

    # Mock the web request to get the data so that we can easily
    # modify the below values in order to run a test:
    from unittest.mock import Mock

    requests_response = Mock()
    requests_response.text = """
[
    "kernel-5.0.17-300.fc30.x86_64",
    "coreos-installer-dracut-0-7.git0e6979c.fc30.noarch",
    "ignition-2.0.0-1.git0c1da80.fc30.x86_64",
    "grub2-efi-x64-1:2.02-81.fc30.x86_64",
    "selinux-policy-3.14.3-37.fc30.noarch"
]
    """
    requests = Mock()
    requests.get.return_value = requests_response

    m = fedora_messaging.api.Message(
            topic = 'io.pagure.prod.pagure.git.receive',
            body = EXAMPLE_MESSAGE_BODY)
    c = Consumer()
    c.__call__(m)
