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
logger.setLevel(logging.DEBUG)

# The target and the intermediate tag. The target tag is where we want
# builds to end up. We'll check the target tag to see if builds are already
# there. The intermediate tag is used when tagging. It is useful to
# set the intermediate tag different than the target tag when there is
# an intermediate tag that is set up for signing. For example we use
# f{releasever}-signing-pending tags today. They inherit from the coreos-pool
# and are configured to sign rpms and then move them into the
# coreos-pool tag.
KOJI_TARGET_TAG = 'coreos-pool'
KOJI_INTERMEDIATE_TAG = 'f{releasever}-coreos-signing-pending'

# if we are in a stage environment then use the
# stage koji as well as the staging kerberos
if os.environ.get('COREOS_KOJI_TAGGER_USE_STG', 'false') == 'true':
    KOJI_CMD = '/usr/bin/stg-koji'
else:
    KOJI_CMD = '/usr/bin/koji'

# This user will be the owner of a pkg in a tag
# To view existing owners run:
#    - koji list-pkgs --tag=coreos-pool
COREOS_KOJI_USER = 'coreosbot'

GIT_REPO_DOMAIN   = 'https://pagure.io/'
GIT_REPO_FULLNAME = 'dusty/coreos-koji-data'
GIT_REPO_BRANCH   = 'master'

# We are processing the io.pagure.prod.pagure.git.receive topic
# https://apps.fedoraproject.org/datagrepper/raw?topic=io.pagure.prod.pagure.git.receive&delta=100000
EXAMPLE_MESSAGE_BODY = json.loads("""
{
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
"""
)


# Given a repo (and thus an input JSON) analyze existing koji tag set
# and tag in any missing packages

class Consumer(object):
    def __init__(self):
        self.target_tag        = KOJI_TARGET_TAG
        self.intermediate_tag  = KOJI_INTERMEDIATE_TAG
        self.git_repo_domain   = GIT_REPO_DOMAIN
        self.git_repo_fullname = GIT_REPO_FULLNAME
        self.git_repo_branch   = GIT_REPO_BRANCH
        self.koji_user         = COREOS_KOJI_USER

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
        msg = message.body
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
        desiredrpms = set(parse_lockfile_data(r.text))

        # convert the rpm NEVRAs into a list of srpm NVRA (format of koji
        # build name)
        buildsinfo = get_buildsinfo_from_rpmnevras(desiredrpms)
        desiredbuilds = set(buildsinfo.keys())

        # Grab the list of pkgs that can be tagged into the tag
        pkgsintag = get_pkgs_in_tag(self.target_tag)

        # Grab the currently tagged builds and convert it into a set
        currentbuilds = set(get_tagged_builds(self.target_tag))

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
            buildinfo = get_rich_info_for_rpm_string(build, arch=False)

            # Check to see if the koji pkg is already covered by the tag
            if buildinfo.name not in pkgsintag:
                pkgstoadd.append(buildinfo.name)

        # Log if there is nothing to do
        if not pkgstoadd and not buildstotag:
            logger.info(f'No new builds to tag.. going back to sleep')
            return

        # Add the needed packages to the tag if we have credentials
        if pkgstoadd:
            logger.info('Adding packages to the '
                        f'{self.target_tag} tag: {pkgstoadd}')
            if self.keytab_file:
                add_pkgs_to_tag(tag=self.target_tag,
                                pkgs=pkgstoadd,
                                owner=self.koji_user)
                logger.info('Package adding done')

        # Perform the tagging for each release into the intermediate
        # tag for that release if we have credentials
        if buildstotag:
            releasevers = set(buildsinfo.values())
            for releasever in releasevers:
                tag = self.intermediate_tag.format(releasever=releasever)
                buildstotagforthisrelease = \
                    [x for x in buildstotag if buildsinfo[x] == releasever]
                if buildstotagforthisrelease:
                    logger.info('Tagging builds into the '
                                f'{tag} tag: {buildstotagforthisrelease}')
                    if self.keytab_file:
                        tag_builds(tag=tag, builds=buildstotagforthisrelease)
            logger.info('Tagging done')

    def find_principal_from_keytab(self) -> str:
        # Find the pricipal/realm that the keytab is for
        cmd = f'/usr/bin/klist -k {self.keytab_file}'
        cp = runcmd(cmd.split(' '), capture_output=True, check=True)

        # The output is in the form:
        #
        # # klist -k coreosbot.keytab
        # Keytab name: FILE:coreosbot.keytab
        # KVNO Principal
        # ---- --------------------------------------------------------------------------
        #    3 coreosbot@FEDORAPROJECT.ORG
        #    3 coreosbot@FEDORAPROJECT.ORG
        #    3 coreosbot@FEDORAPROJECT.ORG
        #    3 coreosbot@FEDORAPROJECT.ORG
        #
        # Grab the last line and use that.
        line = cp.stdout.decode('utf-8').rstrip().splitlines()[-1]

        # The principal will be the last column in that line
        principal = line.split(' ')[-1]
        logger.debug(f'Found principal {principal} in keytab')
        return principal

    def kinit(self):
        logger.info(f'Authenticating with keytab: {self.keytab_file}')
        # find principal first
        principal = self.find_principal_from_keytab()
        logger.info(f'Using principal {principal}')
        # then Auth
        cmd = f'/usr/bin/kinit -k -t {self.keytab_file} {principal}'
        runcmd(cmd.split(' '), check=True)
        check_koji_connection(check=True) # Make sure it works

def runcmd(cmd: list, **kwargs: int) -> subprocess.CompletedProcess:
    try:
        logger.debug(f'Running command: {cmd}')
        cp = subprocess.run(cmd, **kwargs)
    except subprocess.CalledProcessError as e:
        logger.error('Running command returned bad exitcode')
        logger.error(f'COMMAND: {cmd}')
        logger.error(f' STDOUT: {e.stdout}')
        logger.error(f' STDERR: {e.stderr}')
        raise
    return cp # subprocess.CompletedProcess

def get_rich_info_for_rpm_string(string: str, arch: bool) -> hawkey.NEVRA:
    # arch: (bool) whether arch is included in the string
    if arch:
        form=hawkey.FORM_NEVRA
    else:
        form=hawkey.FORM_NEVR

    # get a hawkey.Subject object for the string
    subject = dnf.subject.Subject(string) # returns hawkey.Subject

    # get a list of hawkey.NEVRA objects that are the possibilities
    nevras  = subject.get_nevra_possibilities(forms=form)

    # return the first hawkey.NEVRA item in the list of possibilities
    info = nevras[0]
    #   print(info.name)
    #   print(info.version)
    #   print(info.epoch)
    #   print(info.release)
    #   print(info.arch)
    return info

def parse_lockfile_data(text: str) -> list:
    # Parse the rpm lockfile format and return a list of rpms in
    # NEVRA form.
    # Best documention on the format for now:
    #     https://github.com/projectatomic/rpm-ostree/commit/8ff0ee9c89ecc0540182b5b506455fc275d27a61
    #
    # An example looks something like:
    #
    #   {
    #     "packages": {
    #       "GeoIP": {
    #         "evra": "1.6.12-5.fc30.x86_64",
    #         "digest": "sha256:21dc1220cfdacd089c8c8ed9985801a9d09edb7c26543694cef57ada1d8aafa8"
    #       }
    #     }
    #   }

    # The data is JSON (yay)
    data = json.loads(text)
    logger.debug('Retrieved JSON data:')
    logger.debug(json.dumps(data, indent=4, sort_keys=True))

    # We only care about the NEVRAs, so just accumulate those and return
    return [f'{name}-{v["evra"]}' for name, v in data['packages'].items()]

def grab_first_column(text: str) -> list:
    # The output is split by newlines (split \n) and contains an 
    # extra newline  at the end (rstrip). We only care about the 1st
    # column (split(' ')[0]) so just grab that and return a list.
    lines = text.rstrip().split('\n')
    return [b.split(' ')[0] for b in lines]

def get_releasever_from_buildroottag(buildroottag: str) -> str:
    logger.debug(f'Checking buildroottag {buildroottag}')
    if 'afterburn' in buildroottag:
        # example: module-afterburn-rolling-3020190524194016-2c789dff-build
        releasever = re.search('module-afterburn-rolling-(\d\d)',
                                                buildroottag).group(1)
    elif 'zincati' in buildroottag:
        # example: module-zincati-rolling-3020190711144249-a23e773d-build
        releasever = re.search('module-zincati-rolling-(\d\d)',
                                                buildroottag).group(1)
    elif 'fedora-coreos-pinger' in buildroottag:
        # example: module-fedora-coreos-pinger-rolling-3020190720131029-a23e773d-build
        releasever = re.search('module-fedora-coreos-pinger-rolling-(\d\d)',
                                                buildroottag).group(1)
    else:
        # example: f30-build
        releasever = re.search('f(\d\d)', buildroottag).group(1)
    if not releasever:
        raise
    return releasever

def get_buildsinfo_from_rpmnevras(rpmnevras: set) -> dict:
    # Given a list of rpm NEVRAs get the list of srpms (and
    # thus koji build names) from it
    if not rpmnevras:
        raise

    # Get a set of NVRAs from the list of NEVRAs
    rpmnvras = set()
    for rpmnevra in rpmnevras:
        # Find the some defining information for this rpm.
        rpminfo = get_rich_info_for_rpm_string(rpmnevra, arch=True)
        # come up with rpm NVRA
        rpmnvra = f"{rpminfo.name}-{rpminfo.version}-{rpminfo.release}.{rpminfo.arch}"
        rpmnvras.add(rpmnvra)

    # Query koji in a single query to get rpminfo (includes SRPM name
    # and buildroot tag name) for all rpmnvras
    #
    # Usage: koji rpminfo [options] <n-v-r.a> [<n-v-r.a> ...]
    cmd = f'{KOJI_CMD} rpminfo'.split(' ')
    cmd+= rpmnvras
    cp = runcmd(cmd, check=True, capture_output=True, text=True)

    # Outputs formatting like:
    #  - `SRPM: E:N-V-R`
    #  - `Buildroot: 16295881 (tag f30-build, arch x86_64, repo 1166504)
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
    srpm = None
    buildroottag = None
    buildsinfo = dict()
    for line in cp.stdout.strip().splitlines():
        if 'SRPM:' in line:
            # The (\d+:)? pulls the epoch off the front of each SRPM value
            # if it exists.
            srpm = re.search('SRPM: (\d+:)?([\S]+)', line).group(2)
        if 'Buildroot:' in line:
            buildroottag = re.search('Buildroot: [\d]+ \(tag ([\S]+),', line).group(1)
            releasever = get_releasever_from_buildroottag(buildroottag)
            # Now that we have both pieces of info we add to the dict
            buildsinfo.update({srpm: releasever})
            srpm = None
            buildroottag = None

    logger.debug("Found Builds: {}".format(buildsinfo.keys()))
    logger.debug(buildsinfo)
    return buildsinfo

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
    cmd = f'{KOJI_CMD} list-tagged {tag} --quiet'.split(' ')
    cp = runcmd(cmd, check=True, capture_output=True, text=True)
    return grab_first_column(cp.stdout)

def get_pkgs_in_tag(tag: str) -> list:
    if not tag:
        raise
    # Usage: koji list-pkgs [options]
    cmd = f'{KOJI_CMD} list-pkgs --tag={tag} --quiet'.split(' ')
    cp = runcmd(cmd, check=True, capture_output=True, text=True)
    return grab_first_column(cp.stdout)

def tag_builds(tag: str, builds: list):
    if not tag or not builds:
        raise
    # Usage: koji tag-build [options] <tag> <pkg> [<pkg>...]
    cmd = f'{KOJI_CMD} tag-build {tag}'.split(' ')
    cmd.extend(builds)
    runcmd(cmd, check=True)

def add_pkgs_to_tag(tag: str, pkgs: list, owner: str):
    if not tag or not pkgs or not owner:
        raise
    # Usage: koji add-pkg [options] tag package [package2 ...]
    cmd = f'{KOJI_CMD} add-pkg {tag} --owner {owner}'.split(' ')
    cmd.extend(pkgs)
    runcmd(cmd, check=True)

def check_koji_connection(check: bool = False) -> subprocess.CompletedProcess:
    # Usage: koji moshimoshi [options]
    cmd = f'{KOJI_CMD} moshimoshi'.split(' ')
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
{
  "packages": {
    "GeoIP": {
      "evra": "1.6.12-5.fc30.x86_64",
      "digest": "sha256:21dc1220cfdacd089c8c8ed9985801a9d09edb7c26543694cef57ada1d8aafa8"
    },
    "GeoIP-GeoLite-data": {
      "evra": "2018.06-3.fc30.noarch",
      "digest": "sha256:b871f757d061af1125280219dca15b5066018b6ff20c08010c5774c484f127a8"
    },
    "NetworkManager": {
      "evra": "1:1.16.2-1.fc30.x86_64",
      "digest": "sha256:4818f336e9496ba919dd8158172d57b77cb65389f4b6c0d2462fea3a29ad9fda"
    },
    "NetworkManager-libnm": {
      "evra": "1:1.16.2-1.fc30.x86_64",
      "digest": "sha256:f973761517dd7fd2dcfff0aa9578c99e509591a87d0fc316751c0f96e045cbc1"
    },
    "acl": {
      "evra": "2.2.53-3.fc30.x86_64",
      "digest": "sha256:af5d6641b71ec62d126fa71322a8451aa3de7948202633da802bccd1fd6ece45"
    },
    "adcli": {
      "evra": "0.8.2-3.fc30.x86_64",
      "digest": "sha256:ff7862e1b1fefe936f3ae614d008835e686ccdc6ec06e7cf445e8f75d73d50f0"
    },
    "afterburn": {
      "evra": "4.1.1-3.module_f30+4804+1c3d5e42.x86_64",
      "digest": "sha256:71ef65a598f8b0cbeeee0b86f76d345e46ed0af8a1372d09cde99854f1998b4d"
    },
    "afterburn-dracut": {
      "evra": "4.1.1-3.module_f30+4804+1c3d5e42.x86_64",
      "digest": "sha256:a66b425d7b95c5a87f35ce5abc12c01032726e304db9e284ea859a1003437ce2"
    }
  }
}
    """
    requests = Mock()
    requests.get.return_value = requests_response

    m = fedora_messaging.api.Message(
            topic = 'io.pagure.prod.pagure.git.receive',
            body = EXAMPLE_MESSAGE_BODY)
    c = Consumer()
    c.__call__(m)
