#!/usr/bin/python3
import fedora_messaging.api
import os
import re
import requests
import logging
import json
import koji
from koji_cli.lib import watch_tasks
import traceback

import dnf.subject
import hawkey

import sys
import subprocess
import requests

# Set local logging 
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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

# if we are in a stage environment then use the stage koji
if os.getenv('COREOS_KOJI_TAGGER_USE_STG', 'false') == 'true':
    KOJI_SERVER_URL = 'https://koji.stg.fedoraproject.org/kojihub'
else:
    KOJI_SERVER_URL = 'https://koji.fedoraproject.org/kojihub'

# This user will be the owner of a pkg in a tag
# To view existing owners run:
#    - koji list-pkgs --tag=coreos-pool
COREOS_KOJI_USER = 'coreosbot'

# XXX: should be in config file
DEFAULT_GITHUB_REPO_FULLNAME = 'coreos/fedora-coreos-config'
DEFAULT_GITHUB_REPO_BRANCH   = 'refs/heads/testing-devel'

# We are processing the org.fedoraproject.prod.github.push topic
# https://apps.fedoraproject.org/datagrepper/raw?topic=org.fedoraproject.prod.github.push&delta=100000
EXAMPLE_MESSAGE_BODY = json.loads("""
{
  "forced": false,
  "compare": "https://github.com/coreos/fedora-coreos-config/compare/b7205807daab...17f8d4c15a28",
  "pusher": {
    "email": "coreosbot@users.noreply.github.com",
    "name": "coreosbot"
  },
  "sender": {
    "url": "https://api.github.com/users/coreosbot",
    "site_admin": false,
    "html_url": "https://github.com/coreosbot",
    "node_id": "MDQ6VXNlcjYxNDg4NTA=",
    "gravatar_id": "",
    "login": "coreosbot",
    "type": "User",
    "id": 6148850
  },
  "repository": {
    "has_wiki": true,
    "has_pages": false,
    "updated_at": "2019-07-22T19:47:35Z",
    "private": false,
    "disabled": false,
    "full_name": "coreos/fedora-coreos-config",
    "owner": {
      "name": "coreos",
      "url": "https://api.github.com/users/coreos",
      "site_admin": false,
      "html_url": "https://github.com/coreos",
      "email": null,
      "node_id": "MDEyOk9yZ2FuaXphdGlvbjM3MzA3NTc=",
      "gravatar_id": "",
      "login": "coreos",
      "type": "Organization",
      "id": 3730757
    },
    "id": 145484028,
    "size": 123,
    "archived": false,
    "has_projects": false,
    "watchers_count": 25,
    "forks": 32,
    "homepage": null,
    "fork": false,
    "description": "Base configuration for Fedora CoreOS",
    "has_downloads": true,
    "forks_count": 32,
    "default_branch": "testing-devel",
    "html_url": "https://github.com/coreos/fedora-coreos-config",
    "node_id": "MDEwOlJlcG9zaXRvcnkxNDU0ODQwMjg=",
    "has_issues": true,
    "master_branch": "testing-devel",
    "stargazers_count": 25,
    "name": "fedora-coreos-config",
    "open_issues_count": 10,
    "watchers": 25,
    "language": "Shell",
    "license": {
      "spdx_id": "NOASSERTION",
      "url": null,
      "node_id": "MDc6TGljZW5zZTA=",
      "name": "Other",
      "key": "other"
    },
    "url": "https://github.com/coreos/fedora-coreos-config",
    "stargazers": 25,
    "created_at": 1534810727,
    "pushed_at": 1564157477,
    "open_issues": 10,
    "organization": "coreos"
  },
  "created": false,
  "deleted": false,
  "commits": [
    {
      "committer": {
        "email": "coreosbot@fedoraproject.org",
        "name": "CoreOS Bot"
      },
      "added": [],
      "author": {
        "email": "coreosbot@fedoraproject.org",
        "name": "CoreOS Bot"
      },
      "distinct": true,
      "timestamp": "2019-07-26T16:11:15Z",
      "modified": [
        "manifest-lock.generated.x86_64.json"
      ],
      "url": "https://github.com/coreos/fedora-coreos-config/commit/17f8d4c15a28864c8229906a5723b8de9e00804a",
      "tree_id": "a3ab160b89b264870cf3cecd7b4d6c252e8a5482",
      "message": "lockfiles: import from build 30.20190725.dev.0",
      "removed": [],
      "id": "17f8d4c15a28864c8229906a5723b8de9e00804a"
    }
  ],
  "after": "17f8d4c15a28864c8229906a5723b8de9e00804a",
  "fas_usernames": {
    "coreos": "github_org_coreos"
  },
  "head_commit": {
    "committer": {
      "email": "coreosbot@fedoraproject.org",
      "name": "CoreOS Bot"
    },
    "added": [],
    "author": {
      "email": "coreosbot@fedoraproject.org",
      "name": "CoreOS Bot"
    },
    "distinct": true,
    "timestamp": "2019-07-26T16:11:15Z",
    "modified": [
      "manifest-lock.generated.x86_64.json"
    ],
    "url": "https://github.com/coreos/fedora-coreos-config/commit/17f8d4c15a28864c8229906a5723b8de9e00804a",
    "tree_id": "a3ab160b89b264870cf3cecd7b4d6c252e8a5482",
    "message": "lockfiles: import from build 30.20190725.dev.0",
    "removed": [],
    "id": "17f8d4c15a28864c8229906a5723b8de9e00804a"
  },
  "organization": {
    "url": "https://api.github.com/orgs/coreos",
    "login": "coreos",
    "node_id": "MDEyOk9yZ2FuaXphdGlvbjM3MzA3NTc=",
    "description": "Key components to secure, simplify and automate your container infrastructure",
    "id": 3730757
  },
  "ref": "refs/heads/testing-devel",
  "base_ref": null,
  "before": "b7205807daab0bbe1a3e65383b5155c2e37f03c6"
}
"""
)


class BuildInfo(object):
    def __init__(self, buildid, buildrootid):
        self.buildrootid = buildrootid
        self.id          = buildid
        self._name       = None
        self._nvr        = None
        self._releasever = None

        @property
        def releasever(self):
            return self._releasever
        @releasever.setter
        def releasever(self, value):
            self._releasever = value

        @property
        def name(self):
            return self._name
        @name.setter
        def name(self, value):
            self._name = value

        @property
        def nvr(self):
            return self._nvr
        @nvr.setter
        def nvr(self, value):
            self._nvr = value

# Given a repo (and thus an input JSON) analyze existing koji tag set
# and tag in any missing packages
class Consumer(object):
    def __init__(self):
        self.target_tag        = KOJI_TARGET_TAG
        self.intermediate_tag  = KOJI_INTERMEDIATE_TAG
        self.github_repo_fullname = os.getenv(
                                        'GITHUB_REPO_FULLNAME',
                                        DEFAULT_GITHUB_REPO_FULLNAME)
        self.github_repo_branch   = os.getenv(
                                        'GITHUB_REPO_BRANCH',
                                        DEFAULT_GITHUB_REPO_BRANCH)
        self.koji_user         = COREOS_KOJI_USER
        self.koji_client       = koji.ClientSession(KOJI_SERVER_URL)

        # If a keytab was specified let's try to auth.
        self.keytab_file = os.getenv('COREOS_KOJI_TAGGER_KEYTAB_FILE')
        if self.keytab_file:
            if not os.path.exists(self.keytab_file):
                raise Exception("The specified keytab file "
                                "does not exist: %s" % self.keytab_file)
            principal = find_principal_from_keytab(self.keytab_file)
            self.koji_client.gssapi_login(principal, self.keytab_file)
        else:
            logger.info('No keytab file defined in '
                        '$COREOS_KOJI_TAGGER_KEYTAB_FILE')
            logger.info('Will not attempt koji write operations')

    def __call__(self, message: fedora_messaging.api.Message):
        # Catch any exceptions and don't raise them further because
        # it will cause /usr/bin/fedora-messaging to crash and we'll
        # lose the traceback logs from the container
        try:
            self.process(message)
        except Exception as e:
            logger.error('Caught Exception!')
            logger.error('###################################')
            traceback.print_exc()
            logger.error('###################################')
            logger.error('\t continuing...')
            pass

    def process(self, message: fedora_messaging.api.Message):
        logger.debug(message.topic)
        logger.debug(message.body)

        # Grab the raw message body and the status from that
        msg = message.body
        branch = msg['ref']
        repo   = msg['repository']['full_name']
        commit = msg['head_commit']['id']

        if (repo != self.github_repo_fullname):
            logger.info(f'Skipping message from unrelated repo: {repo}')
            return

        if (branch != self.github_repo_branch):
            logger.info(f'Skipping message from unrelated branch: {branch}')
            return

        # Now grab data from the commit we should operate on:
        # XXX: should update for multi-arch
        url = f'https://raw.githubusercontent.com/{repo}/{commit}/manifest-lock.generated.x86_64.json'
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

        # parse the lockfile and get a set of rpm NEVRAs (strings)
        desiredrpms = set(parse_lockfile_data(r.text))

        # convert the NEVRAs into a dict of build IDs -> BuildInfo objects
        buildsinfo = self.get_buildsinfo_from_rpmnevras(desiredrpms)
        desiredbuildids = buildsinfo.keys()

        # Grab the build IDs of currently tagged builds
        currentbuildids = self.get_tagged_buildids(self.target_tag)

        # Get the set of names of pkgs needed
        desiredpkgs = set([x.name for x in buildsinfo.values()])

        # Grab the set of names of pkgs that can be tagged into the tag
        pkgsintag = self.get_pkglist_in_tag(self.target_tag)

        # compute the pkgstoadd and the buildstotag
        pkgstoadd   = desiredpkgs - pkgsintag
        buildstotag = desiredbuildids - currentbuildids 

        # Log if there is nothing to do
        if not pkgstoadd and not buildstotag:
            logger.info(f'No new builds to tag.. going back to sleep')
            return

        # Make sure all packages desired are in the pkglist
        if pkgstoadd:
            logger.info('Adding packages to the '
                        f'{self.target_tag} tag: {pkgstoadd}')
            if self.keytab_file:
                with self.koji_client.multicall(strict=True) as m:
                    for pkg in pkgstoadd:
                        m.packageListAdd(self.target_tag, pkg,
                                         owner=self.koji_user)
                logger.info('Package adding done')

        # Perform the tagging for each release into the intermediate
        # tag for that release if we have credentials
        if buildstotag:
            # Get a set of tuples of build name to tag to tag into
            tuples = [(self.intermediate_tag.format(
                        releasever=buildsinfo[x].releasever),
                        buildsinfo[x].nvr)
                        for x in buildstotag]
            logger.info('Tagging the following (tag, nvr): \n\t%s' %
                                            '\n\t'.join(map(str, tuples)))
            if self.keytab_file:
                with self.koji_client.multicall(strict=True) as m:
                    tasks = [m.tagBuild(tag=tag, build=nvr)
                                    for (tag, nvr) in tuples]
                watch_tasks(self.koji_client,
                            [task.result for task in tasks],
                            poll_interval=10)
                logger.info('Tagging done')


    def get_buildsinfo_from_rpmnevras(self, rpmnevras: set) -> dict:
        # Given a set of rpm NEVRAs get a set of corresponding koji buildids
        if not rpmnevras:
            raise ValueError("No nevras to get_builds_from_rpmnevras")

        buildsinfo = {} # dict of buildid -> BuildInfo object

        # Grab info about each of the rpms
        with self.koji_client.multicall(strict=True) as m:
            nvras = [get_NVRA_from_NEVRA(nevra) for nevra in rpmnevras]
            rpminfos = [m.getRPM(nvra, strict=True) for nvra in nvras]

        for rpm in [r.result for r in rpminfos]:
            buildsinfo[rpm['build_id']] = \
                BuildInfo(buildid     = rpm['build_id'],
                          buildrootid = rpm['buildroot_id'])

        # Grab info about each related build
        # Grab info about each builds buildroot
        buildinfo = {}
        brinfo = {}
        with self.koji_client.multicall(strict=True) as m:
            for buildid in buildsinfo.keys():
                buildinfo[buildid] = m.getBuild(buildid, strict=True)
                brinfo[buildid] = \
                    m.getBuildroot(buildsinfo[buildid].buildrootid, strict=True)

        # Update the BuildInfo objects with the information we now have
        # Now translate the buildroot tag name into a releasever and
        # add it to the BuildInfo objects
        for buildid in buildsinfo.keys():
            buildsinfo[buildid].name = buildinfo[buildid].result['name']
            buildsinfo[buildid].nvr = buildinfo[buildid].result['nvr']
            # Apply a heuristic to the buildroot tag name in order to
            # derive the releasever for this build so that we can then
            # know what intermediate tag to tag it into
            buildsinfo[buildid].releasever = \
                get_releasever_from_buildroottag(
                    brinfo[buildid].result['tag_name'])

        return buildsinfo

    def get_pkglist_in_tag(self, tag: str) -> set:
        # Given a tag, return the set of packages in its pkglist
        pkgs = self.koji_client.listPackages(tagID=tag)
        return set([pkg['package_name'] for pkg in pkgs])

    def get_tagged_buildids(self, tag: str) -> set:
        # Given a tag, return the buildids tagged into it
        builds = self.koji_client.listTagged(tag=tag)
        return set([build['build_id'] for build in builds])

def find_principal_from_keytab(keytab: str) -> str:
    # Find the pricipal/realm that the keytab is for
    cmd = ['/usr/bin/klist', '-k', keytab]
    cp = runcmd(cmd, capture_output=True, check=True)

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
    logger.info(f'Found principal {principal} in keytab')
    return principal

def runcmd(cmd: list, **kwargs: int) -> subprocess.CompletedProcess:
    try:
        logger.info(f'Running command: {cmd}')
        cp = subprocess.run(cmd, **kwargs)
    except subprocess.CalledProcessError as e:
        logger.error('Running command returned bad exitcode')
        logger.error(f'COMMAND: {cmd}')
        logger.error(f' STDOUT: {e.stdout}')
        logger.error(f' STDERR: {e.stderr}')
        raise e
    return cp # subprocess.CompletedProcess

def get_NVRA_from_NEVRA(string: str) -> str:
    form=hawkey.FORM_NEVRA

    # get a hawkey.Subject object for the string
    subject = dnf.subject.Subject(string) # returns hawkey.Subject

    # get a list of hawkey.NEVRA objects that are the possibilities
    nevras  = subject.get_nevra_possibilities(forms=form)

    # get a list of hawkey.NEVRA objects that are the possibilities
    nevras  = subject.get_nevra_possibilities(forms=form)

    # return the first hawkey.NEVRA item in the list of possibilities
    rpminfo = nevras[0]

    # come up with rpm NVRA
    nvra = f"{rpminfo.name}-{rpminfo.version}-{rpminfo.release}.{rpminfo.arch}"
    return nvra

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
        raise Exception('Could not derive a releasever for the given'
                       f'buildroot tag: {buildroottag}')
    return releasever

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
            topic = 'org.fedoraproject.prod.github.push',
            body = EXAMPLE_MESSAGE_BODY)
    c = Consumer()
    c.__call__(m)
