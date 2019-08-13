#!/usr/bin/python3
import fedora_messaging.api
import os
import re
import koji
import logging
import json
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

# TODO: Move to config
KOJI_CONFIG = {
    'server_url': 'https://koji.fedoraproject.org/kojihub',
    'options': {
        'krb_rdns': False,
    },
    'authmethod': 'kerberos',
    'principal': 'me@FEDORAPROJECT.ORG',
    'keytab': os.getenv('COREOS_KOJI_TAGGER_KEYTAB_FILE'),
}
if os.getenv('COREOS_KOJI_TAGGER_USE_STG') == 'true':
    KOJI_CONFIG['server_url'] = 'https://koji.stg.fedoraproject.org/kojihub'

# This user will be the owner of a pkg in a tag
# To view existing owners run:
#    - koji list-pkgs --tag=coreos-pool
COREOS_KOJI_USER = 'coreosbot'

# XXX: should be in config file
DEFAULT_GITHUB_REPO_FULLNAME = 'coreos/fedora-coreos-config'
DEFAULT_GITHUB_REPO_BRANCH   = 'refs/heads/testing-devel'


# Given a repo (and thus an input JSON) analyze existing koji tag set
# and tag in any missing packages

class Consumer(object):
    def __init__(self):
        self._koji_client = None
        self._target_tag_id = None
        self.target_tag        = KOJI_TARGET_TAG
        self.intermediate_tag  = KOJI_INTERMEDIATE_TAG
        self.github_repo_fullname = os.getenv(
                                        'GITHUB_REPO_FULLNAME',
                                        DEFAULT_GITHUB_REPO_FULLNAME)
        self.github_repo_branch   = os.getenv(
                                        'GITHUB_REPO_BRANCH',
                                        DEFAULT_GITHUB_REPO_BRANCH)

    @property
    def target_tag_id(self):
        if self._target_tag_id is None:
            taginfo = self.koji_client.getTag(tag)
            self._target_tag_id = taginfo['id']
        return self._target_tag_id

    @property
    def koji_client(self):
        if self._koji_client is not None:
            return self._koji_client

        clt = koji.ClientSession(
            KOJI_CONFIG['serverurl'],
            KOJI_CONFIG['options'],
        )

        if KOJI_CONFIG['authmethod'] == 'kerberos':
            kwargs = {}
            for opt in ('principal', 'keytab', 'ccache'):
                if opt in KOJI_CONFIG:
                    kwargs[opt] = instance_info['options'][opt]
            clt.krb_login(**kwargs)
        else:
            raise ValueError("Unsupported authmethod")

        self._koji_client = clt

        return clt

    def __call__(self, message: fedora_messaging.api.Message):
        logger.debug(message.topic)
        logger.debug(message.body)

        # Grab the raw message body and the status from that
        msg = message.body
        branch = msg['ref']
        repo   = msg['repository']['full_name']
        commit = msg['head_commit']['id']

        if (repo != self.github_repo_fullname):
            logger.debug(f'Skipping message from unrelated repo: {repo}')
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
        # must determine the srpm name (koji build name) from that and compare
        # that with existing koji builds in the tag. Once we have a list of
        # koji builds that aren't in the tag we can add the koji pkg to the
        # tag (if needed) and then tag the koji build into the tag.

        # parse the lockfile and get a set of rpm NEVRAs
        desiredrpms = set(parse_lockfile_data(r.json()))

        # convert the rpm NEVRAs into a list of build IDs
        desiredbuilds = self.get_builds_from_rpmnevras(desiredrpms)

        # Grab the currently tagged builds
        tagbuilds = self.get_tagged_builds(self.target_tag)

        # Get the list of pkgs needed
        desiredpkgs = self.get_pkgs_from_buildids(desiredbuilds)

        # Grab the list of pkgs that can be tagged into the tag
        tagpkgs = self.get_pkglist(self.target_tag)

        # Make sure all packages desired are in the pkglist
        with self.koji_client.multicall(strict=True) as m:
            for newpkg in (desiredpkgs - tagpkgs):
                m.packageListAdd(self.target_tag, newpkg,
                                 owner=COREOS_KOJI_USER)

        # Now perform tagging and untagging
        with self.koji_client.multicall(strict=True) as m:
            for buildid in (desiredbuilds - tagbuilds):
                m.tagBuild(self.intermediate_tag, buildid)

            for buildid in (tagbuilds - desiredbuilds):
                m.untagBuild(self.target_tag, buildid)

        # And all done

    def get_builds_from_rpmnevras(self, rpmnevras: set) -> set:
        # Given a list of rpm NEVRAs get the list of koji build IDs
        if not rpmnevras:
            raise ValueError("No nevras to get_buildsinfo")

        with self.koji_client.multicall(strict=True) as m:
            rpminfos = [m.getRPM(nevra, strict=True) for nevra in rpmnevras]
        return set([ri.result['build_id'] for ri in rpminfos])

    def get_pkgs_from_buildids(self, buildids: set) -> set:
        with self.koji_client.multicall(strict=True) as m:
            builds = [m.getBuild(bid) for bid in buildids]
        return set([build.result['package_name'] for build in builds])

    def get_pkglist(self, tag) -> set:
        # Giiven a tag, return the packages in its pkglist
        pkgs = self.koji_client.listPackages(tagID=self.target_tag_id)
        return set([pkg['package_name'] for pkg in pkgs])

    def get_tagged_builds(self, tag) -> set:
        # Given a tag, return the build IDs tagged into it
        builds = self.koji_client.listTagged(tag=tag)
        return set([build['build_id'] for build in builds])

def parse_lockfile_data(data: dict) -> list:
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
    logger.debug('Retrieved JSON data:')
    logger.debug(json.dumps(data, indent=4, sort_keys=True))

    # We only care about the NEVRAs, so just accumulate those and return
    return [f'{name}-{v["evra"]}' for name, v in data['packages'].items()]


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
