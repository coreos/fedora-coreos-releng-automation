#!/usr/bin/python3
import dnf.subject
import fedora_messaging.api
import hawkey
import json
import koji
import logging
import os
import re
import requests
import subprocess
import sys
import traceback
import yaml
import time

from koji_cli.lib import watch_tasks
from tenacity import retry, wait_fixed, stop_after_attempt, retry_if_exception_type

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
DEFAULT_GITHUB_REPO_BRANCHES = 'refs/heads/testing-devel refs/heads/next-devel'

# We are processing the org.fedoraproject.prod.github.push topic
# https://apps.fedoraproject.org/datagrepper/raw?topic=org.fedoraproject.prod.github.push&delta=100000
EXAMPLE_MESSAGE_BODY = json.loads("""
{
    "forced": false, 
    "compare": "https://github.com/coreos/fedora-coreos-config/compare/d6c02b5cd107...6a53f43af882", 
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
      "updated_at": "2019-08-18T17:31:15Z", 
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
      "size": 163, 
      "archived": false, 
      "has_projects": false, 
      "watchers_count": 28, 
      "forks": 35, 
      "homepage": null, 
      "fork": false, 
      "description": "Base configuration for Fedora CoreOS", 
      "has_downloads": true, 
      "forks_count": 35, 
      "default_branch": "testing-devel", 
      "html_url": "https://github.com/coreos/fedora-coreos-config", 
      "node_id": "MDEwOlJlcG9zaXRvcnkxNDU0ODQwMjg=", 
      "has_issues": true, 
      "master_branch": "testing-devel", 
      "stargazers_count": 28, 
      "name": "fedora-coreos-config", 
      "open_issues_count": 12, 
      "watchers": 28, 
      "language": "Shell", 
      "license": {
        "spdx_id": "NOASSERTION", 
        "url": null, 
        "node_id": "MDc6TGljZW5zZTA=", 
        "name": "Other", 
        "key": "other"
      }, 
      "url": "https://github.com/coreos/fedora-coreos-config", 
      "stargazers": 28, 
      "created_at": 1534810727, 
      "pushed_at": 1566244300, 
      "open_issues": 12, 
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
        "added": [
          "manifest-lock.x86_64.json"
        ], 
        "author": {
          "email": "coreosbot@fedoraproject.org", 
          "name": "CoreOS Bot"
        }, 
        "distinct": true, 
        "timestamp": "2019-08-19T19:51:38Z", 
        "modified": [], 
        "url": "https://github.com/coreos/fedora-coreos-config/commit/6a53f43af8826d0befd76656b2ce5e66c1111980", 
        "tree_id": "7ee4648a6d5c43c17ebd6c617f911b4d358e83d7", 
        "message": "lockfiles: import from bodhi-updates", 
        "removed": [], 
        "id": "6a53f43af8826d0befd76656b2ce5e66c1111980"
      }
    ], 
    "after": "6a53f43af8826d0befd76656b2ce5e66c1111980", 
    "fas_usernames": {
      "coreos": "github_org_coreos"
    }, 
    "head_commit": {
      "committer": {
        "email": "coreosbot@fedoraproject.org", 
        "name": "CoreOS Bot"
      }, 
      "added": [
        "manifest-lock.x86_64.json"
      ], 
      "author": {
        "email": "coreosbot@fedoraproject.org", 
        "name": "CoreOS Bot"
      }, 
      "distinct": true, 
      "timestamp": "2019-08-19T19:51:38Z", 
      "modified": [], 
      "url": "https://github.com/coreos/fedora-coreos-config/commit/6a53f43af8826d0befd76656b2ce5e66c1111980", 
      "tree_id": "7ee4648a6d5c43c17ebd6c617f911b4d358e83d7", 
      "message": "lockfiles: import from bodhi-updates", 
      "removed": [], 
      "id": "6a53f43af8826d0befd76656b2ce5e66c1111980"
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
    "before": "d6c02b5cd10751fe4b44f5fae44b45293f334cdd"
  }
"""
)

def catch_exceptions_and_continue(func):
    # This is a decorator function that will re-call the decorated
    # function and will catch any exceptions and not raise them further.
    # We want to do this because if we raise exceptions it will cause
    # /usr/bin/fedora-messaging to crash and we'll lose the traceback
    # logs from the container
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error('Caught Exception!')
            logger.error('###################################')
            traceback.print_exc()
            logger.error('###################################')
            logger.error('\t continuing...')
            pass 
    return wrapper

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

# Given a repo analyze existing koji tag set and tag in any missing packages
class Consumer(object):
    def __init__(self):
        self.target_tag        = KOJI_TARGET_TAG
        self.intermediate_tag  = KOJI_INTERMEDIATE_TAG
        self.github_repo_fullname = os.getenv(
                                        'GITHUB_REPO_FULLNAME',
                                        DEFAULT_GITHUB_REPO_FULLNAME)
        self.github_repo_branches = os.getenv(
                                        'GITHUB_REPO_BRANCHES',
                                        DEFAULT_GITHUB_REPO_BRANCHES).split()
        self.koji_user         = COREOS_KOJI_USER
        self.koji_client       = koji.ClientSession(KOJI_SERVER_URL)

        logger.info("Watching commits against branches %s of %s repo" %
                    (self.github_repo_branches, self.github_repo_fullname))

        # If a keytab was specified let's try to auth.
        self.keytab_file = os.getenv('COREOS_KOJI_TAGGER_KEYTAB_FILE')
        if self.keytab_file:
            # Assert the defined keytab file exists
            if not os.path.exists(self.keytab_file):
                raise Exception("The specified keytab file "
                                "does not exist: %s" % self.keytab_file)
            self.koji_login()
        else:
            logger.info('No keytab file defined in '
                        '$COREOS_KOJI_TAGGER_KEYTAB_FILE')
            logger.info('Will not attempt koji write operations')

        # do an initial run on startup in case we're out of sync
        for branch in self.github_repo_branches:
            self.process_lockfiles(branch[len("refs/heads/"):])


    def __call__(self, message: fedora_messaging.api.Message):
        self.process_message(message)

    @catch_exceptions_and_continue
    def process_message(self, message: fedora_messaging.api.Message):
        logger.debug(message.topic)
        logger.debug(message.body)

        # Grab the raw message body and the status from that
        msg = message.body
        branch = msg['ref']
        repo   = msg['repository']['full_name']

        if (repo != self.github_repo_fullname):
            logger.info(f'Skipping message from unrelated repo: {repo}')
            return

        if (branch not in self.github_repo_branches):
            logger.info(f'Skipping message from unrelated branch: {branch}')
            return

        # Some messages don't have commit information
        # For example: https://apps.fedoraproject.org/datagrepper/id?id=2019-f32c811b-658b-4ac7-a455-a7edf616a033&is_raw=true&size=extra-large
        commit = None
        if msg['head_commit']:
            commit = msg['head_commit']['id']
        if commit is None:
            logger.error('No commit id in message!')
            return

        # In case our connection has expired, re-Auth to koji
        if self.keytab_file:
            self.koji_login()

        self.process_lockfiles(commit)

    @catch_exceptions_and_continue
    def process_lockfiles(self, rev):
        # Now grab lockfile data from the commit we should operate on:
        desiredrpms = set()
        for arch in ['x86_64', 'aarch64', 'ppc64le', 's390x']:
            for lockfile in ['manifest-lock', 'manifest-lock.overrides']:
                for filetype in ['yaml', 'json']:
                    url = f'https://raw.githubusercontent.com/{self.github_repo_fullname}/{rev}/{lockfile}.{arch}.{filetype}'
                    logger.info(f'Attempting to retrieve data from {url}')
                    r = requests.get(url)
                    if r.ok:
                        # parse the lockfile and add the set of rpm NEVRAs (strings)
                        desiredrpms.update(parse_lockfile_data(r.text, filetype))
                        break # If both yaml and json files exist, only parse one 
                              # of them. Prefer yaml.
                    else:
                        # Log any errors we encounter. 404s are ok, but won't hurt to log
                        logger.warning('URL request error: %s' % r.text.strip())
        if not desiredrpms:
            logger.warning('No locked RPMs found!')
            logger.warning("Does the repo:ref (%s:%s) have any lockfiles?" %
                            (self.github_repo_fullname, rev))
            logger.warning('Continuing...')
            return

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
                # pylint: disable=E1102
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
                # pylint: disable=E1102
                with self.koji_client.multicall(strict=True) as m:
                    tasks = [m.tagBuild(tag=tag, build=nvr)
                                    for (tag, nvr) in tuples]
                watch_tasks(self.koji_client,
                            [task.result for task in tasks],
                            poll_interval=10)
                logger.info('Tagging done')

                # Subsequently run a distrepo task because there are
                # races in tag2distrepo. https://pagure.io/koji/issue/1630
                # Before running distrepo let's wait for all rpms to
                # pass through signing and make it into the target tag
                #
                # If not done in ten minutes then just timeout (60*10s = 10 minutes)
                for x in range(0, 60):
                    currentbuildids = self.get_tagged_buildids(self.target_tag)
                    difference = desiredbuildids - currentbuildids
                    if difference:
                        logger.info('Waiting on builds to be signed')
                        logger.info('Remaining builds: %s' %
                                        [buildsinfo[x].nvr for x in difference])
                        time.sleep(10)
                        continue
                    break
                # If all the builds didn't make it into the target
                # then just return here.
                if difference:
                    logger.error('Some builds never got signed..  Giving up')
                    return
                # This code is mostly stolen from:
                # https://pagure.io/releng/tag2distrepo/blob/master/f/tag2distrepo.py
                taginfo = self.koji_client.getTag(self.target_tag)
                keys = taginfo['extra'].get("tag2distrepo.keys", '').split()
                task_opts = {
                    'arch': taginfo['arches'].split(),
                    'comp': None,
                    'delta': [],
                    'event': None,
                    'inherit': False,
                    'latest': False,
                    'multilib': False,
                    'split_debuginfo': False,
                    'skip_missing_signatures': False,
                    'allow_missing_signatures': False,
                }
                task = self.koji_client.distRepo(self.target_tag,
                                                    keys, **task_opts)
                watch_tasks(self.koji_client, [task], poll_interval=10)
                logger.info('Dist-repo task has finished')

    # retry to login every 30s for 15m before giving up
    # https://github.com/coreos/fedora-coreos-releng-automation/issues/70
    @retry(retry=retry_if_exception_type(koji.AuthError), wait=wait_fixed(30), stop=stop_after_attempt(30))
    def koji_login(self):
        # If already authenticated then nothing to do
        # Catch koji.AuthError as that is what happens
        # when we get logged out.
        try:
            if self.koji_client.getLoggedInUser():
                return
        except koji.AuthError as e:
            logger.info('Received koji.AuthError from koji. Re-attempting login.')
            pass
        # Login!
        principal = find_principal_from_keytab(self.keytab_file)
        self.koji_client.gssapi_login(principal, self.keytab_file)

    def get_buildsinfo_from_rpmnevras(self, rpmnevras: set) -> dict:
        """
        Given a set of rpm NEVRAs get a set of corresponding koji buildids
        """
        if not rpmnevras:
            raise ValueError("No nevras to get_builds_from_rpmnevras")

        buildsinfo = {} # dict of buildid -> BuildInfo object

        # Grab info about each of the rpms
        with self.koji_client.multicall(strict=True) as m:  # pylint: disable=E1102
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
        with self.koji_client.multicall(strict=True) as m:  # pylint: disable=E1102
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
        """
        Given a tag, return the set of packages in its pkglist
        """
        pkgs = self.koji_client.listPackages(tagID=tag)
        return set([pkg['package_name'] for pkg in pkgs])

    def get_tagged_buildids(self, tag: str) -> set:
        """
        Given a tag, return the buildids tagged into it
        """
        builds = self.koji_client.listTagged(tag=tag)
        return set([build['build_id'] for build in builds])

def find_principal_from_keytab(keytab: str) -> str:
    """
    Find the pricipal/realm that the keytab is for
    """
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

    # return the first hawkey.NEVRA item in the list of possibilities
    rpminfo = nevras[0]

    # come up with rpm NVRA
    nvra = f"{rpminfo.name}-{rpminfo.version}-{rpminfo.release}.{rpminfo.arch}"
    return nvra

def parse_lockfile_data(text: str, filetype: str) -> set:
    """
    Parse the rpm lockfile format and return a set of rpms in
    NEVRA form.
    Best documention on the format for now:
        https://github.com/projectatomic/rpm-ostree/commit/8ff0ee9c89ecc0540182b5b506455fc275d27a61
    
    An example looks something like:
    
      {
        "packages": {
          "GeoIP": {
            "evra": "1.6.12-5.fc30.x86_64"
          }
        }
      }

    or 

      packages:
        GeoIP:
          evra: 1.6.12-5.fc30.x86_64
    """

    if filetype == 'json':
        data = json.loads(text)
        logger.debug('Retrieved JSON data:')
        logger.debug(json.dumps(data, indent=4, sort_keys=True))
    elif filetype == 'yaml':
        data = yaml.safe_load(text)
        logger.debug('Retrieved YAML data:')
        logger.debug(yaml.safe_dump(data))

    # We only care about the NEVRAs, so just accumulate those and return
    return set([f'{name}-{v["evra"]}' for name, v in data['packages'].items()])

def get_releasever_from_buildroottag(buildroottag: str) -> str:
    logger.debug(f'Checking buildroottag {buildroottag}')
    if buildroottag.startswith('module-') and buildroottag.endswith('-build'):
        releasever = re.search('module-.*-(\d\d)[\d]{14}-[a-f0-9]{8}-build$',
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
# call by updating the yaml text below.
if __name__ == '__main__':
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logger.addHandler(sh)

    # Mock the web request to get the data so that we can easily
    # modify the below values in order to run a test:
    from unittest.mock import Mock
    sample_lockfile = """
packages:
  GeoIP:
    evra: 1.6.12-5.fc30.x86_64
  GeoIP-GeoLite-data:
    evra: 2018.06-3.fc30.noarch
  NetworkManager:
    evra: 1:1.16.2-1.fc30.x86_64
  NetworkManager-libnm:
    evra: 1:1.16.2-1.fc30.x86_64
  acl:
    evra: 2.2.53-3.fc30.x86_64
  adcli:
    evra: 0.8.2-3.fc30.x86_64
  afterburn:
    evra: 4.1.1-3.module_f30+4804+1c3d5e42.x86_64
  afterburn-dracut:
    evra: 4.1.1-3.module_f30+4804+1c3d5e42.x86_64
    """

    # Make requests.get() return the above sample lockfile
    # for only one of the requested lockfiles. Otherwise 404
    def side_effect(*args, **kwargs):
        requests_response = Mock()
        if args[0].endswith('lock.x86_64.yaml'):
            requests_response.ok = True
            requests_response.text = sample_lockfile
        else:
            requests_response.ok = False
            requests_response.text = "URL request error: 404: Not Found"
        return requests_response
    requests.get = Mock(side_effect=side_effect)

    # Note that the following will call process_lockfiles twice. Once
    # for startup and once for the fake message we're passing.
    m = fedora_messaging.api.Message(
            topic = 'org.fedoraproject.prod.github.push',
            body = EXAMPLE_MESSAGE_BODY)
    c = Consumer()
    c.__call__(m)
