#!/usr/bin/python3

import fedora_messaging
import fedora_messaging.api
import hashlib
import json
import logging
import os
import requests
import stat
import subprocess
import sys
import tarfile
import tempfile
import traceback
import urllib.request

# Set local logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# This should be one of:
#   - org.fedoraproject.prod.coreos.build.request.ostree-import
#   - org.fedoraproject.stg.coreos.build.request.ostree-import
FEDORA_MESSAGING_TOPIC_LISTEN = fedora_messaging.config.conf.get("bindings")[0]["routing_keys"][0]
FEDORA_MESSAGING_TOPIC_RESPOND = FEDORA_MESSAGING_TOPIC_LISTEN + ".finished"


# We are processing the org.fedoraproject.prod.coreos.build.request.ostree-import topic
# https://apps.fedoraproject.org/datagrepper/raw?topic=org.fedoraproject.prod.coreos.build.request.ostree-import&delta=100000
# The schema was originally designed in:
# https://github.com/coreos/fedora-coreos-tracker/issues/198#issuecomment-513944390
EXAMPLE_MESSAGE_BODY = json.loads(
    """
{
    "build_id": "31.20191217.dev.0",
    "stream": "bodhi-updates",
    "basearch": "x86_64",
    "commit_url": "https://builds.coreos.fedoraproject.org/prod/streams/bodhi-updates/builds/31.20191217.dev.0/x86_64/fedora-coreos-31.20191217.dev.0-ostree.x86_64.tar",
    "checksum": "sha256:7aadab5768438e4cd36ea1a6cd60da5408ef2d3696293a1f938989a318325390",
    "ostree_ref": "fedora/x86_64/coreos/bodhi-updates",
    "ostree_checksum": "4481da720eedfefd3f6ac8925bffd00c4237fd4a09b01c37c6041e4f0e45a3b9",
    "target_repo": "compose"
}
"""
)

KNOWN_OSTREE_REPOS = {
    "prod": "/mnt/koji/ostree/repo",
    "compose": "/mnt/koji/compose/ostree/repo",
}

class Consumer(object):
    def __init__(self):
        # Do sanity checks on the repos
        for path in KNOWN_OSTREE_REPOS.values():

            # Check the repo to make sure it exists
            if not ostree_repo_exists(path):
                raise Exception(f"OSTree repo does not exist at {path}")

            # Sanity check the repo to make sure all directories in the repo
            # have the appropriate permissions (most importantly group writable).
            # See https://pagure.io/releng/issue/8811#comment-616490
            assert_dirs_permissions(path)

        logger.info(
            "Processing messages with topic: %s" % FEDORA_MESSAGING_TOPIC_LISTEN
        )

    def __call__(self, message: fedora_messaging.api.Message):
        # Catch any exceptions and don't raise them further because
        # it will cause /usr/bin/fedora-messaging to crash and we'll
        # lose the traceback logs from the container
        try:
            self.process(message)
            logger.info("Sending SUCCESS message")
            send_message(msg=message.body, status="SUCCESS")
        except Exception as e:
            logger.error("Caught Exception!")
            logger.error("###################################")
            traceback.print_exc()
            logger.error("###################################")
            logger.error("Replying with a FAILURE message...")
            send_message(msg=message.body, status="FAILURE", failure_message=str(e))
            logger.error("\t continuing...")
            pass

    def process(self, message: fedora_messaging.api.Message):
        logger.debug(message.topic)
        logger.debug(message.body)

        # Grab the raw message body and parse out pieces
        msg = message.body
        basearch = msg["basearch"]
        build_id = msg["build_id"]
        checksum = msg["checksum"]
        commit_url = msg["commit_url"]
        ostree_checksum = msg["ostree_checksum"]
        ostree_ref = msg["ostree_ref"]
        target_repo = msg["target_repo"]

        # Qualify arguments
        if not checksum.startswith("sha256:"):
            raise Exception("checksum value must start with sha256:")
        if target_repo not in KNOWN_OSTREE_REPOS.keys():
            raise Exception(f"Provided target repo is unknown: {target_repo}")

        sha256sum = checksum[7:]
        target_repo_path = KNOWN_OSTREE_REPOS[target_repo]
        source_repo_path = None

        # Sanity check the repo to make sure all directories in the repo
        # have the appropriate permissions (most importantly group writable).
        # See https://pagure.io/releng/issue/8811#comment-616490
        assert_dirs_permissions(target_repo_path)

        logger.info(
            f"Processing request to import {build_id} into the "
            f"{ostree_ref} branch of the {target_repo} repo."
        )

        # Detect if the commit already exists in the target repo
        # NOTE: We assume here that an import won't be requested twice for
        #       the same commit (i.e. someone adds detached metadata and
        #       then does a second import request).
        if ostree_commit_exists(target_repo_path, ostree_checksum):
            logger.info(
                f"Commit {ostree_checksum} already exists in the target repo. "
                "Skipping import"
            )
            return

        # Import the OSTree commit to the specified repo. We'll use
        # a temporary directory to untar the repo into.
        with tempfile.TemporaryDirectory() as tmpdir:
            # If the target repo is the prod repo the commit could
            # already have been imported into the compose repo. If it
            # is already in the compose repo then let's just pull-local
            # from there to save downloading all from the net again.
            if target_repo == "prod" and ostree_commit_exists(
                repo=KNOWN_OSTREE_REPOS["compose"], commit=ostree_checksum
            ):
                logger.info("Commit exists in compose repo. Importing from there")
                source_repo_path = KNOWN_OSTREE_REPOS["compose"]
            else:
                # Grab the file from a web url and then pull local
                untar_file_from_url(url=commit_url, tmpdir=tmpdir, sha256sum=sha256sum)
                source_repo_path = tmpdir

            # one more sanity check: make sure buildid == version
            assert_commit_has_version(
                repo=source_repo_path, commit=ostree_checksum, version=build_id
            )
            # Import the commit into the target repo
            ostree_pull_local(
                commit=ostree_checksum,
                dstrepo=target_repo_path,
                srcrepo=source_repo_path,
                branch=ostree_ref,
            )

        # Update the summary file if we're in the prod repo. The compose
        # repo doesn't use a summary file and creating one causes problems
        if target_repo == "prod":
            ostree_update_summary(target_repo_path)


def assert_dirs_permissions(path: str):
    # Find all directories under path. We need to optimize os.walk()
    # here because it can take a really long time to find all the
    # directories on the NFS mounts because it must look at every file
    # and there are many many files in the directories under objects/*/.
    # Here we'll optmize for the fact that we know objects/* are directories
    # and objects/*/* are normal files so we don't need to traverse deeper.
    directories = []
    for root, dirs, files in os.walk(path, topdown=True):
        # don't traverse into the objects/*/ directories
        # dirs[:] = [] will cause os.walk to not traverse deeper
        # https://stackoverflow.com/a/19859907
        if root == os.path.join(path, 'objects'):
            for d in dirs:
                directories.append(os.path.join(root, d))
            dirs[:] = []
        else:
            directories.append(root)
    # Determine if any of the directories have inappropriate permissions
    founderror = False
    for d in directories:
        statinfo = os.stat(d)
        # Verifies group permissions are 0bXXX111XXX (---rwx---)
        if ((statinfo.st_mode & stat.S_IRWXG) != stat.S_IRWXG):
            logger.warning(f"Directory {root} does not have rwx group permissions!")
            founderror = True
    if founderror:
        raise Exception(f"Found directories that did not have rwx group permissions")


def runcmd(cmd: list, **kwargs: int) -> subprocess.CompletedProcess:
    try:
        # default args to pass to subprocess.run
        pargs = {"check": True, "capture_output": True}
        logger.debug(f"Running command: {cmd}")
        pargs.update(kwargs)
        cp = subprocess.run(cmd, **pargs)
    except subprocess.CalledProcessError as e:
        logger.error("Command returned bad exitcode")
        logger.error(f"COMMAND: {cmd}")
        logger.error(f" STDOUT: {e.stdout.decode()}")
        logger.error(f" STDERR: {e.stderr.decode()}")
        raise e
    return cp  # subprocess.CompletedProcess


def send_message(msg: dict, status: str, failure_message: str = ""):
    # Send back a message with all the original message body
    # along with additional `status:` and `failure-message` headers.
    body = {"status": status, **msg}
    if failure_message:
        body["failure-message"] = failure_message
    fedora_messaging.api.publish(
        fedora_messaging.message.Message(
            topic=FEDORA_MESSAGING_TOPIC_RESPOND, body=body
        )
    )


# https://stackoverflow.com/a/55542529
def get_sha256sum(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as file:
        while True:
            # Reading is buffered, so we can read smaller chunks.
            chunk = file.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def untar_file_from_url(url: str, tmpdir: str, sha256sum: str):
    filename = "ostree.tar"
    filepath = os.path.join(tmpdir, filename)

    # Grab file from the url
    logger.info(f"Downloading object from url: {url}")
    urllib.request.urlretrieve(url, filepath)

    # Verify file has correct checksum
    calcuatedsum = get_sha256sum(filepath)
    if sha256sum != calcuatedsum:
        raise Exception("Checksums do not match: " f"{sha256sum} != {calcuatedsum}")

    # Untar the file into the temporary directory
    with tarfile.open(filepath) as tar:
        tar.extractall(path=tmpdir)


def ostree_pull_local(srcrepo: str, dstrepo: str, branch: str, commit: str):
    branch_exists = ostree_branch_exists(repo=dstrepo, branch=branch)
    has_parent_commit = ostree_has_parent_commit(repo=srcrepo, commit=commit)

    # If we're making a new branch let's make sure it's the first commit (i.e.
    # has no parent). There could be cases where we actually want to do this
    # but let's do it manually in releng to make sure it's what we actually
    # want to do.
    if has_parent_commit and not branch_exists:
        raise Exception("Refusing to import non-origin commit into a new branch")

    # If we have a parent commit and the branch is already in the repo then
    # verify the parent commit of the new commit is in the destination repo
    # and also that the current branch in the repo points to it
    if has_parent_commit and branch_exists:
        parent = ostree_get_parent_commit(repo=srcrepo, commit=commit)
        assert_branch_points_to_commit(repo=dstrepo, branch=branch, commit=parent)

    # pull content
    logger.info("Running ostree pull-local to perform import")
    cmd = ["ostree", f"--repo={dstrepo}", "pull-local", srcrepo, commit]
    runcmd(cmd)
    # update branch
    if branch_exists:
        cmd = ["ostree", f"--repo={dstrepo}", "reset", branch, commit]
    else:
        cmd = ["ostree", f"--repo={dstrepo}", "refs", f"--create={branch}", commit]
    logger.info(f"Updating branch {branch} -> {commit} in {dstrepo}")
    runcmd(cmd)


def ostree_update_summary(repo: str):
    logger.info("Updating summary file")
    cmd = ["ostree", f"--repo={repo}", "summary", "-u"]
    runcmd(cmd)


def ostree_repo_exists(repo: str) -> bool:
    if not os.path.exists(repo):
        return False
    cmd = ["ostree", f"--repo={repo}", "refs"]
    if runcmd(cmd, check=False).returncode != 0:
        logger.debug(f"OSTree repo does not exist at {repo}")
        return False
    return True


def ostree_commit_exists(repo: str, commit: str) -> bool:
    cmd = ["ostree", f"--repo={repo}", "show", commit]
    return runcmd(cmd, check=False).returncode == 0


def ostree_branch_exists(repo: str, branch: str) -> bool:
    cmd = ["ostree", f"--repo={repo}", "rev-parse", branch]
    return runcmd(cmd, check=False).returncode == 0

def ostree_has_parent_commit(repo: str, commit: str) -> str:
    cmd = ["ostree", f"--repo={repo}", "rev-parse", f"{commit}^"]
    return runcmd(cmd, check=False).returncode == 0

def ostree_get_parent_commit(repo: str, commit: str) -> str:
    cmd = ["ostree", f"--repo={repo}", "rev-parse", f"{commit}^"]
    return runcmd(cmd, check=True).stdout.strip().decode()


def assert_branch_points_to_commit(repo: str, branch: str, commit: str):
    cmd = ["ostree", f"--repo={repo}", "rev-parse", branch]
    cp = runcmd(cmd, check=True)
    detected = cp.stdout.strip().decode()
    logger.debug(f"{branch} points to {detected}")
    if commit != detected:
        raise Exception(f"{branch} points to {detected}. Expected {commit}")


def assert_commit_has_version(repo: str, commit: str, version: str):
    cmd = ["ostree", f"--repo={repo}", "show", commit, "--print-metadata-key=version"]
    cp = runcmd(cmd, check=True)
    embeddedversion = cp.stdout.replace(b"'", b"").strip().decode()
    if version != embeddedversion:
        raise Exception(
            "Embedded commit version does not match buildid "
            f"{version} != {embeddedversion}"
        )


# The code in this file is expected to be run through fedora messaging
# However, you can run the script directly for testing purposes. The
# below code allows us to do that and also fake feeding data to the
# call by updating the json text below.
if __name__ == "__main__":
    sh = logging.StreamHandler()
    sh.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    )
    logger.addHandler(sh)

    # Allow a user to pass in a url to a datagrepper page and we'll
    # parse that and pass it into the Consumer.
    if len(sys.argv) == 1:
        # no args, just use example message body
        body = EXAMPLE_MESSAGE_BODY
    else:
        # User passed in a url like:
        # https://apps.fedoraproject.org/datagrepper/id?id=2020-32c268dc-36ba-4cef-be6a-f4969a0c83af&is_raw=true&size=extra-large
        url = sys.argv[1]
        logger.info(f'Attempting to retrieve data from {url}')
        r = requests.get(url)
        data = json.loads(r.text)
        logger.debug('Retrieved JSON data:')
        logger.debug(json.dumps(data, indent=4, sort_keys=True))
        body = data['msg']

    # Create a Message and then call the Consumer()
    m = fedora_messaging.api.Message(
        topic=FEDORA_MESSAGING_TOPIC_LISTEN,
        body=body,
    )
    c = Consumer()
    c.__call__(m)
