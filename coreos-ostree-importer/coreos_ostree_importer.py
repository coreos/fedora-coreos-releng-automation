#!/usr/bin/python3

import fedora_messaging
import fedora_messaging.api
import hashlib
import json
import logging
import os
import subprocess
import sys
import tarfile
import tempfile
import traceback
import urllib.request

# Set local logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

FEDORA_MESSAGING_TOPIC_LISTEN = (
    "org.fedoraproject.prod.coreos.build.request.ostree-import"
)
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
    "commit": "https://builds.coreos.fedoraproject.org/prod/streams/bodhi-updates/builds/31.20191217.dev.0/x86_64/fedora-coreos-31.20191217.dev.0-ostree.x86_64.tar",
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
        # Check the possible repos to make sure they exist
        for path in KNOWN_OSTREE_REPOS.values():
            if not ostree_repo_exists(path):
                raise Exception(f"OSTree repo does not exist at {path}")

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
            send_message(msg=message.body, status="FAILURE")
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
        commit_url = msg["commit"]
        ostree_checksum = msg["ostree_checksum"]
        ostree_ref = msg["ostree_ref"]
        stream = msg["stream"]
        target_repo = msg["target_repo"]

        # Qualify arguments
        if not checksum.startswith("sha256:"):
            raise Exception("checksum value must start with sha256:")
        if target_repo not in KNOWN_OSTREE_REPOS.keys():
            raise Exception(f"Provided target repo is unknown: {target_repo}")

        sha256sum = checksum[7:]
        target_repo_path = KNOWN_OSTREE_REPOS[target_repo]
        source_repo_path = None

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


def send_message(msg: dict, status: str):
    # Send back a message with all the original message body
    # along with an additional `status:` header with either
    # `SUCCESS` or `FAILURE`.
    fedora_messaging.api.publish(
        fedora_messaging.message.Message(
            topic=FEDORA_MESSAGING_TOPIC_RESPOND, body={"status": status, **msg}
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
    # verify the parent commit of the new commit is in the destination repo
    # and also that the current branch in the repo points to it
    branch_exists = ostree_branch_exists(repo=dstrepo, branch=branch)
    parent = ostree_get_parent_commit(repo=srcrepo, commit=commit)
    if branch_exists:
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
    # update summary file
    logger.info("Updating summary file")
    cmd = ["ostree", f"--repo={dstrepo}", "summary", "-u"]
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

    m = fedora_messaging.api.Message(
        topic="org.fedoraproject.prod.coreos.build.request.ostree-import",
        body=EXAMPLE_MESSAGE_BODY,
    )
    c = Consumer()
    c.__call__(m)
