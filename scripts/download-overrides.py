#!/usr/bin/python3

import dnf.subject
import hawkey
import os
import yaml
import subprocess
import sys


# this was copied from coreos-koji-tagger
def get_NVRA_from_NEVRA(string: str) -> str:
    form = hawkey.FORM_NEVRA

    # get a hawkey.Subject object for the string
    subject = dnf.subject.Subject(string)  # returns hawkey.Subject

    # get a list of hawkey.NEVRA objects that are the possibilities
    nevras = subject.get_nevra_possibilities(forms=form)

    # return the first hawkey.NEVRA item in the list of possibilities
    rpminfo = nevras[0]

    # come up with rpm NVRA
    nvra = f"{rpminfo.name}-{rpminfo.version}-{rpminfo.release}.{rpminfo.arch}"
    return nvra


def is_override_lockfile(filename: str) -> bool:
    return (filename.startswith('manifest-lock.overrides.')
            and filename[-4:] in ['json', 'yaml'])


assert os.path.isdir("builds"), "Missing builds/ dir; is this a cosa workdir?"

rpms = set()
for filename in os.listdir(os.path.join("src/config")):
    if is_override_lockfile(filename):
        with open(f'src/config/{filename}') as f:
            lockfile = yaml.safe_load(f)
        for pkg, pkgobj in lockfile['packages'].items():
            rpms.add(get_NVRA_from_NEVRA(f"{pkg}-{pkgobj['evra']}"))

if not rpms:
    print("No overrides; exiting.")
    sys.exit(0)

# could probably be more efficient here by using the Koji API directly, but
# meh... there shouldn't be that many overrides anyway
for rpm in rpms:
    os.makedirs('overrides/rpm', exist_ok=True)
    subprocess.check_call(['koji', 'download-build', '--rpm', rpm],
                          cwd='overrides/rpm')
