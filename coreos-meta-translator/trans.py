#!/usr/bin/env python3

from argparse import ArgumentParser, FileType
from datetime import datetime
import json
import os


def ensure_dup(inp, out, inp_key, out_key):
    '''
    If the out dictionary does not contain a value for out_key update it
    to be equal to the inp dictionaries inp_key value, if it does exist
    ensure the values are equal between the two dictionaries
    '''
    if out.get(out_key, None) == None:
        out[out_key] = inp.get(inp_key)
    if out.get(out_key) != inp.get(inp_key):
        raise Exception("Input Files do not appear to be for the same release")

def url_builder(stream, version, arch, path):
    return f"https://builds.coreos.fedoraproject.org/prod/streams/{stream}/builds/{version}/{arch}/{path}"

def get_extension(path, modifier):
    return path.rsplit(modifier)[1][1:]


parser = ArgumentParser()
parser.add_argument("--workdir", help="cosa workdir", required=True)
parser.add_argument("--build-id", help="build id", required=False)
args = parser.parse_args()

arches = []

with open(os.path.join(args.workdir, "builds", "builds.json"), 'r') as build_file:
    build_json = json.load(build_file)
    if len(build_json.get('builds', [])) > 0:
        individual_build = {}
        if args.build_id is None:
            individual_build = build_json.get('builds')[0]
            args.build_id = individual_build.get('id')
        else:
            for build in build_json.get('builds'):
                if build.get('id') == args.build_id:
                    individual_build = build
                    break
        arches = individual_build.get('arches')

outer_dir = os.path.join(args.workdir, "builds", args.build_id)
release_file = os.path.join(outer_dir, "release.json")

out = {}
if os.path.exists(release_file):
    with open(release_file, 'r') as w:
        out = json.load(w)

files = [os.path.join(outer_dir, arch, "meta.json") for arch in arches]

for f in files:
    with open(f, 'r') as w:
        input_ = json.load(w)

        arch = input_.get("coreos-assembler.basearch")

        ensure_dup(input_, out, "buildid", "release")
        ensure_dup(input_.get('coreos-assembler.container-config-git'), out, 'branch', 'stream')

        # build the architectures dict
        arch_dict = {"media": {}}
        ensure_dup(input_, arch_dict, "ostree-commit", "commit")
        generic_arches = ["aws", "qemu", "metal", "openstack", "vmware"]
        for ga in generic_arches:
            if input_.get("images", {}).get(ga, None) is not None:
                i = input_.get("images").get(ga)
                ext = get_extension(i.get('path'), ga)
                arch_dict['media'][ga] = {
                    "artifacts": {
                        ext: {
                            "disk": {
                                "location": url_builder(out.get('stream'), out.get('release'), arch, i.get('path')),
                                "signature": "{}.sig".format(url_builder(out.get('stream'), out.get('release'), arch, i.get('path'))),
                                "sha256": i.get("sha256")
                            }
                        }
                    }
                }

        # AMI specific additions
        if input_.get("amis", None) is not None:
            arch_dict["media"]["aws"] = arch_dict["media"].get("aws", {})
            arch_dict["media"]["aws"]["images"] = arch_dict["media"]["aws"].get("images", {})
            for ami_dict in input_.get("amis"):
                arch_dict["media"]["aws"]["images"][ami_dict["name"]] = {
                    "image": ami_dict["hvm"]
                }

        # metal specific additions
        arch_dict["media"]["metal"] = arch_dict["media"].get("metal", {})
        arch_dict["media"]["metal"]["artifacts"] = arch_dict["media"]["metal"].get("artifacts", {})
        if input_.get("images", {}).get("iso", None) is not None:
            i = input_.get("images").get("iso")
            arch_dict["media"]["metal"]["artifacts"]["installer.iso"] = {
                "disk": {
                    "location": url_builder(out.get('stream'), out.get('release'), arch, i.get('path')),
                    "signature": "{}.sig".format(url_builder(out.get('stream'), out.get('release'), arch, i.get('path'))),
                    "sha256": i.get("sha256")
                }
            }
        if input_.get("images", {}).get("kernel", None) is not None:
            i = input_.get("images").get("kernel")
            arch_dict["media"]["metal"]["artifacts"]["installer-pxe"] = arch_dict["media"]["metal"]["artifacts"].get("installer-pxe",{})
            arch_dict["media"]["metal"]["artifacts"]["installer-pxe"]["kernel"] = {
                "location": url_builder(out.get('stream'), out.get('release'), arch, i.get('path')),
                "signature": "{}.sig".format(url_builder(out.get('stream'), out.get('release'), arch, i.get('path'))),
                "sha256": i.get("sha256")
            }
        if input_.get("images", {}).get("initramfs", None) is not None:
            i = input_.get("images").get("initramfs")
            arch_dict["media"]["metal"]["artifacts"]["installer-pxe"] = arch_dict["media"]["metal"]["artifacts"].get("installer-pxe", {})
            arch_dict["media"]["metal"]["artifacts"]["installer-pxe"]["initramfs"] = {
                "location": url_builder(out.get('stream'), out.get('release'), arch, i.get('path')),
                "signature": "{}.sig".format(url_builder(out.get('stream'), out.get('release'), arch, i.get('path'))),
                "sha256": i.get("sha256")
            }

        # if architectures as a whole or the individual arch is empty just push our changes
        if out.get('architectures', None) is None or out['architectures'].get(arch, None) is None:
            oa = out.get('architectures', {})
            oa[arch] = arch_dict
            out['architectures'] = oa
        # else check media warning if key present, appending if not
        else:
            out_arch = out['architectures'][arch]
            for media_type, val in arch_dict.get('media').items():
                if media_type not in out_arch['media']:
                    out['architectures'][arch]['media'].update({media_type: val})
                elif val == out_arch['media'][media_type]:
                    continue
                else:
                    raise Exception("differing media type detected: input_file '{}', media_type '{}'".format(input_file, media_type))

with open(release_file, 'w') as w:
    json.dump(out, w)
