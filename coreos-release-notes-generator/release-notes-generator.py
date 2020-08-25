"""Fedora CoreOS Release Notes Generator

This script allows the developer to generate a YAML / JSON format Fedora
CoreOS release notes file with specified build id.

This script updates existing `release-notes.yaml` if specified by the flag
`--release-notes-file` or creates a new one if none is specified.

This script writes the output to STDOUT by default or to the `release-notes.yaml`
or `release-notes.json` specified by the flags `--output-dir` and `--json`.

This file contains the following functions:

    * parse_args - parse command line arguments
    * read_yaml_snippets - read yaml snippets from `release-notes.d` directory
    * write_yaml_snippets - write yaml snippets to STDOUT or `release-notes.yaml` or `release-notes.json`
    * main - the main function of the script
"""


import yaml
import argparse
import os
import glob
import json
import sys


def parse_args():
    """
    Returns:
        Namspace: Parsed command line attributes
    """
    parser = argparse.ArgumentParser(
        description="Builds 'release-notes.yaml' from yaml snippets \
            under 'release-notes.d' directory with specified build id. \
            Outputs to STDOUT by default.")

    parser.add_argument(
        '--build-id', help='build id of the release', required=True)
    parser.add_argument(
        '--config-dir', help="FCOS config directory where 'release-notes.d' lives", required=True)
    parser.add_argument(
        '--release-notes-file', help="input 'release-notes.yaml' for update, omit to generate a new one", required=False)
    parser.add_argument(
        '--output-dir', help="output directory for 'release-notes.yaml'", required=False)
    parser.add_argument('--json', action='store_true',
                        help='output json instead of yaml', required=False)
    args = parser.parse_args()
    return args


def read_yaml_snippets(args):
    """Reads and parses yaml snippets under `release-notes.d` directory

    Args:
        args (Namespace): Parsed command line attributes

    Returns:
        dictionary: A dictionary consists of a new release notes item generated from
                    yaml snippets under `release-notes.yaml`. As an example:
                    {"ignition": [{subject: "", body: ""}]}
    """
    if not os.path.exists(args.config_dir):
        raise Exception(
            "config directory '{}' does not exist".format(args.config_dir))

    if not os.path.exists(os.path.join(args.config_dir, 'release-notes.d')):
        raise Exception(
            "release-notes.d does not exist under {}".format(args.config_dir))

    snippet_yaml_list = glob.glob(os.path.join(
        args.config_dir, 'release-notes.d/*.yaml'))
    if len(snippet_yaml_list) == 0:
        print("release-notes.d/ does not contain any yaml snippets under '{}'".format(args.config_dir))
        return dict()

    snippet_dict = dict()
    for snippet_yaml in snippet_yaml_list:
        with open(snippet_yaml, 'r') as f:
            snippet = yaml.load(f, Loader=yaml.FullLoader)
            for item in snippet:
                note = {'subject': item.get(
                    'subject', ''), 'body': item.get('body', '')}
                # purposely avoid item.get('component', '') to error out if the component key does not exist
                component_name = item['component']
                snippet_dict[component_name] = [*snippet_dict.get(component_name, []), note]

    # clean up empty fields
    for component in snippet_dict.copy():
        # filter out empty note item that has empty component line
        if component == '':
            snippet_dict.pop(component, '')
            continue
        # filter out empty note item that has empty subject line
        snippet_dict[component] = list(
            filter(lambda item: len(item['subject']) > 0, snippet_dict[component]))
        # remove empty note body from note item
        for i, item in enumerate(snippet_dict.copy()[component]):
            if item.get('body', '') == '':
                item.pop('body', '')
                snippet_dict[component][i] = item
        # remove the component if all note items are removed
        if len(snippet_dict[component]) == 0:
            snippet_dict.pop(component, '')
    return snippet_dict


def write_yaml_snippets(args, snippet_dict):
    """Writes the generated release note item to STDOUT or file

    Writes a new release note if `--release-notes-file` is not specified and
    writes to STDOUT if `--outptu-dir` is not specified. Default format is
    YAML unless `--json` is specified.

    Args:
        args (Namespace): Parsed command line attributes
        snippet_dict (dictionary): The newly created release note item returned
            by `read_yaml_snippets`
    """
    if len(snippet_dict) == 0:
        print("empty release notes generated from yaml snippets, nothing to be written")
        return

    # output file name and format depending on the --json flag
    outfile = 'release-notes.json' if args.json else 'release-notes.yaml'

    # store list of release note dictionaries
    release_notes = []
    if args.release_notes_file:
        if not os.path.exists(args.release_notes_file):
            raise Exception(
                "intput file '{}' does not exist".format(args.release_notes_file))
        with open(args.release_notes_file, 'r') as f:
            release_notes = yaml.load(f, Loader=yaml.FullLoader)
    release_notes.insert(0, {args.build_id: snippet_dict})

    if args.output_dir:
        if not os.path.exists(args.output_dir):
            raise Exception(
                "output directory '{}' does not exist".format(args.output_dir))
        if not os.path.isdir(args.output_dir):
            raise Exception(
                "output path '{}' is not a directory".format(args.output_dir))
        outfile = os.path.join(args.output_dir, outfile)
        if args.json:
            with open(outfile, 'w') as f:
                json.dump(release_notes, f, indent=2)
        else:
            print(yaml.dump(release_notes, default_flow_style=False),
                  file=open(outfile, 'w'))
        print(f"successfully wrote release note file at {outfile}")
    else:
        if args.json:
            json.dump(release_notes, sys.stdout, indent=2)
        else:
            print(yaml.dump(release_notes, default_flow_style=False))
    return


def main():
    """Main function of the script

    Parses command line argument, then reads and parses yaml snippets under
    `release-notes.d/`, then writes the newly generated release note item to
    either STDOUT(default) or a file.
    """
    args = parse_args()
    snippet_dict = read_yaml_snippets(args)
    write_yaml_snippets(args, snippet_dict)


if __name__ == "__main__":
    main()
