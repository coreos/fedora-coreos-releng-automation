# coreos-release-notes-generator

`coreos-release-notes-generator` generates `release-notes.yaml` from `release-notes.d` yaml snippets using the specified build id using `--build-id` option.

## Options
 - `--build-id`: build id of the latest release
 - `--config-dir`: path to the directory where `release-notes.d/` lives
 - `--release-notes-file`: path to the input `release-notes.yaml` file for update
 - `--output-dir`: output directory for `release-notes.yaml`
 - `--json`: output JSON format instead of YAML for easier consumption by Fedora CoreOS website (https://getfedora.org/en/coreos?stream=stable)

As an example, assuming following structure:
```
.
├── fedora-coreos-config
└── fedora-coreos-releng-automation

```

## Generate a new `release-notes.yaml`

To generate a new `release-notes.yaml`, simply omit `--release-notes.yaml`:
```
$ ./release-notes-generator.py --config-dir ../../fedora-coreos-config/ \
    --build-id 32.20200817.2.1

- 32.20200817.2.1:
    coreos-installer:
    - subject: installer 4
    - body: installer body 1
      subject: installer 1
    - subject: installer 2
    - subject: installer 3
    ignition:
    - body: ignition body 1
      subject: ignition 1
    - subject: igntiion 2
    miscellaneous:
    - subject: misc 2
    - subject: misc 1

```

## Update existing `release-notes.yaml`

To update existing `release-notes.yaml`:
```
$ cat ../../fedora-coreos-config/release-notes.yaml
- 32.20200801.2.1:
    afterburn:
    - body: afterburn body 1
      subject: afterburn 1
    - subject: afterburn 2
    miscellaneous:
    - subject: misc 1

$ ./release-notes-generator.py --release-notes-file ../../fedora-coreos-config/release-notes.yaml \
    --config-dir ../../fedora-coreos-config/ \
    --build-id 32.20200817.2.1
- 32.20200817.2.1:
    coreos-installer:
    - subject: installer 4
    - body: installer body 1
      subject: installer 1
    - subject: installer 2
    - subject: installer 3
    ignition:
    - body: ignition body 1
      subject: ignition 1
    - subject: igntiion 2
    miscellaneous:
    - subject: misc 2
    - subject: misc 1
- 32.20200801.2.1:
    afterburn:
    - body: afterburn body 1
      subject: afterburn 1
    - subject: afterburn 2
    miscellaneous:
    - subject: misc 1

```
