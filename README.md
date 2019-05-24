# coreos-koji-tagger

Source code that monitors a git repo and tags packages over into
appropriate koji tags to be consumed by Fedora CoreOS build processes.

# Rough notes for deployment

Create a new project and build the container.

```
oc new-project coreos-koji-tagger
oc new-build --strategy=docker https://pagure.io/dusty/coreos-koji-tagger --to coreos-koji-tagger-img
```

Use kedge to get up and running in openshift:

```
kedge apply -f kedge.yaml
```
