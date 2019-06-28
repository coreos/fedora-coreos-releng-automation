# coreos-koji-tagger

Source code that monitors a git repo and tags packages over into
appropriate koji tags to be consumed by Fedora CoreOS build processes.

# Deploying in Fedora


The files for deploying to Fedora's OpenShift Instance are:

- [playbooks/openshift-apps/coreos-koji-tagger.yml](https://infrastructure.fedoraproject.org/cgit/ansible.git/tree/playbooks/openshift-apps/coreos-koji-tagger.yml)
- [roles/openshift-apps/coreos-koji-tagger/templates/buildconfig.yml](https://infrastructure.fedoraproject.org/cgit/ansible.git/tree/roles/openshift-apps/coreos-koji-tagger/templates/buildconfig.yml)
- [roles/openshift-apps/coreos-koji-tagger/templates/deploymentconfig.yml](https://infrastructure.fedoraproject.org/cgit/ansible.git/tree/roles/openshift-apps/coreos-koji-tagger/templates/deploymentconfig.yml)
- [roles/openshift-apps/coreos-koji-tagger/templates/imagestream.yml](https://infrastructure.fedoraproject.org/cgit/ansible.git/tree/roles/openshift-apps/coreos-koji-tagger/templates/imagestream.yml)

This can be deployed by people with appropriate permissions by
executing:

```
[localhost]$ ssh batcave01.phx2.fedoraproject.org
[batcave01]$ sudo rbac-playbook openshift-apps/coreos-koji-tagger.yml
```

# Rough notes for deployment to another OpenShift instance:

*NOTE*: This doesn't handle keytab right now but is a good way watch
        what operations would happen.

Create a new project and build the container.

```
NAME=coreos-koji-tagger
oc new-project $NAME
oc new-build --strategy=docker https://github.com/coreos/fedora-coreos-releng-automation --name=$NAME --context-dir=$NAME --to "${NAME}-img"
```

Use kedge to get up and running in openshift:

```
kedge apply -f kedge.yaml
```

# Rough notes for running locally:

From your local directory where you have the keytab

```
keytab=./keytab
podman build -t ckt .
podman run -it --rm -v $PWD/:/pwd/ \
           -e COREOS_KOJI_TAGGER_KEYTAB_FILE=/pwd/$keytab ckt
```

If you'd like you can add `--entrypoint=/bin/bash` and run the
coreos_koji_tagger directly. If you modify the json at the bottom
of the file you can test it out or actually have it call koji
to apply tags.
