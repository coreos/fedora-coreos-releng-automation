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

The Application will then be running in Fedora OpenShift instances:

- [PROD](https://os.fedoraproject.org/console/project/coreos-koji-tagger/)
- [STAGE](https://os.stg.fedoraproject.org/console/project/coreos-koji-tagger/)

If you have appropriate permissions you'll be able to view them in the
OpenShift web interface.

# Testing in Fedora Stage

In order to test a new version of coreos-koji-tagger in Fedora Stage
there are two inputs which you can control:

- The coreos-koji-tagger source code
- The input manifest lockfiles

In order to update the source code you need to push to the repo/branch
currently being monitored by the
[the buildconfig](https://infrastructure.fedoraproject.org/cgit/ansible.git/tree/roles/openshift-apps/coreos-koji-tagger/templates/buildconfig.yml).
for the staging environment. This will most likely be the
`fedora-infra-staging` branch of this git repo.

Once you have the version of coreos-koji-tagger that you want running
in stage you need to push code to the repo/branch currently being monitored
by the staging coreos-koji-tagger. This involves changing the manifest file(s)
and pushing to the git repo. To see the branch/repo currently being
monitored you can see that in the
[deploymentconfig](https://infrastructure.fedoraproject.org/cgit/ansible.git/tree/roles/openshift-apps/coreos-koji-tagger/templates/deploymentconfig.yml).

You'll need to either push to the target branch/repo or you'll need to
update the deploymentconfig to point to another one that you control. The
repo will need to be set up publish events to fedmsg using
[github2fedmsg](https://apps.fedoraproject.org/github2fedmsg) so that
the script can pick up the event and process it.

The manifest file(s) will need to be updated to contain information
about RPMs that are available in the staging koji. In order to test
the full process (including signing) we need to use rpms that were
built in staging koji and not just imported from prod. Here is a
oneliner you can use to find those rpms:

```
$ stg-koji list-builds --after '2019-10-01 11:56:41' --volume=DEFAULT --state=COMPLETE --type=rpm | grep fc31
```

That command will show you rpmbuilds built in staging koji (`--volume=DEFAULT`) 
that were successful. The `--after` allows you to limit the search so the query
takes less time. Grepping for `fc31` helps to find rpms for that release.
You can test with any rpm, not just ones that are in FCOS.

Once you git push you should notice the tagger pick up the event
and perform some tagging. The RPMs should eventually end up in the
[coreos-pool repodist directory](https://kojipkgs.stg.fedoraproject.org/repos-dist/coreos-pool).

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

If you'd like you can add `--entrypoint=/bin/bash` and run 
`/pwd/coreos_koji_tagger.py` directly. If you modify the yaml at the bottom
of the file you can test it out or actually have it call koji
to apply tags.
