# config-bot

config-bot performs automated management tasks on the main
[fedora-coreos-config](https://github.com/coreos/fedora-coreos-config)
repo.

It performs three closely related, but mostly independent
functions. The names below reflect each of those functions.
One can find their corresponding configuration section in
`config.toml` and function names in `main`.

1. `sync-build-lockfiles`: watches for new builds on a set
   of streams, and pushes the generated lockfile to their
   corresponding branches
2. `promote-lockfiles`: on some configurable interval,
   pushes lockfiles from one config branch to another
3. `propagate-files`: watches for pushes to a config branch
   and propagates changes to a subset of files to a set of
   target branches.

All these are currently timer-based. In the future, they
will use fedora-messaging for triggering.

Similarly, for now all changes are done using `git push`. In
the future, config-bot PR functionality can be added.

## Testing locally

Tweak settings as appropriate in `config.toml`, e.g.:
- point to your fork of `fedora-coreos-config`
- use your own GitHub token
- you can comment out whole sections if you'd like to test a
  specific function only; e.g. if you only want to test
  `promote-lockfiles`, you can comment out
  `sync-build-lockfiles` and `propagate-files`

Then:

```
./main --config myconfig.toml
```

### Deploying to OpenShift

This app is currently deployed in the same namespace as the
[Fedora CoreOS production
pipeline](https://github.com/coreos/fedora-coreos-pipeline).

However, it expects to use a different GitHub token
(`github-coreosbot-token-config-bot`) which only needs
`repo:public_repo` scope. You can find this token in
BitWarden.

To create the secret:

```
$ read token
<token>
$ oc create secret generic github-coreosbot-token-config-bot --from-literal=token=$token
```

To deploy:

```
oc new-app --file=manifest.yaml
```

To get the generated webhook secret text you can run:

```
oc get bc/config-bot -o json \
    | jq -r '.spec.triggers[] | select(.type == "GitHub") | .github.secret'
```

Now you can get the webhook URL by describing the buildconfig:

```
oc get bc/config-bot -o json
```

Then replace the `<secret>` part with the secret above and use
that resulting URL to create a new webhook in the GitHub settings
for this repo as described in the
[OpenShift documentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/builds_using_buildconfig/triggering-builds-build-hooks#builds-using-github-webhooks_triggering-builds-build-hooks).
