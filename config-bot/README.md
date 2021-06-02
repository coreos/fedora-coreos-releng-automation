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
`repo:public_repo` scope.

To deploy:

```
oc new-app --file=manifest.yaml
```

Copy the generated GitHub webhook secret, and substitute it
into the webhook URL from `oc describe bc config-bot`, then
create a new webhook in the GitHub settings for this repo as
described in the [OpenShift
documentation](https://docs.openshift.com/container-platform/4.4/builds/triggering-builds-build-hooks.html#builds-using-github-webhooks_triggering-builds-build-hooks)
using that URL.
