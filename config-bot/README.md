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
