# coreos-ostree-importer

Source code that watches for ostree-import requests on the fedora
messaging bus and imports those commit objects into the ostree
repositories managed by Fedora infra/releng teams. 

# Rough notes for running locally:

If you'd like to use a local rabbitmq server setup you'll need to modify the
`amqp_url` at the top of the `fedora-messaging-config.toml` file
to point to your local server. For example: `amqp_url = "amqp://192.168.121.2"`
See the [later section](#running-rabbitmq-server-locally)
on that topic and update your fedora messaging config accordingly.

From your local git directory:

```
podman build -t coreos-ostree-importer .
```

Create some empty OSTree repos:

```
mkdir /srv/prodrepo
mkdir /srv/composerepo

ostree --repo=/srv/prodrepo init --mode=archive 
ostree --repo=/srv/composerepo init --mode=archive
```

Run the importer:

```
podman run -it --rm                                                \
           -v $PWD/:/pwd/                                          \
           -v /srv/composerepo/:/mnt/koji/compose/ostree/repo/:z   \
           -v /srv/prodrepo/:/mnt/koji/ostree/repo/:z              \
           coreos-ostree-importer
```


If you'd like you can add `--entrypoint=/bin/bash` and run 
`/pwd/coreos_koji_tagger.py` directly. If you modify the json at the top
of the file you can test out the import locally.


# Running rabbitmq server locally:


## Server

The rough steps for setting up a server are: 

- `sudo dnf install -y fedora-messaging rabbitmq-server`
- `sudo systemctl start rabbitmq-server`

Optional - to see a web browser view:

- `sudo sed -i -e 's|@RABBITMQ_USER@|rabbitmq|' -e 's|@RABBITMQ_GROUP@|rabbitmq|' /usr/sbin/rabbitmq-plugins`
    - https://bugzilla.redhat.com/show_bug.cgi?id=1755152
- `sudo rabbitmq-plugins enable rabbitmq_management`
- Navigate to `<IP_OF_HOST>:15672` in a web browser and log in with `guest`/`guest`. 
- Navigate to `Queues` tab to view existing queues/messages.

## Fedora Messaging consumer

If you want to see the `request.ostree-import.finished` messages sent by the ostree-importer
you can run the following command on the on the same system that is running the rabbitmq server.

```
fedora-messaging consume --callback=fedora_messaging.example:printer --routing-key org.fedoraproject.prod.coreos.build.request.ostree-import.finished
```

## Fedora Messaging sender

If you'd like to send a `request.ostree-import` message to rabbitmq (i.e. letting the
ostree-importer listen and react to the message) you can do something like this python file
on the rabbitmq server:

```
cat <<'EOF' > publisher.py
#!/usr/bin/python3
from fedora_messaging import api, message
topic = 'org.fedoraproject.prod.coreos.build.request.ostree-import'
body = {
    "build_id": "30.20190905.0",
    "stream": "testing",
    "basearch": "x86_64",
    "commit": "https://fcos-builds/prod/streams/testing/builds/30.20190905.0/x86_64/ostree-commit.tar",
    "checksum": "sha256:d01db6939e7387afa2492ac8e2591c53697fc21cf16785585f7f1ac0de692863",
    "ostree_ref": "fedora/x86_64/coreos/testing",
    "ostree_checksum": "b4beca154dab3696fd04f32ddab818102caa9247ec3192403adb9aaecc991bd9",
    "target_repo": "prod"
}
api.publish(message.Message(topic=topic, body=body))
EOF
```

You'll have to update the body with new information you'd like to use. Then run:

```
./publisher.py
```
