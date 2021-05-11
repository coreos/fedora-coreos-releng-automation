# coreos-ostree-importer

Source code that watches for ostree-import requests on the fedora
messaging bus and imports those commit objects into the ostree
repositories managed by Fedora infra/releng teams. 

# Deploying in Fedora

The [playbook](https://pagure.io/fedora-infra/ansible/blob/main/f/playbooks/openshift-apps/coreos-ostree-importer.yml)
and [supporting files](https://pagure.io/fedora-infra/ansible/blob/main/f/roles/openshift-apps/coreos-ostree-importer)
for deploying to Fedora's OpenShift Instance are in the
[Fedora Infra Ansible repo](https://pagure.io/fedora-infra/ansible).

The application can be deployed by people with appropriate permissions by
executing:

```
[localhost]$ ssh batcave01.iad2.fedoraproject.org
[batcave01]$ sudo rbac-playbook openshift-apps/coreos-ostree-importer.yml
```

The Application will then be running in Fedora OpenShift instances:

- [PROD](https://os.fedoraproject.org/console/project/coreos-ostree-importer/)
- [STAGE](https://os.stg.fedoraproject.org/console/project/coreos-ostree-importer/)

If you have appropriate permissions you'll be able to view them in the
OpenShift web interface.

To limit executing playbooks against `prod` or `staging` you can use
`-l os_masters[0]` or `-l os_masters_stg[0]`.

To take down the application completely:

```
[localhost]$ ssh batcave01.iad2.fedoraproject.org
[batcave01]$ sudo rbac-playbook -t delete openshift-apps/coreos-ostree-importer.yml
```

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
    "build_id": "31.20191217.dev.0",
    "stream": "bodhi-updates",
    "basearch": "x86_64",
    "commit_url": "https://builds.coreos.fedoraproject.org/prod/streams/bodhi-updates/builds/31.20191217.dev.0/x86_64/fedora-coreos-31.20191217.dev.0-ostree.x86_64.tar",
    "checksum": "sha256:7aadab5768438e4cd36ea1a6cd60da5408ef2d3696293a1f938989a318325390",
    "ostree_ref": "fedora/x86_64/coreos/bodhi-updates",
    "ostree_checksum": "4481da720eedfefd3f6ac8925bffd00c4237fd4a09b01c37c6041e4f0e45a3b9",
    "target_repo": "compose"
}
api.publish(message.Message(topic=topic, body=body))
EOF
```

You'll have to update the body with new information you'd like to use. Then run:

```
./publisher.py
```

## Fedora Messaging sender from the Fedora CoreOS Pipeline

Included in this directory is a file (`send-ostree-import-request.py`)
that is not used by the `coreos-ostree-importer`
at all. It is used by the
[Fedora CoreOS Pipeline](https://github.com/coreos/fedora-coreos-pipeline.git)
to send the request to the importer. It made sense to co-locate the
requester and importer in the same code repo/directory.

Here's how you might send a request using `fcos-pipeline-ostree-import-request.py`: 


```
cosa buildprep --build=31.20200212.20.0 s3://fcos-builds/prod/streams/testing-devel/builds
/usr/lib/coreos-assembler/send-ostree-import-request.py \
        --fedmsg-conf /srv/fedora-messaging-config.toml \
        --build 31.20200212.20.0 --stg \
        --s3 fcos-builds/prod/streams/testing-devel \
        --repo compose
```
