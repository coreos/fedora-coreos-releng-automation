FROM registry.fedoraproject.org/fedora:36

# set PYTHONUNBUFFERED env var to non-empty string so that our
# periods with no newline get printed immediately to the screen
ENV PYTHONUNBUFFERED=true

# Get any latest updates since last container spin
RUN dnf update -y

# Install necessary (fedmsg/koji/yaml) libraries
RUN dnf -y install dnf-plugins-core \
                   fedora-messaging \
                   koji             \
                   python3-pyyaml   \
                   krb5-workstation

# Grab the kerberos/koji configuration (i.e. /usr/bin/stg-koji) by
# installing the fedora-packager rpm. We don't need the deps because
# we aren't building anything.
RUN dnf download fedora-packager && rpm -ivh --nodeps fedora-packager*rpm && rm fedora-packager*rpm

RUN mkdir /work
WORKDIR /work

# Copy the fedora config for fedora-messaging and also generate a random UUID
# https://fedora-messaging.readthedocs.io/en/latest/fedora-broker.html#getting-connected
# Note this will mean that if there is more than one container running
# using this image they will be reading from the same queue. Generally
# I expect this to only be running in one place.
RUN sed -e "s/[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}/$(uuidgen)/g" /etc/fedora-messaging/fedora.toml > /work/my_config.toml

# Set the Application Name
RUN sed -i 's|Example Application|CoreOS Koji Tagger: https://github.com/coreos/fedora-coreos-releng-automation/tree/main/coreos-koji-tagger |' /work/my_config.toml

# Lower log levels to WARNING level
RUN sed -i 's/INFO/WARNING/' /work/my_config.toml

# Set the format for the log messages
RUN sed -i 's/format =.*$/format = "%(asctime)s %(levelname)s %(name)s - %(message)s"/' /work/my_config.toml

# We only care about org.fedoraproject.prod.github.push messages
RUN sed -i 's/^routing_keys.*$/routing_keys = ["org.fedoraproject.prod.github.push"]/' /work/my_config.toml

# Add coreos_koji_tagger to the container
ADD coreos_koji_tagger.py /work/

# Environment variable to be defined by the user that defines the
# filesystem path to the keytab file. If blank it will be ignored
# and privileged (write) operations won't be attempted
ENV COREOS_KOJI_TAGGER_KEYTAB_FILE ''

# Error when trying to store the kerberos cache in the default
# location because of use of UID in the cache location:
# default_ccache_name = KEYRING:persistent:%{uid}
#
# kinit: Invalid UID in persistent keyring name while getting default ccache
#
# Workaround by commenting that line from the config:
# https://community.hortonworks.com/content/supportkb/222432/error-kadminlocal-invalid-uid-in-persistent-keyrin.html
RUN sed -i 's/^    default_ccache_name/#   default_ccache_name/' /etc/krb5.conf

# Call fedora-messaging CLI and tell it to use the Consumer
# class from coreos_koji_tagger.py
CMD fedora-messaging --conf /work/my_config.toml consume --callback-file=/work/coreos_koji_tagger.py:Consumer
