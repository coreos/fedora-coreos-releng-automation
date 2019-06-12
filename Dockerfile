FROM registry.fedoraproject.org/fedora:30

# set PYTHONUNBUFFERED env var to non-empty string so that our
# periods with no newline get printed immediately to the screen
ENV PYTHONUNBUFFERED=true

# Install pagure/fedmsg libraries
RUN dnf -y install python3-libpagure fedora-messaging koji krb5-workstation && dnf clean all

# Grab the kerberos configuration. Pulling directly from upstream
# here rather than installing the fedora-packager rpm because it's
# a bunch of deps and we only need one file.
RUN curl -L https://pagure.io/fedora-packager/raw/master/f/krb-configs/fedoraproject_org > /etc/krb5.conf.d/fedoraproject_org

RUN mkdir /work
WORKDIR /work

# Copy the fedora config for fedora-messaging and also generate a random UUID
# https://fedora-messaging.readthedocs.io/en/latest/fedora-broker.html#getting-connected
# Note this will mean that if there is more than one container running
# using this image they will be reading from the same queue. Generally
# I expect this to only be running in one place.
RUN sed -e "s/[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}/$(uuidgen)/g" /etc/fedora-messaging/fedora.toml > /work/my_config.toml

# Set the Application Name
RUN sed -i 's|Example Application|CoreOS Koji Tagger: https://pagure.io/dusty/coreos-koji-tagger|' /work/my_config.toml

# Lower log levels to WARNING level
RUN sed -i 's/INFO/WARNING/' /work/my_config.toml

# Set the format for the log messages
RUN sed -i 's/format =.*$/format = "%(asctime)s %(levelname)s %(name)s - %(message)s"/' /work/my_config.toml

# We only care about pungi.compose.status.change messages
RUN sed -i 's/^routing_keys.*$/routing_keys = ["io.pagure.prod.pagure.git.receive"]/' /work/my_config.toml

# Put compose-tracker into a location that can be imported
ADD coreos_koji_tagger.py /usr/lib/python3.7/site-packages/

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

# Call fedora-messaging CLI and tell it to use the ComposeTracker
# class from the compose-tracker module.
CMD fedora-messaging --conf /work/my_config.toml consume --callback=coreos_koji_tagger:Consumer

# Put the keytab in place
ADD coreosbot.keytab  /work/
