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

# Might have to do this: https://community.hortonworks.com/content/supportkb/222432/error-kadminlocal-invalid-uid-in-persistent-keyrin.html

RUN mkdir /work
WORKDIR /work

# Copy the fedora config for fedora-messaging and also generate a random UUID
# https://fedora-messaging.readthedocs.io/en/latest/fedora-broker.html#getting-connected
# Note this will mean that if there is more than one container running
# using this image they will be reading from the same queue. Generally
# I expect this to only be running in one place.
RUN sed -e "s/[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}/$(uuidgen)/g" /etc/fedora-messaging/fedora.toml > /work/my_config.toml

# Lower log levels to WARNING level
#RUN sed -i 's/INFO/WARNING/' /work/my_config.toml
# We only care about pungi.compose.status.change messages
#RUN sed -i 's/^routing_keys.*$/routing_keys = ["pungi.compose.status.change"]/' /work/my_config.toml

# Put compose-tracker into a location that can be imported
ADD coreos_koji_tagger.py /usr/lib/python3.7/site-packages/

# Call fedora-messaging CLI and tell it to use the ComposeTracker
# class from the compose-tracker module.
CMD fedora-messaging --conf /work/my_config.toml consume --callback=coreos_koji_tagger:Consumer
