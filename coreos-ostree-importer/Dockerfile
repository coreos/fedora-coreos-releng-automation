FROM registry.fedoraproject.org/fedora:31

# set PYTHONUNBUFFERED env var to non-empty string so that our
# periods with no newline get printed immediately to the screen
ENV PYTHONUNBUFFERED=true

# Get any latest updates since last container spin
RUN dnf update -y

# Install boto/fedmsg/ostree libraries
RUN dnf -y install fedora-messaging ostree

# Put the file into a location that can be imported
ADD coreos_ostree_importer.py /usr/lib/python3.7/site-packages/

# Copy in the fedora messaging config into the
# default location
ADD fedora-messaging-config.toml /etc/fedora-messaging/config.toml

# Call fedora-messaging CLI and tell it to use the Consumer
# class from the included module.
CMD fedora-messaging consume --callback=coreos_ostree_importer:Consumer
