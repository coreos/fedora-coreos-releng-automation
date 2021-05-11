FROM registry.fedoraproject.org/fedora:34

# set PYTHONUNBUFFERED env var to non-empty string so that our
# output immediately comes to the console
ENV PYTHONUNBUFFERED=true

# Get any latest updates since last container spin
RUN dnf update -y

# Install needed rpms
RUN dnf -y install \
        fedora-messaging \
        python-requests  \
        ostree           \
        strace

# Configure a umask of 0002 which will allow for the group permissions
# to include write for newly created files. We need this because we'd
# like to access the OSTree repos from two different Kubernetes pods,
# which will have different UIDs but the same GID.
# See: https://pagure.io/releng/issue/8811#comment-616490
#
# This is also done within the coreos-ostree-importer-wrapper script,
# but we also want it done in the container because admins may run some
# ostree operations by hand from a bash prompt and we want those
# operations to not put the repo in a bad state.
RUN echo 'umask 0002' > /etc/profile.d/umask-for-openshift.sh

# Add coreos_ostree_importer to the container
ADD coreos_ostree_importer.py /usr/local/lib/

# Copy in the fedora messaging config into the
# default location
ADD fedora-messaging-config.toml /etc/fedora-messaging/config.toml

# Copy in the wrapper that starts the importer
ADD coreos-ostree-importer-wrapper /usr/local/bin/

# Call the wrapper
CMD ["/usr/local/bin/coreos-ostree-importer-wrapper"]
