FROM registry.fedoraproject.org/fedora:41

# set PYTHONUNBUFFERED env var to non-empty string so that our
# output immediately comes to the console
ENV PYTHONUNBUFFERED=true

# Get any latest updates since last container spin
RUN dnf update -y

# Install ostree/dumb-init
RUN dnf -y install ostree dumb-init

# Configure a umask of 0002 which will allow for the group permissions
# to include write for newly created files. We need this because we'd
# like to access the OSTree repos from two different Kubernetes pods,
# which will have different UIDs but the same GID.
# See: https://pagure.io/releng/issue/8811#comment-616490
#
# This is also done within the fedora-ostree-pruner script,
# but we also want it done in the container because admins may run some
# ostree operations by hand from a bash prompt and we want those
# operations to not put the repo in a bad state.
RUN echo 'umask 0002' > /etc/profile.d/umask-for-openshift.sh

# Put the file into typical place for execuatables
ADD fedora-ostree-pruner /usr/local/bin/

# Use dumb-init (reaps defunct processes) to call the pruner
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/local/bin/fedora-ostree-pruner", "--loop"]
