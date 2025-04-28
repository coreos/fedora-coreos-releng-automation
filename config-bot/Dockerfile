FROM registry.fedoraproject.org/fedora:42

RUN dnf -y install git python3-aiohttp && dnf clean all

COPY main /usr/lib/config-bot/main
COPY config.toml /etc/config-bot.toml

CMD /usr/lib/config-bot/main
