FROM quay.io/coreos-assembler/coreos-assembler:master

RUN dnf -y install git python3-toml python3-aiohttp && dnf clean all

COPY main /usr/lib/config-bot/main
COPY config.toml /etc/config-bot.toml

CMD /usr/lib/config-bot/main
