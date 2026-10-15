FROM alpine:3.19

RUN apk update && apk add --no-cache \
    suricata \
    iptables \
    iproute2 \
    tcpdump \
    bash \
    curl \
    python3 \
    py3-pip \
    jq

RUN mkdir -p /var/log/suricata /etc/suricata/custom-rules /etc/suricata/rules

COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/custom-rules/local.rules
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /var/log/suricata

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
