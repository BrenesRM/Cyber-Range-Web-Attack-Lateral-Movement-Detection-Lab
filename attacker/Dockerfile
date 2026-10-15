FROM alpine:3.19

RUN apk update && apk add --no-cache \
    bash \
    curl \
    nmap \
    python3 \
    py3-pip \
    iproute2 \
    bind-tools \
    netcat-openbsd \
    jq \
    git \
    openssh-client \
    tcpdump

# Install sqlmap lightweight or alias
RUN apk add --no-cache sqlmap || true

WORKDIR /workspace

CMD ["/bin/bash"]
