FROM python:3.11-alpine

RUN apk update && apk add --no-cache bash iproute2 curl

WORKDIR /app

COPY internal_server.py /app/internal_server.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 5000 22

ENTRYPOINT ["/app/entrypoint.sh"]
