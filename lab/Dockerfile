FROM alpine:3.22

RUN apk add --no-cache openvpn openssl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1194/tcp 1194/udp
ENTRYPOINT ["/entrypoint.sh"]
