FROM nutsfoundation/nuts-node:master

# install and configure node-exporter
RUN apk update && apk add --no-cache prometheus-node-exporter openrc
RUN rc-update add node-exporter default \
  && mkdir -p /run/openrc \
  && touch /run/openrc/softlevel # Workaround for the Error Message
COPY node-exporter.conf /etc/conf.d/node-exporter

# add script that starts node-exporter
COPY entrypoint.sh /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:8081/status || exit 1

EXPOSE 8080 8081 5555 9100

ENTRYPOINT ["entrypoint.sh"]
CMD ["/usr/bin/nuts", "server"]