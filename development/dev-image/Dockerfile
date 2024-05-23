FROM nutsfoundation/nuts-node:master as nutsnode
FROM debian:buster-slim

RUN apt-get update && apt-get install -y curl sudo musl
RUN curl -sL https://aka.ms/DevTunnelCliInstall | bash

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

COPY --from=nutsnode /usr/bin/nuts /usr/bin/nuts
RUN chmod +x /usr/bin/nuts

HEALTHCHECK --start-period=60s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:8081/status || exit 1

WORKDIR /nuts

EXPOSE 8080 8081 5555
ENTRYPOINT ["/entrypoint.sh"]
