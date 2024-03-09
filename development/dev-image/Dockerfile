FROM nutsfoundation/nuts-node:master as nutsnode
FROM node:21-alpine

RUN npm install -g localtunnel

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

COPY --from=nutsnode /usr/bin/nuts /usr/bin/nuts
RUN chmod +x /usr/bin/nuts

HEALTHCHECK --start-period=30s --timeout=5s --interval=10s \
    CMD curl -f http://localhost:1323/status || exit 1

EXPOSE 1323 5555
ENTRYPOINT ["/entrypoint.sh"]
