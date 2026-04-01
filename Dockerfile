# Rocket — Blue Team Log Analysis Toolkit
# Author: Hernan Herrera
# Website: https://rocket.sockets.ar
# License: Apache 2.0

FROM alpine:3.20 AS base
RUN apk --no-cache add ca-certificates

FROM scratch

LABEL maintainer="Hernan Herrera <hernannh@gmail.com>"
LABEL org.opencontainers.image.title="Rocket"
LABEL org.opencontainers.image.description="Blue Team Log Analysis Toolkit"
LABEL org.opencontainers.image.url="https://rocket.sockets.ar"
LABEL org.opencontainers.image.source="https://github.com/hernannh/rocket"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.authors="Hernan Herrera"

COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY bin/rocket-linux-amd64 /usr/local/bin/rocket

ENTRYPOINT ["rocket"]
