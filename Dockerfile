FROM golang:1.15-alpine AS builder
# hadolint ignore=DL3020
ADD . /go/src/starwind-exporter
WORKDIR /go/src/starwind-exporter
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o starwind-exporter .

# hadolint ignore=DL3007
FROM prom/busybox:latest

COPY --from=builder  /go/src/starwind-exporter/starwind-exporter /bin/starwind-exporter
COPY starwind-exporter.yml       /etc/starwind-exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/starwind-exporter" ]
CMD         [ "--config.file=/etc/starwind-exporter/config.yml" ]
