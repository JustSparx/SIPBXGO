# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=1.0.0
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/JustSparx/SIPBXGO/internal/pbx.Version=${VERSION}" \
      -o /out/sipbxgo ./cmd/sipbxgo \
 && mkdir -p /out/data

# ---- runtime ----
# distroless/static: no shell, no package manager, runs as non-root (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="SIPBXGO"       org.opencontainers.image.description="Small self-hosted SIP PBX for extension-to-extension calling"       org.opencontainers.image.source="https://github.com/JustSparx/SIPBXGO"       org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/sipbxgo /usr/local/bin/sipbxgo
# License, attribution notice and third-party license texts travel with the image.
COPY --from=build /src/LICENSE /src/NOTICE /src/THIRD_PARTY_NOTICES /usr/share/doc/sipbxgo/
COPY --from=build --chown=65532:65532 /out/data /data
ENV SIPBX_DATA_DIR=/data
VOLUME ["/data"]
# SIP (UDP+TCP), SIP over TLS, the RTP media relay range, web UI.
EXPOSE 5060/udp 5060/tcp 5061/tcp 10000-10999/udp 8080/tcp
ENTRYPOINT ["sipbxgo"]
CMD ["serve"]
