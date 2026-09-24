# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/JustSparx/SIPBXGO/internal/pbx.Version=${VERSION}" \
      -o /out/sipbxgo ./cmd/sipbxgo \
 && mkdir -p /out/data

# ---- runtime ----
# distroless/static: no shell, no package manager, runs as non-root (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sipbxgo /usr/local/bin/sipbxgo
COPY --from=build --chown=65532:65532 /out/data /data
ENV SIPBX_DATA_DIR=/data
VOLUME ["/data"]
# SIP (UDP+TCP). RTP ports will be added with media support.
EXPOSE 5060/udp 5060/tcp
ENTRYPOINT ["sipbxgo"]
CMD ["serve"]
