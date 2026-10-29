# ─── EndoriumFort — File share service image ─────────────────────────────
# Separate from the bastion image on purpose: its own container, volume and
# (in compose) an internal-only network. Static binary on distroless, non-root,
# read-only root filesystem friendly — /data is the only writable path.
#
# Build: docker build -t endoriumfort-files fileshare/

# Cross-compiled on the build host: multi-arch images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-trixie AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/endoriumfort-files . \
  && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/endoriumfort-files /endoriumfort-files
# Owned by the nonroot user (65532) so a fresh named volume is writable.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV EF_FS_LISTEN=:8090 \
    EF_FS_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/endoriumfort-files", "healthcheck"]
ENTRYPOINT ["/endoriumfort-files"]
