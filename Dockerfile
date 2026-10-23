# syntax=docker/dockerfile:1.7
# One image for the control plane and the runner. Build from this repo with the
# web and modules repos as named contexts (docker-compose.yml does this):
#   docker build --build-context web=../cloud-pravaha-web --build-context catalog=../cloud-pravaha-modules/catalog -t cloud-pravaha .
ARG TOFU_VERSION=1.13.2

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=0.1.0" -o /out/pravaha ./cmd/pravaha \
 && mkdir -p /out/certs /out/work

FROM node:20-alpine AS webbuild
WORKDIR /web
COPY --from=web package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY --from=web . .
RUN npm run build

FROM ghcr.io/opentofu/opentofu:${TOFU_VERSION}-minimal AS tofu

# Control plane: static, distroless, non-root (no shell, no package manager).
FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build /out/pravaha /usr/local/bin/pravaha
COPY --from=webbuild /web/dist /srv/web
COPY --from=catalog . /srv/catalog
# Owned by nonroot so named volumes mounted here start out writable by the service.
COPY --from=build --chown=65532:65532 /out/certs /certs
ENV PRAVAHA_WEB_DIR=/srv/web \
    PRAVAHA_CATALOG_DIR=/srv/catalog
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pravaha"]
CMD ["central"]

# Runner: OpenTofu downloads registry modules from their git sources (pinned to a
# commit by the registry), so this image adds git and CA certificates, nothing else.
FROM alpine:3.22 AS runner
RUN apk add --no-cache git ca-certificates \
 && adduser -D -H -u 65532 nonroot
COPY --from=build /out/pravaha /usr/local/bin/pravaha
COPY --from=tofu /usr/local/bin/tofu /usr/local/bin/tofu
COPY --from=catalog . /srv/catalog
ENV PRAVAHA_CATALOG_DIR=/srv/catalog \
    PRAVAHA_TOFU_PATH=/usr/local/bin/tofu \
    PRAVAHA_WORK_DIR=/tmp/pravaha
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/pravaha"]
CMD ["runner"]
