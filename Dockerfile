# anvilkit-codegen: the trusted harness image of the codegen Job class (P09b),
# the fixed non-paid task of the profiles codegen-fixed-v1 and
# harness-wiring-dev-v1. Built from this repository alone (build context: its
# root); it links no contract module, so its bytes never depend on the
# profile that pins its own digest. The team image (anvilkit-codegen-team) is
# built by anvilkit-job-codegen-team from these sources as its named
# "supervisor" build context. The fixed candidate task, the protected
# fixtures and the explicit trusted resources are part of the image; the
# candidate UID (10001) exists as a passwd entry only.
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOPROXY=$GOPROXY
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/anvilkit-codegen-supervisor ./cmd/anvilkit-codegen-supervisor \
 && go build -trimpath -ldflags="-s -w" -o /out/anvilkit-codegen-candidate ./cmd/anvilkit-codegen-candidate

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN addgroup -g 10001 candidate && adduser -D -H -u 10001 -G candidate -s /sbin/nologin candidate \
 && mkdir -p /anvilkit/agent /anvilkit/fixtures /anvilkit/verdict /workspace /run/anvilkit /etc/anvilkit/anvilkit-codegen \
 && chmod 0700 /anvilkit/agent /anvilkit/fixtures /etc/anvilkit/anvilkit-codegen
COPY --from=build /out/anvilkit-codegen-supervisor /out/anvilkit-codegen-candidate /usr/local/bin/
COPY --chmod=0600 config.yaml /etc/anvilkit/anvilkit-codegen/config.yaml
COPY --chmod=0600 agent/resources.json /anvilkit/agent/resources.json
COPY --chmod=0600 fixtures/fixed-input.txt /anvilkit/fixtures/fixed-input.txt
ENV ANVILKIT_CODEGEN_CONFIG=/etc/anvilkit/anvilkit-codegen/config.yaml
# The supervisor starts as UID 0 in its container; the Job template grants
# it SETUID, SETGID and SETPCAP only, and it drops to 10001 for the candidate.
USER 0:0
ENTRYPOINT ["/usr/local/bin/anvilkit-codegen-supervisor"]
