# The corpus is compiled into the image rather than fetched at runtime, so nothing the worker cites
# can change under it and no egress to GitHub is opened. corpusc reads both trees and fails the
# build on a malformed entry, an id collision, an unresolved citation or a pairing with no reason.
#
# The build context holds both checkouts, because k8-lab builds this from a pinned ai-k8s commit:
#   docker buildx build --platform linux/amd64,linux/arm64 -f ai-k8s/Dockerfile .
#
# BUILDPLATFORM keeps the compiler native and cross-compiles for the target, because the nodes are
# amd64 and a workstation here is arm64.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build

ARG AGENT_DIR=ai-k8s
ARG KLAB_DIR=k8-lab
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY ${AGENT_DIR}/go.mod ${AGENT_DIR}/go.sum ./
RUN go mod download

COPY ${AGENT_DIR}/ ./
RUN go vet ./... && go test ./...

# corpusc runs on the build platform, so it stays native and is not cross-compiled.
RUN go build -o /out/corpusc ./cmd/corpusc
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/triage-worker ./cmd/triage-worker

# Only the three files the corpus reads, so an unrelated change in k8-lab does not bust this layer.
COPY ${KLAB_DIR}/.checkov.baseline /klab/.checkov.baseline
COPY ${KLAB_DIR}/decisions.md /klab/decisions.md
COPY ${KLAB_DIR}/reference/threat-model.md /klab/reference/threat-model.md
RUN /out/corpusc -k8-lab /klab -corpus corpus -out /out/corpus.json

FROM gcr.io/distroless/static-debian12:nonroot

# Stamped by the build, recorded with every verdict, so a verdict names the tree it came from.
ARG AGENT_COMMIT=unknown
ARG CORPUS_COMMIT=unknown
ENV AGENT_COMMIT=${AGENT_COMMIT} CORPUS_COMMIT=${CORPUS_COMMIT}

COPY --from=build /out/triage-worker /triage-worker
COPY --from=build /out/corpus.json /corpus/corpus.json

USER nonroot:nonroot
ENTRYPOINT ["/triage-worker"]
