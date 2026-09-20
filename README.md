# ai-k8s

Agents that operate the [k8-lab](https://github.com/sindredg/k8-lab) platform. This repository holds
the agent source. The platform, the identities, the Terraform, the manifests and all evidence stay in
`k8-lab`, which builds this from a pinned commit under its own identity. Nothing here holds a Google
Cloud credential.

## What is here

| Component | Runs | Does |
| --- | --- | --- |
| `cmd/corpusc` | At image build time | Compiles the corpus into one index, and fails the build on a bad entry |
| `cmd/triage-worker` | One replica in the `agents` namespace | Pulls Security Command Center findings, settles them, records and notifies |

Phase 15 Increment 1 is deterministic. It calls no model, so the whole path is proven before a token
is spent. Increment 2 adds the Vertex AI call for what the rules could not settle.

## The verdict contract

Four values, and the worker separates them rather than the model.

| Verdict | Condition | Citations |
| --- | --- | --- |
| `accepted` | Resolution matched a corpus entry, and that entry prices this finding | One or more that resolve |
| `contradicts_decision` | Resolution matched, and the decision does not hold for the named resource | One or more that resolve |
| `new` | Resolution found no applicable entry, and the finding is complete | None. `corpus_match: none` is recorded explicitly |
| `insufficient_evidence` | The worker refused to rule | Optional. The record lists what is missing |

Schema validation enforces that table. It rejects `accepted` or `contradicts_decision` with no
resolved citation, rejects `new` when resolution returned a match, and rejects
`insufficient_evidence` with an empty missing-evidence list. Increment 1 never returns
`contradicts_decision`: deterministic resolution can establish that a decision covers a resource,
never that it fails to hold.

The spelling is a cross-repository contract. `terraform/modules/observability/triage.tf` alerts on
`jsonPayload.verdict != "accepted"`, so any other spelling of `accepted` pages the platform owner.

## The corpus

Five sources, compiled into one index at build time and baked into the image. The worker never reads
a corpus source at runtime, so nothing it cites can change under it and no egress to GitHub is opened.

| Source | Lives in | Becomes |
| --- | --- | --- |
| `.checkov.baseline` | k8-lab | `checkov:<check>:<address>` |
| `reference/threat-model.md` findings table | k8-lab | `threat:<n>` |
| `decisions.md` headings carrying a `Decision:` line | k8-lab | `decision:<anchor>` |
| `corpus/controls.yaml` | here | `control:<slug>` |
| `corpus/mapping.yaml` | here | The category pairings, which cite the four above |

A citation is one of those ids and nothing else, and resolution is an exact lookup. Name-based
pairing produced two wrong matches while this phase was drafted, and doubled the reported overlap.
Resolving the citation catches that without asking anything to be right.

Resolution matches **category and resource together**. An accepted decision about one cluster does
not cover another cluster of the same kind.

```bash
go run ./cmd/corpusc -k8-lab ../k8-lab -corpus corpus -out corpus.json
```

## The ledger

One object per finding state, under one prefix per key, every write create-only. Nothing is
overwritten, which is what lets the worker hold no delete permission on the bucket.

The key is the finding's **canonical name**, its event time and its state. A finding carries three
names and they are not interchangeable: it is read at organization scope and written at project
scope. The canonical name is the key because the project number is immutable.

| State | Written | On redelivery |
| --- | --- | --- |
| `received` | First, before anything else | The create fails. Resume from the furthest state present |
| `classified` | After the verdict validates, before any notification | Resume at `notification_attempted` |
| `notification_attempted` | Before the log entry is emitted | Notify again. The state means one may or may not have gone out |
| `acknowledged` | After the Pub/Sub acknowledgement returns | Nothing to do. Drop the message |

Record before notifying, notify before acknowledging. A crash between inference and persistence
re-infers, which costs a fraction of a cent. A crash between persistence and notification re-notifies
without paying for inference again. Duplicate email is accepted; a missed notification is not.

## Running it

The worker refuses to start without the six environment variables that identify the Pod. A missing
one produces a monitored resource the alert policy does not match, and that failure is silent.

| Variable | Why |
| --- | --- |
| `PROJECT_ID`, `CLUSTER_NAME`, `CLUSTER_LOCATION` | Labels on the `k8s_container` monitored resource |
| `POD_NAMESPACE`, `POD_NAME`, `CONTAINER_NAME` | The rest of those labels, from the downward API |
| `AGENT_COMMIT`, `CORPUS_COMMIT`, `IMAGE_DIGEST` | Provenance recorded with every verdict |

```bash
triage-worker -subscription scc-triage -ledger-bucket k8-lab-verdicts-<project> -corpus /corpus/corpus.json
```

It serves two probe paths on `:8080` and nothing else. The worker handles no traffic, so without
them a wedged pull loop is invisible: the process stays up and triages nothing.

| Path | Answers |
| --- | --- |
| `/readyz` | 200 once the pull loop is running. Not ready while the three clients open |
| `/healthz` | 200 unless `-idle-limit` (24h) passes with no message. True throughout startup, so liveness never kills a Pod that is merely slow to start |

An idle subscription is the normal state, which is why the budget is a day rather than minutes.

## Scope

The worker triages everything except `VULNERABILITY`, which covers misconfiguration, external
exposure and threat, and any class Google adds later. The vulnerability volume is counted and
acknowledged rather than dropped silently: it was 653 findings against 15 of everything else.

## Building

```bash
docker buildx build --platform linux/amd64,linux/arm64 -f ai-k8s/Dockerfile .
```

The build context holds both checkouts, because `k8-lab` builds this from a pinned commit. The nodes
are amd64, so an image built only for the workstation's architecture fails to pull.
