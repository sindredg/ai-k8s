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
| `cmd/triage-eval` | From a workstation, and rules-only in CI | Scores the worker's decisions on a reviewed set of findings |

The rules run first. Vertex AI is asked only about a complete finding the reviewed mapping left
unmatched, and it can return `new`, `contradicts_decision` or `insufficient_evidence`, never
`accepted`.

## Status

The triage worker runs in `k8-lab` at [`a2159a1`](https://github.com/sindredg/ai-k8s/tree/a2159a1)
with `gemini-2.5-flash`. The project closed on 2026-09-22. The other agents in the
[k8-lab plan](https://github.com/sindredg/k8-lab/blob/main/plan.md#status) were not built.

| Measured, `gemini-2.5-flash`, five runs per case | Rules alone | Rules plus the model |
| --- | --- | --- |
| Dev cases right on every run, of 18 | 14 | 16 |
| Holdout cases right on every run, of 7 | 5 | 7 |
| False contradictions, of 125 model-path runs | | 0, from 15 before contradictions had to land on a control |
| Unsupported citations | | 0 |
| Latency p95 per call | | about 2 seconds |
| Cost per call | | about 0.003 USD, estimated from tokens |

Still wrong on dev: a finding naming no workload is `new` where `insufficient_evidence` is right,
and a planted note naming a real corpus id turns `new` into `insufficient_evidence`. Evidence is in
[the Phase 15 worklog](https://github.com/sindredg/k8-lab/blob/main/worklog/phase-15-scc-triage.md#slice-14-a-contradiction-has-to-land-on-something),
and the raw results are in [`eval/results`](eval/results).

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
`insufficient_evidence` with an empty missing-evidence list. The rules never return
`contradicts_decision`: deterministic resolution can establish that a decision covers a resource,
never that it fails to hold. Only the model can, and only when a cited control applies to a
resource the finding names. A contradiction resting on a decision, a baseline entry, a threat, or a
control for something else lands as `insufficient_evidence`, naming what the model claimed. Before
that check the model raised 15 false contradictions in 125 evaluation runs, and after it none.

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
| `corpus/controls.yaml` | here | `control:<slug>`, with the resources each control applies to |
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

## Evaluation

`triage-eval` decides every case through `worker.Decide`, the function the worker calls, and scores
two systems: the rules alone, and the rules plus the model. It writes nothing to the ledger.

| File | Holds |
| --- | --- |
| `eval/findings.json` | Finding bodies. Real ones as delivered, and three written by hand |
| `eval/dev.json` | Cases used while developing the prompt |
| `eval/holdout.json` | Cases never used to change the prompt, the schema or the mapping |
| `eval/results/<set>.json` | The last committed run, with everything it depends on in its header |

Each case records the verdict it prefers, others that are defensible, and every corpus id a citation
may name. A citation outside that list is unsupported even when it resolves, and a right verdict that
stands on one scores as wrong. A case is `real`, `derived` (a real finding with named fields changed)
or `synthetic`, and says which.

| Measured | How |
| --- | --- |
| Right and preferred | Against the answer written before the run |
| Error direction | `silenced`, `missed_contradiction`, `overconfident`, `false_contradiction`, `needless_abstention`, `unsupported_citation` |
| Consistency | Each case asked `-repeats` times; a case whose verdict moves counts as inconsistent |
| Latency and cost | Per call, p50 and p95, and the token estimate the worker records |

```bash
go run ./cmd/triage-eval -set eval/dev.json -corpus corpus.json                       # rules alone
go run ./cmd/triage-eval -set eval/dev.json -corpus corpus.json -project <project> \
  -agent-commit "$(git rev-parse HEAD)" -out eval/results/dev.json                     # with the model
```

CI scores the rules alone and fails when a committed result is stale: when the instruction, the
schema, the parameters, the cases, the mapping or the controls moved since it ran. A change to the
half of the corpus that `k8-lab` contributes only warns, because this repository cannot stop that
edit and failing every unrelated pull request for it would teach people to ignore the check.

## Building

```bash
docker buildx build --platform linux/amd64,linux/arm64 -f ai-k8s/Dockerfile .
```

The build context holds both checkouts, because `k8-lab` builds this from a pinned commit. The nodes
are amd64, so an image built only for the workstation's architecture fails to pull.
