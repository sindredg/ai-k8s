# Decisions

## Agents

### Agent namespace

Decision: A namespace of its own, `agents`, with its own quota, limit range and network policies.

Why: The trust levels differ.

Cost: A second set of platform manifests.

### Agent permission boundary

Decision: The triage worker holds four grants and nothing else.

Why: This is the one identity that parses attacker-influenced strings.

### Deferred decision records

These are gates rather than decisions, so this section carries no Decision line.

## Project and process

### Project focus

Decision: Platform engineering on Kubernetes.
