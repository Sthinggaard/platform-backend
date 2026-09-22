# The Resilience Interpretation Boundary

*CA-05-ALIGN (#170). The line between what Initial Discovery **observes** and what a
person **decides**, and how that line is held.*

---

Status: active
Audience: engineers working on discovery, the Collector, or the resilience model
Enforced by: `apps/server/tests/test_resilience_interpretation_boundary.py`
Last updated: 2026-08-19

---

## Why this document exists

CA-05 Initial Discovery scans an organisation's estate and turns what it finds into
artefacts. The resilience model that consumes those artefacts is being upgraded
independently, and the risk that prompted this ticket is a quiet one: discovery
gradually starts *interpreting* what it finds, because at every individual step it looks
like a small convenience.

That would break the product's first rule — **the system never decides** — in the one
place where it is hardest to notice, because a scanner's output is easy to mistake for
fact.

So the boundary is stated here **and asserted in a test**. A document alone goes stale
the first time someone adds an import.

## What CA-05 does

Collects technical evidence, and normalises it into artefacts that later stages can
reconcile and map. Its entire model surface is technical:

| Concern | Models it reaches |
|---|---|
| The request and its approval | `discovery_run`, `discovery_scope_proposal` |
| Planning and execution | `discovery_execution` (plan, stage, provider execution, worker lease) |
| The Collector | `evidence_scanner`, `evidence_source`, `access_connector`, `connector_access_test` |
| What was found | `assets_runtime`, `artefact_relationships`, `artefact_reconciliation`, `artefact_access_lifecycle` |
| Provenance | `common` (`AuditEvent`), `tenant_org`, `tenant_identity`, `organization_identity` |

## What CA-05 does not do

Each row is an acceptance criterion of #170, and each is true for the same structural
reason: **discovery cannot reach the module that holds the judgement.**

| CA-05 does not determine | Held by |
|---|---|
| Business Service criticality | `value_streams` |
| Resilience Service designation | `value_streams` |
| Outcome Goals | `value_streams` |
| Impact Tolerance | `process_bia_assessment` |
| Business impact | `process_bia_assessment` |
| Risk appetite | `risk_appetite_policy`, `service_appetite_reassessment` |
| Resilience Capability | `risk_evaluation` |
| Decision status | `risk_evaluation` |
| Whether a Business Process is live | `process_activation` |
| What to recommend to a person | `business_process_recommendation` |

None of these is imported anywhere on the CA-05 path. That is checked, not asserted:
`test_discovery_never_imports_the_interpretation_layer` parses every module on the path
and fails on any import of the modules above.

## The evidence must stay usable — the boundary is not achieved by producing less

A boundary kept by gathering *less* would satisfy every "does not" above and destroy the
reason discovery exists. So the ninth criterion is separately guarded: a normalised
artefact keeps `canonical_identity_key` (what reconciliation matches on),
`lifecycle_state`, and `intent` (the observed evidence, including how the artefact was
named and why — CA-07.1).

## ⚠️ The one honest exception

`Asset.criticality` is `NOT NULL` with a default, so normalisation writes
`Criticality.MEDIUM` into every artefact it creates. **Discovery assessed nothing** — the
column demanded a value.

This is the single place where the boundary is upheld in intent and not in the data. A
reader querying an artefact straight out of discovery is told `MEDIUM` and cannot tell
that nobody decided it. That is the same failure mode CA-07.0 named and refused
elsewhere: *a decision nobody made must never read as one somebody did.*

It is recorded rather than glossed, and pinned by
`test_criticality_written_by_discovery_is_a_column_default_not_a_determination`, which
fails the moment that value starts varying with the evidence — because at that point
discovery has begun interpreting.

**The real fix is a schema change** — a nullable criticality, or an explicit
"not yet assessed" member — and it is not made here, because #170's own last criterion is
that no unnecessary CA-05 implementation change is introduced.

## When the boundary genuinely moves

It may. If a later epic decides discovery should carry some interpretation, the guard
test fails and that is the intended behaviour: update `_INTERPRETATION_MODULES`, this
document, and `TASKS.md` in one change, deliberately, rather than discovering afterwards
that the line moved on its own.
