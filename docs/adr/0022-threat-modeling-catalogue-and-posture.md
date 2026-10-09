# ADR-0022: Threat modeling, the control catalogue as code, and an explainable posture score

- **Status:** Accepted
- **Date:** 2026-10-08
- **Phase:** 10
- **Builds on:** ADR-0005 (audit log), ADR-0009 (provenance), ADR-0012 (backend layering),
  ADR-0015 (database roles), ADR-0021 (vulnerability management)

## Context
Until Phase 10 the threat model (`docs/threat-model.md`) and the control catalogue
(`docs/security-controls.md`) were documents. They were reviewed every phase, but nothing
connected them to the running platform: a reader could not ask SentinelEdge which threats a
control mitigates, which controls are still planned, or what the posture is today. The spec asks
for threat modeling with STRIDE and PASTA (§36), a control matrix that traces requirements to
threats, controls and evidence (§37), and a posture score (§40).

There are two kinds of model. SentinelEdge's own threat model is reviewed in pull requests with
the code it describes, so editing it in a web form would create a second, unreviewed version.
Models for other protected applications have no repository here, so they have to be built in
the application.

## Decision

**The catalogue is code.** `app/governance/catalogue_source.py` parses the two documents: assets,
trust boundaries, data flows, threats (with a "Control IDs" column), attack paths, residual
risks, controls (implemented ones per phase section, planned ones in one table) and the
requirement matrix. `make governance-catalogue` writes `app/governance/catalogue.json`, which ships
with the API. Three tests keep it honest:
* the shipped JSON must equal what the documents produce now (edit a document without
  regenerating, and CI fails);
* every threat names a control, and every requirement and attack path names known threats;
* every test, test file and `make` target cited as evidence must exist, and a control's status
  must match its phase (implemented only in completed phases).

**Loaded lazily, once.** The first governance request after a new catalogue arrives loads it
under a PostgreSQL advisory lock, so concurrent requests load it only once. Controls and
requirements are upserted by reference; one that leaves the documents is retired, never
deleted. Every load is audited with the catalogue's digest.

**SentinelEdge's model is read-only in the application** (origin `catalogue`, 409
`maintained_as_code`). It changes through a reviewed pull request to the documents.

**Application models** (origin `app`) are built in the application by leads (ADMIN,
SECURITY_ENGINEER), with STRIDE or PASTA (PASTA records its seven stages). Elements (assets,
boundaries, flows, attack paths, residual risks) are retired, never deleted, so threats that
cite them stay readable. A threat must cite real controls from the catalogue and boundaries of
its own model. Every change carries the model's version (a stale write gets 409) and is
audited. DEVELOPERs read the models of applications they own (other IDs answer 404, audited).
ANALYST and VIEWER read every model.

**Removing a model** (an owner request during the phase). Delete opens a dialog offering two
choices:
* **Archive**: ADMIN, SECURITY_ENGINEER, and DEVELOPERs on their own applications. The model is
  kept and hidden from the list by default.
* **Delete permanently**: leads only. Migration 0013 grants DELETE on the three model tables.
  The audit record keeps a summary of what was removed: name, application, method, status,
  counts and the first 50 threats.

ANALYST and VIEWER cannot remove anything. The VIEWER role must stay read-only because the
authenticated DAST scanner signs in as a VIEWER (T-VM-06). SentinelEdge's own model cannot be
archived or deleted.

**The posture score is arithmetic you can read.** It has 11 categories, and each catalogue
control family belongs to exactly one of them (a unit test checks this). A category's score
starts at its coverage, the share of its controls that are implemented. Points are then taken
off for live signals, and each deduction names the records behind it:
* findings past their SLA;
* open live incidents;
* high or critical exceptions in force;
* decisions waiting more than seven days;
* the last scan failing the gate, or no scan at all.

A category whose controls are all planned scores 0 and says "planned". The overall score is the
mean of all categories. `built_scope` is the mean of the categories that can be measured, so a
reader sees both how good the built part is and how much is left to build. The method is the
module docstring, returned with every score. No AI is involved and no weights are hidden.
Snapshots (`posture_snapshots`, insert-only) are taken on the first read of each day and on
demand by leads, and the page plots them as a trend.

## Alternatives considered
- **Edit SentinelEdge's model in the app and export it to Markdown.** Rejected: that would put
  the reviewed record in the database and the reviewed pull request second.
- **A weighted or machine-learned score.** Rejected: nobody can argue with a number they cannot
  trace. Coverage minus named deductions is cruder, but every point can be checked.
- **Hard delete only, or soft delete only.** The owner asked for both. Archive is the default
  for everyone who may change models, and permanent deletion is kept for leads because it
  cannot be undone.

## Incidents during the phase (kept as lessons)
1. **Python `None` in a JSONB column was stored as JSON `null`**, not SQL NULL, and the CHECK
   constraints that compare columns with NULL refused the rows. The columns now use
   `JSONB(none_as_null=True)`.
2. **Markdown leaked into the application.** Control text showed backticks from the documents.
   The parser now strips code markers after it has read the evidence from the raw cell, where
   the backticks mark what to verify.
3. **The SPA bundle passed 500 kB** once the governance pages arrived. Vite (rolldown) now puts
   React and the router in their own chunk, which brings the application chunk down to about 280 kB.

## Consequences
- `docs/threat-model.md` v0.6 has 80 threats and `docs/security-controls.md` has 101 controls;
  both appear in the application, linked to each other and to evidence.
- Editing either document means running `make governance-catalogue` and committing the JSON.
  CI fails otherwise.
- The score is low by design while AWS phases (3, 4, 5) and AI (9) are planned. `built_scope`
  is the number to watch until then.
