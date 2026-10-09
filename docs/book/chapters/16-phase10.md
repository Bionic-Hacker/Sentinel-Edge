# Phase 10 — Threat Modeling and Governance

<p class="lead">Until Phase 10 the threat model and the control catalogue were documents, reviewed every phase but disconnected from the running platform. Phase 10 loads them into the application without creating a second, unreviewed copy. It adds threat models for other applications, an explainable posture score, and the two decisions that carry most of a programme's risk: accepting a weakness for a while, and changing a control. Whoever asks cannot approve. Released as v0.6.0.</p>

## Milestones

| Milestone | Delivered |
|---|---|
| M1 | The catalogue as code: threat model and controls parsed from the reviewed documents, shipped as JSON, loaded once into the database; SentinelEdge's own model read-only in the app; application models (STRIDE, PASTA) |
| M2 | Security exceptions and change requests with separation of duties in the service and the database; EXC-0001 and EXC-0002 migrated; the scan gate's register generated from the application |
| M3 | The explainable posture score with daily snapshots; the Threat Modeling and Compliance pages; eight smoke checks; then, at the owner's request, archive and permanent deletion of threat models |
| M4 | ADR-0022 and ADR-0023, threat model v0.6, the governance runbook, Edition 4 of this book, v0.6.0 |

## The catalogue is code

SentinelEdge's threat model is reviewed in pull requests with the code it describes. Editing it in a web form would create a second version that nobody reviewed. So the documents stay the source, and the application reads them (ADR-0022).

{{figure:governance|From reviewed documents to the application. The parser runs at development time; CI refuses a catalogue that differs from the documents. The API loads a new catalogue once, on the first request that needs it.|72}}

`app/governance/catalogue_source.py` parses both documents:

- **`docs/threat-model.md`:** assets, trust boundaries, data flows, every threat table (each with a *Control IDs* column), the attack paths and the residual risks.
- **`docs/security-controls.md`:** the implemented controls, by phase section, the planned controls, and the requirement → threat → control → evidence matrix.

`make governance-catalogue` writes `app/governance/catalogue.json`, which ships inside the API image.

Three tests keep the documents, the JSON and the application from disagreeing:

- **The shipped JSON must be exactly what the documents produce now.** Edit a document without regenerating, and CI fails.
- **Every threat names at least one control**, and every requirement and attack path names threats that exist.
- **Every piece of cited evidence must exist.** A test name, test file or `make` target written in a document is looked up in the repository, so renaming a test without updating the document fails the build. A control's status must also match its phase: *implemented* only in a completed phase, *planned* only in a future one.

:::why Why a drift test instead of a database editor
A control catalogue is only useful if it is true. The cheapest way to keep it true is to make lying about it fail the build: a claimed control must cite evidence that exists, and the application must show exactly what the reviewed document says.
:::

The first governance request after a new catalogue arrives loads it, under a PostgreSQL advisory lock so concurrent requests load it once. Controls and requirements are upserted by reference. One dropped from the documents is retired, never deleted, so old links stay readable. Every load is audited with the catalogue's digest. SentinelEdge's own model then appears in the application with origin *catalogue*, and any attempt to edit it gets 409 `maintained_as_code`.

:::lesson Markdown leaked into the application
The first screenshots showed backticks around file names in control text. The parser must keep the backticks long enough to find the evidence (they mark what to verify), then strip them for display. It now reads evidence from the raw cell and the text from a cleaned copy.
:::

## Threat models for other applications

Other applications have no reviewed documents here, so their models are built in the application, by leads (admins and security engineers).

- **Methods:** STRIDE, or PASTA, which records its seven stages.
- **Elements:** assets, trust boundaries, data flows, attack paths and residual risks.
- **Threats:** a threat must cite real controls from the catalogue and boundaries of its own model.
- **Retiring, not deleting:** elements are retired, never deleted, so a threat that cites one stays readable.
- **Every change:** carries the model's version (a stale write gets 409) and is audited.
- **Access:** developers read the models of applications they own; any other ID answers 404, and the attempt is audited.

### Removing a model

Midway through M3 the owner asked to be able to delete a threat model, with a choice when pressing Delete: archive for most roles, permanent deletion for admins and security engineers. "Archive for all roles" collided with a Phase 8 decision: the VIEWER role must stay read-only, because the authenticated DAST scanner signs in as a viewer and attacks every write endpoint it can reach (T-VM-06). The owner chose to extend archiving to developers on their own applications instead.

| Role | Archive | Delete permanently |
|---|---|---|
| Admin, security engineer | ✓ | ✓ |
| Developer | Own applications | |
| Analyst, viewer | | |

Archive keeps the model, marks it out of use, and hides it from the list unless *Show archived models* is ticked. Permanent deletion needs migration 0013, which grants DELETE on the three model tables. The audit record keeps a summary of what was removed: name, application, method, status, counts and the first 50 threats. SentinelEdge's own model can be neither archived nor deleted. The dialog that offers the choice is an `alertdialog` with focus on *Cancel*. Escape and a click outside cancel it, and only the buttons the server allows appear.

## The posture score

The spec asks for a posture score that is explainable. The score has 11 categories, from identity to governance, and every control family belongs to exactly one of them. A unit test enforces this, so a new family cannot silently drop out of the score.

A category starts at its **coverage**: the share of its catalogue controls that are implemented. Then it **loses points for live signals**, and each deduction lists the records behind it:

| Category | Deduction |
|---|---|
| Vulnerability management | Each active finding past its SLA: critical 10, high 5, medium 2 |
| Monitoring and response | Each open live incident: critical 10, high 5 |
| Governance | Each approved high or critical exception in force: 5; each request waiting more than seven days: 2 |
| DevSecOps | The last imported scan failed the gate: 10; no scan ever imported: 5 |

A category whose controls are all planned scores 0 and says *planned*. The overall score is the mean of every category, so the AWS and AI phases still to come pull it down. `built_scope` is the mean of the measured categories only. Both are shown, so the roadmap is visible without hiding how much of it is not built yet.

:::why No AI, no hidden weights
A score nobody can trace cannot be argued with, so it cannot be trusted. The method is the module docstring of `app/services/posture.py`, returned by the API with every score and shown on the page. Every point can be checked by opening the records the page names.
:::

Snapshots are stored insert-only in `posture_snapshots`: one on the first read of each day, and one whenever a lead asks. The Compliance page plots them as a trend.

## Exceptions and change management

{{figure:exceptions|The exception lifecycle. Approval is by a lead other than the requester. Expiry happens on the date during the next read or write, with no scheduler. Approved scan-finding exceptions become the scan gate's register.|100}}

**Whoever asks cannot approve** (ADR-0023). The service refuses self-approval with 409 `separation_of_duties`. The response tells the UI, so the page explains why there is no *Approve* button rather than hiding it silently. A database CHECK (`approver_id <> requester_id`) refuses it again, so a bug in the service cannot approve anything.

**Exceptions (EXC-n)** are requested by leads, or by developers for their own applications. Each one carries:

- the scope: dependency, scan finding, control, configuration or other;
- the risk level, justification, compensating control and exit criteria;
- an expiry no later than the risk allows: critical 30 days, high 90, medium 180, low 365.

The requester may withdraw before the decision, with a reason. An approved exception expires on its date, or is closed early with a reason once the issue is fixed. The two exceptions in the old Markdown register were migrated by migration 0011, not retyped.

**Change requests (CHG-n)** follow these rules:

- **Submitting:** a request carries a rollback plan and a validation plan.
- **Deciding:** another lead approves or rejects it.
- **Implementing:** the requester or a lead implements it, with a reference such as a pull request.
- **Finishing:** a lead validates it, or the requester or a lead rolls it back.
- **Reasons:** rejection, cancellation, validation and rollback each need a reason.
- **WAF changes:** a `waf_rule` change, allowed only on SentinelEdge itself, drives the **simulated** WAF from Phase 7. Implementing it switches the rule's mode, and rolling back restores the previous one. Real WAF rules will still change only through reviewed Terraform (ADR-0008).

**Decisions are final.** Database triggers refuse a rewritten decision and the revival of a rejected, withdrawn or cancelled record, and the application role holds no DELETE on either table. Each record's history is read from the hash-chained audit log, where every step is written in the same transaction as the step itself.

### The application is the system of record

Phase 8 left accepted risks in two places: the scan gate's TOML file and the in-application acceptances. Approved **scan-finding exceptions** are now exported to `scanning/accepted-findings.toml` by `make accepted-risks`. The file says at the top that it is generated, and an expired exception stops covering its finding at the next export.

:::lesson Seeded rows shift every reference
Migration 0011 seeds EXC-0001 and EXC-0002, so the first exception a test creates is EXC-0003, unless another test ran first. Tests that assumed a reference number failed in a different order. Tests now use the reference the API returns, and today's date from the application's clock.
:::

## The frontend

Two pages arrived in M3:

- **Threat Modeling** lists the models with their threat counts and highest open risk. A model's page shows its stats, elements, threats with their controls, and, for PASTA, the stages.
- **Compliance** has five tabs:
    - posture, by category with its factors, the method and the trend;
    - controls, filterable by family and linked from the posture page;
    - requirements;
    - exceptions;
    - changes.

Detail pages show each exception and change with its permissions and history. Everything people typed (threats, justifications, rollback plans) is rendered as text, under the strict CSP (T-GOV-09).

:::lesson A bundle over 500 kB
With the governance pages the SPA's single chunk passed 500 kB. React and the router now build into their own chunk (rolldown `advancedChunks`), which leaves about 280 kB for the application.
:::

## Verified

:::evidence Phase 10 at release
- **Tests:** 892 backend tests (98.3% coverage) against real PostgreSQL and 103 frontend tests.
- **Smoke:** `make smoke` runs 64 checks, including:
    - the catalogue loaded from the documents;
    - SentinelEdge's model refusing an edit;
    - the posture score explaining all 11 categories;
    - an exception and a change request each refused for self-approval, then withdrawn or cancelled;
    - a viewer refused an exception request.
- **Threat model v0.6:** nine new threats (T-GOV-01 to T-GOV-09) and two new assets (A14, A15). Controls C-GOV-03 and C-GOV-06 to C-GOV-10 are new, and C-GOV-04, C-API-01 and C-API-13 are extended.
- **Browser:** every new page and the remove dialog checked in headless Chromium at 1440 and 390 px wide.
:::
