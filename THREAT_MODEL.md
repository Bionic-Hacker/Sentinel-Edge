# Threat model

SentinelEdge's threat model is [docs/threat-model.md](docs/threat-model.md) (v0.14): STRIDE per
trust boundary, 100 threats, each linked to its controls in
[docs/security-controls.md](docs/security-controls.md). It is loaded into the application as
SentinelEdge's own model, read-only, and a test keeps the two identical. The assessment of how
it holds is [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md).
