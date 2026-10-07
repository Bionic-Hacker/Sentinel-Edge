# Security automation tools (Phase 11)

Planned Python CLI tools, each calling the SentinelEdge REST API with a scoped token:

```
python tools/security_report.py        # downloadable security assessment
python tools/certificate_inventory.py  # certificate status and expiry
python tools/api_inventory.py          # endpoint inventory with OWASP API mapping
python tools/waf_event_analysis.py     # WAF event summaries
python tools/vulnerability_report.py   # findings by severity, SLA status
python tools/posture_score.py          # explainable posture score with evidence
python tools/verify_audit_chain.py     # audit log hash-chain verification (Phase 2)
```

None exist yet.
