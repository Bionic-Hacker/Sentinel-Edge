## Change

## Security checklist
- [ ] No secrets, credentials, or real personal data added
- [ ] Authorization enforced server-side for any new endpoint
- [ ] Input and output validated with Pydantic models
- [ ] New capability registered in `backend/app/core/capabilities.py` with correct provenance
- [ ] Simulated functionality is labelled as simulated in UI and docs
- [ ] Threat model / control matrix updated if the attack surface changed
- [ ] Tests added, including negative (security) cases
