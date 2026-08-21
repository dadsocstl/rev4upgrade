# Validation Checklist – DAAG Rev 4 → Rev 5 Narrative Migration

## Content Gates

- [ ] Every Rev 5 narrative contains migration strategy and legacy source markers
- [ ] No unverified SCLM repository URLs embedded
- [ ] ODPs treated as candidates until approved
- [ ] Container-specific values replaced or explicitly justified for target system
- [ ] Legacy Implemented/Planned/Compensated/N/A statuses not auto-carried forward as Rev 5 assertions
- [ ] Withdrawn controls appear only in audit log, not in implemented-requirements

## OSCAL Gates

- [ ] Deterministic UUID v5 on every implemented-requirement
- [ ] Lowercase prop names (`sclm-module-id`, etc.)
- [ ] Control IDs lowercase with parentheses form
- [ ] Generated artifact validates against the local OSCAL component or SSP schema
- [ ] No duplicate UUIDs or duplicate control-id entries for the same target

## eMASS Gates

- [ ] Import of the draft does not create duplicate requirement records (idempotency test)
- [ ] Custom props parse correctly under eMASS validation rules
- [ ] Envelope metadata does not claim ATO or authorization status

## Assessor / Process Gates

- [ ] Approved Rev 5 catalog and profile version recorded
- [ ] Approved baseline and DCSA/NSS overlay applicability decision recorded
- [ ] Each ODP value reviewed by ISSM / control owner / System Owner
- [ ] Evidence/artifact locations and owners identified
- [ ] Synchronization rule completed before any production generation
- [ ] Package retains merge report, mapping register, ODP approvals, and review decisions

## Unit / Automated Gates

- [ ] `python -m unittest tests.test_oscal_migration -v` passes (17 tests)
- [ ] Migration statistics logged (processed / split / merged / withdrawn / errors)
- [ ] Schema validation of generated component definition or SSP passes
