# rev4upgrade

**NIST RMF SP 800-53 Rev 4 → Rev 5 OSCAL SSP Migration Pipeline**  
*For Cybersecurity Auditors, Assessors, and eMASS Operators*

This repository provides a production-grade, auditable Python pipeline that converts an eMASS-exported OSCAL Rev 4 System Security Plan (SSP) into a validated OSCAL Rev 5 SSP JSON payload. It injects custom Secure Configuration LockDown Module (SCLM) tracking properties while preserving full auditability and deterministic UUIDs for safe iterative imports into eMASS.

## DAAG Transition Strategy

Full strategy, architecture, narrative contract, and validation gates live under:

**[docs/daag-transition/](docs/daag-transition/)**

Key principles:

- Every Rev 5 narrative is traceable to its Rev 4 source (or an explicit new-control decision).
- SCLM values remain `NOT-CONFIGURED` / `review-required` until ISSM/ISSO/SCA populate verified evidence.
- No unverified repository URLs are embedded.
- Output is a **draft** until the synchronization rule and review gates complete.
- **Never invent classified content. Never claim ATO.**

See also: [Architecture](docs/daag-transition/architecture.md) · [Narrative Engine](docs/daag-transition/narrative-engine.md) · [Validation Checklist](docs/daag-transition/validation-checklist.md)

## Role & Objective

You are a **NIST RMF SP 800-53 Cybersecurity Auditor** specializing in OSCAL-based migrations. Your goal is to transform an eMASS-exported OSCAL Rev 4 SSP into a validated OSCAL Rev 5 SSP JSON payload while injecting organization-specific SCLM tracking properties under the DAAG transition strategy.

### Execution Pipeline Requirements

1. **Environment Setup** – Python 3 + `requests`
2. **Input Ingestion** – `source_rev4_ssp.json` + conversion matrix + SCLM map
3. **Transform Engine Rules**
   - `one-to-one`: Direct narrative copy + SCLM properties
   - `split`: Duplicate base narrative across all child controls; append GFM provenance markers
   - `merge`: Concatenate source narratives with clear separators
   - `withdrawn`: Omit from output; record in audit log only
4. **Reproducibility (Idempotency)** – UUID v5 only inside `implemented-requirements`
5. **Error Management** – Dual-channel logging + execution statistics

### Deliverables

- Structural OSCAL Rev 5 JSON aligned with NIST schema (draft)
- Transparent `migration_audit.log` with processed / split / merged / withdrawn / error counts

## Quick Start

```bash
git clone https://github.com/dadsocstl/rev4upgrade.git
cd rev4upgrade
pip install -r requirements.txt
python oscal_migration_pipeline.py
```

Outputs:
- `OSCAL_SSP_Rev5_YYYYMMDD.json` – draft ready for schema validation and review gates
- `migration_audit.log` – full decision trail

## Unit Tests (100% Accuracy Target)

```bash
python -m unittest tests.test_oscal_migration -v
```

17 tests covering UUID determinism, one-to-one / split / merge / withdrawn, SCLM fallbacks, eMASS schema integrity, and edge cases. All currently pass.

## Conversion Matrix Patterns

| Rev 4 Pattern       | Rev 5 Structural Shift          | Data Matrix Action                                      | SCLM Integration Strategy                          |
|---------------------|---------------------------------|---------------------------------------------------------|----------------------------------------------------|
| 1-to-1 Match        | Direct carry-over (e.g. cm-2)   | Copy narrative string                                   | Placeholder until verified                         |
| 1-to-Many Split     | Control divided into subsets    | Duplicate base narrative; append provenance markers     | Distinct placeholders per child                    |
| Many-to-1 Merge     | Consolidations                  | Concat narratives with separators                       | Single placeholder on target                       |
| Withdrawn / Omitted | Control removed or integrated   | Record in audit log only                                | Flag associated script as deprecated               |

Authoritative map: [`config/migration-sclm-map.json`](config/migration-sclm-map.json) (SCLM set to `NOT-CONFIGURED` / `review-required`).

## Schema Integrity Rules (eMASS)

- Property names in `props` must be lower-case (`sclm-module-id`, etc.)
- Every `implemented-requirement` must have a **unique deterministic UUID**
- Control IDs must be lowercase with standard parentheses: `ac-2(1)`
- Never invent classified content or claim ATO

## File Layout

```
rev4upgrade/
├── oscal_migration_pipeline.py
├── requirements.txt
├── config/
│   ├── migration-sclm-map.json   # DAAG-aligned matrix + safe SCLM placeholders
│   ├── rev4_rev5_map.json
│   └── sclm_library.json
├── docs/daag-transition/       # Strategy, architecture, narrative engine, checklist
├── samples/
│   └── source_rev4_ssp.json
├── tests/
│   └── test_oscal_migration.py
└── README.md
```

## Scope Boundary

This repository covers **narrative migration and its supporting traceability**. It does not replace the authoritative NIST catalog, DCSA transition instructions, eMASS import validation, or an Authorizing Official decision. A generated narrative remains a draft until the ISSM/ISSO, system owner, assessor, and AO-authorized process approve it.

---
*Aligned with NIST SP 800-53 Rev 5, OSCAL 1.1.x, DAAG transition strategy, and eMASS import expectations. Never claims Authorization to Operate.*
