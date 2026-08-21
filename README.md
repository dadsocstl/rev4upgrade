# Rev 4 to Rev 5 Upgrade

**NIST RMF SP 800-53 Rev 4 → Rev 5 OSCAL SSP Migration Pipeline**  
*For Cybersecurity Auditors, Assessors, and eMASS Operators*

This repository provides a production-grade, auditable Python pipeline that converts an eMASS-exported OSCAL Rev 4 System Security Plan (SSP) into a validated OSCAL Rev 5 SSP JSON payload. It injects custom Secure Configuration LockDown Module (SCLM) tracking properties while preserving full auditability and deterministic UUIDs for safe iterative imports into eMASS.

## Why This Exists

NIST SP 800-53 Rev 5 introduced structural changes (control splits, consolidations, withdrawals). Manual migration of implementation narratives is error-prone and non-reproducible. This pipeline enforces a controlled conversion matrix so every auditor runs against the same approved mapping baseline.

## Role & Objective (Agent Instruction Summary)

You are a **NIST RMF SP 800-53 Cybersecurity Auditor** specializing in OSCAL-based migrations. Your goal is to transform an eMASS-exported OSCAL Rev 4 SSP into a validated OSCAL Rev 5 SSP JSON payload while injecting organization-specific SCLM tracking properties.

### Execution Pipeline Requirements

1. **Environment Setup** – Python 3 + `requests`
2. **Input Ingestion** – `source_rev4_ssp.json` + authoritative remote `rev4_rev5_map.json` + `sclm_library.json`
3. **Transform Engine Rules**
   - `one-to-one`: Direct narrative copy + SCLM properties
   - `split`: Duplicate base narrative across all child controls; append migration markers
   - `merge`: Concatenate source narratives with `---` separators
4. **Reproducibility (Idempotency)** – UUID v5 only (never v4) inside `implemented-requirements`
5. **Error Management** – Dual-channel logging + execution statistics

### Deliverables

- Structural OSCAL Rev 5 JSON aligned with NIST schema
- Transparent `migration_audit.log` with processed / split / merged / error counts

## Quick Start

```bash
# 1. Clone
git clone 
cd rev4-to-rev5-upgrade

# 2. Install dependencies
pip install -r requirements.txt

# 3. Place your eMASS Rev 4 export as source_rev4_ssp.json
#    (or use the included sample)

# 4. (Optional) Point to your own remote mapping matrix
#    Edit MAPPING_URL and SCLM_URL in the script, or keep the local fallbacks

# 5. Run
python oscal_migration_pipeline.py
```

Outputs:
- `OSCAL_SSP_Rev5_YYYYMMDD.json` – ready for eMASS import validation
- `migration_audit.log` – full decision trail

## Conversion Matrix Patterns

| Rev 4 Pattern       | Rev 5 Structural Shift          | Data Matrix Action                                      | SCLM Integration Strategy                          |
|---------------------|---------------------------------|---------------------------------------------------------|----------------------------------------------------|
| 1-to-1 Match        | Direct carry-over (e.g. cm-2)   | Copy narrative string                                   | Map to one SCLM module ID                          |
| 1-to-Many Split     | Control divided into subsets    | Duplicate base narrative; append child-context blocks   | Bind distinct automated checks to each child       |
| Many-to-1 Merge     | Consolidations                  | Concat narratives with `---` separators                 | Reference omnibus orchestration playbook           |
| Withdrawn / Omitted | Control removed or integrated   | Move narrative to system remark / audit trail           | Flag associated SCLM script as deprecated          |

## Schema Integrity Rules (eMASS)

- Property names in `props` must be lower-case (`sclm-module-id`, etc.)
- Every `implemented-requirement` must have a **unique deterministic UUID**
- Control IDs must be lowercase with standard parentheses: `ac-2(1)`
- Never invent classified content or claim ATO

## File Layout

```
rev4-to-rev5-upgrade/
├── oscal_migration_pipeline.py   # Main engine
├── requirements.txt
├── config/
│   ├── rev4_rev5_map.json        # Conversion matrix (can be remote)
│   └── sclm_library.json         # SCLM telemetry bindings
├── samples/
│   └── source_rev4_ssp.json      # Example eMASS Rev 4 export
├── migration_audit.log           # Generated on run
└── README.md
```

## Remote Configuration (Recommended for Enterprise)

Host `rev4_rev5_map.json` and `sclm_library.json` in a private Git repository (or internal S3/Artifactory) and point the script at the raw URLs. This guarantees every auditor uses the identical approved baseline.

## License

This project is provided for official use by cybersecurity auditors performing NIST RMF SP 800-53 migrations. No warranty expressed or implied. Always validate output against the current NIST OSCAL schema and your organizational eMASS import rules before production use.

---
*Aligned with NIST SP 800-53 Rev 5, OSCAL 1.1.x, and eMASS import expectations. Never claims Authorization to Operate.*