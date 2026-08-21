# Architecture – DAAG Rev 4 → Rev 5 Narrative Migration

## Design Principles

1. **Traceability first** – Every Rev 5 narrative must point to its Rev 4 source (or an explicit new-control decision), the target control/statement, and the evidence expectation.
2. **Deterministic identity** – UUID v5 for all `implemented-requirement` and component objects so eMASS re-imports are idempotent.
3. **No silent carry-forward** – Legacy Implemented/Planned/Compensated/N/A statuses are source evidence only; Rev 5 status is confirmed through mapping and assessment review.
4. **Placeholders over unverified claims** – SCLM module IDs and automation payloads remain `NOT-CONFIGURED` / `review-required` until ISSM/ISSO/SCA populate verified values.
5. **Scope boundary** – Narrative migration and supporting traceability only. No ATO claim. No replacement of the authoritative NIST catalog or DCSA instructions.

## Target Components

| Component | Responsibility | Ownership boundary |
|-----------|----------------|--------------------|
| Conversion matrix (`rev4_rev5_map.json` / `migration-sclm-map.json`) | Declares one-to-one, split, merge, withdrawn strategies and SCLM placeholders | Configuration managed under change control |
| Migration engine (`oscal_migration_pipeline.py`) | Applies matrix, injects provenance and SCLM props, emits deterministic UUIDs | Pipeline maintainers |
| Source SSP (eMASS Rev 4 export) | Provides original implementation narratives and statuses | System Owner / ISSO |
| Target profile / tailoring delta | Supplies selected controls, ODPs, and exclusions | ISSM / SCA / AO-authorized process |
| Generated Rev 5 OSCAL artifact | Draft SSP or component-definition for review | Remains draft until approved |
| Audit log (`migration_audit.log`) | Decision trail of every transformation | Retained with the package |

## Data Flow (High Level)

```
eMASS Rev 4 SSP (JSON)
        |
        v
+-----------------------+
|  Conversion Matrix    |  <- one-to-one / split / merge / withdrawn
|  + SCLM placeholders  |
+-----------+-----------+
            |
            v
+-----------------------+
|  Migration Engine     |  <- deterministic UUID v5
|  (narrative + props)  |  <- GFM provenance markers
+-----------+-----------+
            |
            v
+-----------------------+
|  Draft Rev 5 OSCAL    |  <- schema-validated
|  + migration_audit.log|
+-----------+-----------+
            |
            v
   Review gates (ISSM / ISSO / SCA / System Owner)
            |
            v
   Approved package (only after synchronization rule complete)
```

## Ownership Boundaries

- **Pipeline maintainers** own the engine, matrix schema, and unit tests.
- **ISSM / control owners** own the content of ODPs, evidence statements, and final status disposition.
- **System Owner / ISSO** own system-specific implementation claims and artifact locations.
- **SCA / AO-authorized process** own baseline selection, overlay applicability, and final approval.
