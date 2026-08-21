# Narrative Engine – Contract, Delta Classes, Provenance, Generation Rules

## Narrative Contract

Every generated Rev 5 implementation narrative must contain:

1. **Migration strategy marker** – one-to-one | split | merge | withdrawn | new-control
2. **Legacy Rev 4 source** – control ID(s) or explicit "new-control" statement
3. **Readable body** – the substance of the original (or merged) narrative, preserved
4. **SCLM properties** (lowercase) – `sclm-module-id`, `sclm-automation-payload`, `implementation-status`
5. **Deterministic UUID** – UUID v5 derived from target control ID + fixed namespace

## Provenance Model (GFM)

Generated descriptions use GitHub-Flavored Markdown markers for human and machine readability:

```text
**Migration strategy:** split
**Legacy Rev 4 source:** ac-2

---

<original narrative text>
```

For merges:

```text
**Migration strategy:** merge
**Legacy Rev 4 source:** ia-2, ia-2(1)

---

--- Legacy Source IA-2 ---
<ia-2 narrative>

--- Legacy Source IA-2(1) ---
<ia-2(1) narrative>
```

## Delta Classes

| Class | Meaning | Engine action |
|-------|---------|---------------|
| one-to-one | Direct structural carry-over | Copy narrative; inject props |
| split | One Rev 4 control → multiple Rev 5 targets | Duplicate narrative across children; distinct UUIDs and SCLM bindings |
| merge | Multiple Rev 4 controls → one Rev 5 target | Concatenate narratives with clear separators |
| withdrawn | Control removed or integrated elsewhere | Omit from output; record in audit log only |
| new-control | No Rev 4 source; introduced in Rev 5 | Explicit marker; requires separate approval |

## Generation Rules

1. Consume each Rev 4 control at most once (track `processed_r4`).
2. Never invent narrative text; only transform and mark provenance.
3. SCLM values default to `NOT-CONFIGURED` / `N/A` / `review-required` when the map has no verified entry.
4. Do not embed unverified repository URLs.
5. All `props.name` values are lowercase.
6. Control IDs are lowercase with standard parentheses (`ac-2(1)`).
7. Output remains a **draft** until the synchronization rule and review gates complete.
