#!/usr/bin/env python3
"""
Comprehensive Unit Test Suite for NIST RMF SP 800-53 Rev4 → Rev5 OSCAL SSP Migration
Cybersecurity Auditor Edition – 100% accuracy target on transformation logic.

Covers:
  - Deterministic UUID v5 generation (idempotency)
  - one-to-one, split, merge, withdrawn strategies
  - SCLM property injection and fallbacks
  - Narrative preservation and merge aggregation
  - Edge cases: missing sources, empty SSP, unknown strategy, duplicate prevention
  - eMASS schema integrity (lowercase props, control-id format)
"""

import unittest
import uuid
import json
import copy
from typing import Any


# =============================================================================
# 1. CORE PURE FUNCTIONS (mirrors production pipeline logic exactly)
# =============================================================================

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def generate_deterministic_uuid(control_id: str, context: str = "ssp-req") -> str:
    """Generates a stable UUID v5 using a fixed DNS namespace for eMASS idempotency."""
    return str(uuid.uuid5(NAMESPACE, f"emass-rev5-{control_id}-{context}"))


def execute_mll_migration(
    ssp_source: dict[str, Any],
    matrix: dict[str, Any],
    sclm: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Transforms a Rev 4 SSP structure into an eMASS-compliant Rev 5
    implemented-requirements list with SCLM props.
    Mirrors the production OscalMigrationPipeline.migrate_ssp logic.
    """
    r4_requirements = (
        ssp_source
        .get("system-security-plan", {})
        .get("control-implementation", {})
        .get("implemented-requirements", [])
    )
    r5_requirements: list[dict[str, Any]] = []

    r4_lookup = {
        req.get("control-id"): req.get("description", "")
        for req in r4_requirements
        if req.get("control-id")
    }
    processed_r4: set[str] = set()

    for req in r4_requirements:
        r4_id = req.get("control-id")
        if not r4_id or r4_id in processed_r4:
            continue

        base_text = req.get("description", "")
        entry = matrix.get(
            r4_id,
            {"strategy": "one-to-one", "targets": [r4_id], "processing_note": "Fallback Default"},
        )
        strategy = entry.get("strategy", "one-to-one")
        targets = entry.get("targets", [r4_id])

        # ------------------------------------------------------------------
        # One-to-One and One-to-Many Split
        # ------------------------------------------------------------------
        if strategy in ("one-to-one", "split"):
            for target_id in targets:
                sclm_info = sclm.get(
                    target_id,
                    {"module_id": "NOT-CONFIGURED", "uri": "N/A", "status": "planned"},
                )
                r5_requirements.append(
                    {
                        "uuid": generate_deterministic_uuid(target_id),
                        "control-id": target_id,
                        "props": [
                            {"name": "migration-strategy", "value": strategy},
                            {"name": "legacy-rev4-control", "value": r4_id},
                            {"name": "sclm-module-id", "value": sclm_info.get("module_id", "NOT-CONFIGURED")},
                            {"name": "sclm-automation-payload", "value": sclm_info.get("uri", "N/A")},
                            {"name": "implementation-status", "value": sclm_info.get("status", "planned")},
                        ],
                        "description": f"| Migrated via {strategy.upper()} | {base_text}",
                    }
                )
            processed_r4.add(r4_id)

        # ------------------------------------------------------------------
        # Many-to-One Merge
        # ------------------------------------------------------------------
        elif strategy == "merge":
            sources = entry.get("sources_to_merge", [r4_id])
            merged_text: list[str] = []
            for src in sources:
                if src in r4_lookup:
                    merged_text.append(f"--- Legacy Source {src.upper()} ---\n{r4_lookup[src]}")
                    processed_r4.add(src)

            unified_narrative = "| Merged Data Stream |\n\n" + "\n\n".join(merged_text)
            for target_id in targets:
                sclm_info = sclm.get(
                    target_id,
                    {"module_id": "NOT-CONFIGURED", "uri": "N/A", "status": "planned"},
                )
                r5_requirements.append(
                    {
                        "uuid": generate_deterministic_uuid(target_id),
                        "control-id": target_id,
                        "props": [
                            {"name": "migration-strategy", "value": strategy},
                            {"name": "legacy-rev4-control", "value": ", ".join(sources)},
                            {"name": "sclm-module-id", "value": sclm_info.get("module_id", "NOT-CONFIGURED")},
                            {"name": "sclm-automation-payload", "value": sclm_info.get("uri", "N/A")},
                            {"name": "implementation-status", "value": sclm_info.get("status", "planned")},
                        ],
                        "description": unified_narrative,
                    }
                )

        # ------------------------------------------------------------------
        # Withdrawn / Omitted – narrative is intentionally dropped from output
        # (preserved only in audit log in the full pipeline)
        # ------------------------------------------------------------------
        elif strategy == "withdrawn":
            processed_r4.add(r4_id)
            # No r5_requirements entry is created

        # ------------------------------------------------------------------
        # Unknown strategy → treat as one-to-one fallback
        # ------------------------------------------------------------------
        else:
            for target_id in targets:
                sclm_info = sclm.get(
                    target_id,
                    {"module_id": "NOT-CONFIGURED", "uri": "N/A", "status": "planned"},
                )
                r5_requirements.append(
                    {
                        "uuid": generate_deterministic_uuid(target_id),
                        "control-id": target_id,
                        "props": [
                            {"name": "migration-strategy", "value": "one-to-one"},
                            {"name": "legacy-rev4-control", "value": r4_id},
                            {"name": "sclm-module-id", "value": sclm_info.get("module_id", "NOT-CONFIGURED")},
                            {"name": "sclm-automation-payload", "value": sclm_info.get("uri", "N/A")},
                            {"name": "implementation-status", "value": sclm_info.get("status", "planned")},
                        ],
                        "description": f"| Migrated via ONE-TO-ONE | {base_text}",
                    }
                )
            processed_r4.add(r4_id)

    return r5_requirements


# =============================================================================
# 2. AUTOMATED UNIT TEST SUITE – 100% accuracy target
# =============================================================================

class TestOscalMllMigrationPipeline(unittest.TestCase):
    """Full structural and semantic verification of the migration engine."""

    def setUp(self):
        """Initializes baseline M-L-L payload, conversion matrix, and SCLM library."""
        self.mock_mll_ssp_source = {
            "system-security-plan": {
                "system-characteristics": {
                    "system-name": "Tactical Logistics Processor",
                    "security-sensitivity-level": "M-L-L",
                },
                "control-implementation": {
                    "implemented-requirements": [
                        {
                            "control-id": "cm-2",
                            "description": "System configuration baselines are versioned in Git.",
                        },
                        {
                            "control-id": "ac-2",
                            "description": "Active Directory configuration handles system access profiles.",
                        },
                        {
                            "control-id": "ia-2",
                            "description": "CAC multi-factor login token authentication is mandatory.",
                        },
                        {
                            "control-id": "ia-2(1)",
                            "description": "Local API identity providers cross-check session token parameters.",
                        },
                    ]
                },
            }
        }

        self.mock_conversion_matrix = {
            "cm-2": {"strategy": "one-to-one", "targets": ["cm-2"]},
            "ac-2": {"strategy": "split", "targets": ["ac-2", "ac-2(1)"]},
            "ia-2": {
                "strategy": "merge",
                "targets": ["ia-2"],
                "sources_to_merge": ["ia-2", "ia-2(1)"],
            },
        }

        self.mock_sclm_library = {
            "cm-2": {
                "module_id": "SCLM-RHEL-STIG",
                "uri": "https://repo/rhel9.yml",
                "status": "implemented",
            },
            "ac-2": {
                "module_id": "SCLM-AD-CORE",
                "uri": "https://repo/ad.ps1",
                "status": "implemented",
            },
            "ac-2(1)": {
                "module_id": "SCLM-AD-LOCK",
                "uri": "https://repo/lock.ps1",
                "status": "implemented",
            },
            "ia-2": {
                "module_id": "SCLM-MFA-FORCE",
                "uri": "https://repo/mfa.json",
                "status": "implemented",
            },
        }

        self.results = execute_mll_migration(
            self.mock_mll_ssp_source,
            self.mock_conversion_matrix,
            self.mock_sclm_library,
        )

    # ------------------------------------------------------------------
    # 2.1 UUID Determinism & Format
    # ------------------------------------------------------------------
    def test_idempotent_uuid_generation(self):
        """UUID fields are deterministic UUID v5 and structurally valid."""
        for req in self.results:
            c_id = req["control-id"]
            expected = generate_deterministic_uuid(c_id)
            self.assertEqual(
                req["uuid"],
                expected,
                f"UUID for control {c_id} is non-deterministic.",
            )
            # Must parse as a real UUID
            try:
                uuid.UUID(req["uuid"])
            except ValueError:
                self.fail(f"Control {c_id} produced invalid UUID string.")

    def test_uuid_stability_across_runs(self):
        """Running the same migration twice yields identical UUIDs (idempotency)."""
        run1 = execute_mll_migration(
            self.mock_mll_ssp_source,
            self.mock_conversion_matrix,
            self.mock_sclm_library,
        )
        run2 = execute_mll_migration(
            self.mock_mll_ssp_source,
            self.mock_conversion_matrix,
            self.mock_sclm_library,
        )
        uuids1 = {r["control-id"]: r["uuid"] for r in run1}
        uuids2 = {r["control-id"]: r["uuid"] for r in run2}
        self.assertEqual(uuids1, uuids2)

    # ------------------------------------------------------------------
    # 2.2 One-to-One
    # ------------------------------------------------------------------
    def test_one_to_one_mapping_integrity(self):
        """1:1 controls preserve narrative and inject correct SCLM props."""
        cm2 = next((r for r in self.results if r["control-id"] == "cm-2"), None)
        self.assertIsNotNone(cm2, "CM-2 missing after migration.")

        self.assertIn("Git", cm2["description"])
        self.assertIn("| Migrated via ONE-TO-ONE |", cm2["description"])

        props = {p["name"]: p["value"] for p in cm2["props"]}
        self.assertEqual(props["migration-strategy"], "one-to-one")
        self.assertEqual(props["legacy-rev4-control"], "cm-2")
        self.assertEqual(props["sclm-module-id"], "SCLM-RHEL-STIG")
        self.assertEqual(props["sclm-automation-payload"], "https://repo/rhel9.yml")
        self.assertEqual(props["implementation-status"], "implemented")

    # ------------------------------------------------------------------
    # 2.3 One-to-Many Split
    # ------------------------------------------------------------------
    def test_one_to_many_split_integrity(self):
        """Split duplicates narrative across children and isolates SCLM bindings."""
        base = next((r for r in self.results if r["control-id"] == "ac-2"), None)
        enh = next((r for r in self.results if r["control-id"] == "ac-2(1)"), None)

        self.assertIsNotNone(base, "Base AC-2 missing after split.")
        self.assertIsNotNone(enh, "Enhancement AC-2(1) missing after split.")

        narrative = "Active Directory configuration handles system access profiles."
        self.assertIn(narrative, base["description"])
        self.assertIn(narrative, enh["description"])
        self.assertIn("| Migrated via SPLIT |", base["description"])
        self.assertIn("| Migrated via SPLIT |", enh["description"])

        base_props = {p["name"]: p["value"] for p in base["props"]}
        enh_props = {p["name"]: p["value"] for p in enh["props"]}

        self.assertEqual(base_props["sclm-module-id"], "SCLM-AD-CORE")
        self.assertEqual(enh_props["sclm-module-id"], "SCLM-AD-LOCK")
        self.assertEqual(base_props["migration-strategy"], "split")
        self.assertEqual(enh_props["migration-strategy"], "split")
        self.assertEqual(base_props["legacy-rev4-control"], "ac-2")
        self.assertEqual(enh_props["legacy-rev4-control"], "ac-2")

        # Distinct UUIDs for each child
        self.assertNotEqual(base["uuid"], enh["uuid"])

    # ------------------------------------------------------------------
    # 2.4 Many-to-One Merge
    # ------------------------------------------------------------------
    def test_many_to_one_merge_integrity(self):
        """Merge aggregates all source narratives without loss."""
        ia2 = next((r for r in self.results if r["control-id"] == "ia-2"), None)
        self.assertIsNotNone(ia2, "Merged IA-2 missing.")

        desc = ia2["description"]
        self.assertIn("| Merged Data Stream |", desc)
        self.assertIn("--- Legacy Source IA-2 ---", desc)
        self.assertIn("--- Legacy Source IA-2(1) ---", desc)
        self.assertIn("CAC multi-factor login token authentication", desc)
        self.assertIn("Local API identity providers cross-check", desc)

        props = {p["name"]: p["value"] for p in ia2["props"]}
        self.assertEqual(props["migration-strategy"], "merge")
        self.assertIn("ia-2", props["legacy-rev4-control"])
        self.assertIn("ia-2(1)", props["legacy-rev4-control"])
        self.assertEqual(props["sclm-module-id"], "SCLM-MFA-FORCE")
        self.assertEqual(props["implementation-status"], "implemented")

    # ------------------------------------------------------------------
    # 2.5 Result cardinality
    # ------------------------------------------------------------------
    def test_result_cardinality(self):
        """Expected number of Rev 5 requirements after all transformations."""
        # cm-2 → 1, ac-2 split → 2, ia-2 merge → 1  => total 4
        self.assertEqual(len(self.results), 4)

        control_ids = [r["control-id"] for r in self.results]
        self.assertCountEqual(control_ids, ["cm-2", "ac-2", "ac-2(1)", "ia-2"])

    # ------------------------------------------------------------------
    # 2.6 SCLM fallback when module is missing
    # ------------------------------------------------------------------
    def test_sclm_fallback_when_missing(self):
        """Missing SCLM entry yields NOT-CONFIGURED / planned defaults."""
        empty_sclm: dict[str, Any] = {}
        results = execute_mll_migration(
            self.mock_mll_ssp_source,
            self.mock_conversion_matrix,
            empty_sclm,
        )
        for req in results:
            props = {p["name"]: p["value"] for p in req["props"]}
            self.assertEqual(props["sclm-module-id"], "NOT-CONFIGURED")
            self.assertEqual(props["sclm-automation-payload"], "N/A")
            self.assertEqual(props["implementation-status"], "planned")

    # ------------------------------------------------------------------
    # 2.7 Withdrawn strategy
    # ------------------------------------------------------------------
    def test_withdrawn_control_omitted(self):
        """Withdrawn controls produce no implemented-requirement entry."""
        matrix = {
            "cm-2": {"strategy": "withdrawn", "targets": []},
            "ac-2": {"strategy": "one-to-one", "targets": ["ac-2"]},
        }
        results = execute_mll_migration(
            self.mock_mll_ssp_source,
            matrix,
            self.mock_sclm_library,
        )
        control_ids = [r["control-id"] for r in results]
        self.assertNotIn("cm-2", control_ids)
        self.assertIn("ac-2", control_ids)

    # ------------------------------------------------------------------
    # 2.8 Fallback for unmapped control
    # ------------------------------------------------------------------
    def test_unmapped_control_falls_back_to_one_to_one(self):
        """Control absent from matrix is treated as one-to-one to itself."""
        ssp = {
            "system-security-plan": {
                "control-implementation": {
                    "implemented-requirements": [
                        {"control-id": "au-2", "description": "Audit events are logged."}
                    ]
                }
            }
        }
        results = execute_mll_migration(ssp, {}, self.mock_sclm_library)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["control-id"], "au-2")
        props = {p["name"]: p["value"] for p in results[0]["props"]}
        self.assertEqual(props["migration-strategy"], "one-to-one")
        self.assertIn("Audit events are logged.", results[0]["description"])

    # ------------------------------------------------------------------
    # 2.9 Empty / malformed source
    # ------------------------------------------------------------------
    def test_empty_implemented_requirements(self):
        """Empty requirements list yields empty result without error."""
        ssp = {
            "system-security-plan": {
                "control-implementation": {"implemented-requirements": []}
            }
        }
        results = execute_mll_migration(ssp, self.mock_conversion_matrix, self.mock_sclm_library)
        self.assertEqual(results, [])

    def test_missing_control_implementation_section(self):
        """Missing control-implementation yields empty result safely."""
        ssp = {"system-security-plan": {}}
        results = execute_mll_migration(ssp, self.mock_conversion_matrix, self.mock_sclm_library)
        self.assertEqual(results, [])

    # ------------------------------------------------------------------
    # 2.10 Duplicate prevention
    # ------------------------------------------------------------------
    def test_duplicate_r4_control_processed_once(self):
        """Same control-id appearing twice is processed only once."""
        ssp = {
            "system-security-plan": {
                "control-implementation": {
                    "implemented-requirements": [
                        {"control-id": "cm-2", "description": "First narrative."},
                        {"control-id": "cm-2", "description": "Second narrative (should be ignored)."},
                    ]
                }
            }
        }
        matrix = {"cm-2": {"strategy": "one-to-one", "targets": ["cm-2"]}}
        results = execute_mll_migration(ssp, matrix, self.mock_sclm_library)
        self.assertEqual(len(results), 1)
        self.assertIn("First narrative.", results[0]["description"])
        self.assertNotIn("Second narrative", results[0]["description"])

    # ------------------------------------------------------------------
    # 2.11 eMASS schema integrity
    # ------------------------------------------------------------------
    def test_props_keys_are_lowercase(self):
        """All prop names are lowercase (eMASS validation requirement)."""
        for req in self.results:
            for p in req["props"]:
                self.assertEqual(
                    p["name"],
                    p["name"].lower(),
                    f"Prop name '{p['name']}' is not lowercase.",
                )

    def test_control_ids_are_lowercase_with_parentheses(self):
        """Control IDs follow Rev 5 lowercase + parentheses convention."""
        for req in self.results:
            cid = req["control-id"]
            self.assertEqual(cid, cid.lower())
            # Enhancement form must use parentheses, never space or "enh"
            if "(" in cid:
                self.assertRegex(cid, r"^[a-z]+-\d+\(\d+\)$")

    def test_required_props_present(self):
        """Every requirement contains the five mandatory custom props."""
        required = {
            "migration-strategy",
            "legacy-rev4-control",
            "sclm-module-id",
            "sclm-automation-payload",
            "implementation-status",
        }
        for req in self.results:
            names = {p["name"] for p in req["props"]}
            self.assertTrue(
                required.issubset(names),
                f"Missing required props on {req['control-id']}: {required - names}",
            )

    # ------------------------------------------------------------------
    # 2.12 Merge with missing source narrative
    # ------------------------------------------------------------------
    def test_merge_with_partial_sources(self):
        """Merge continues gracefully when one source narrative is absent."""
        ssp = {
            "system-security-plan": {
                "control-implementation": {
                    "implemented-requirements": [
                        {"control-id": "ia-2", "description": "Only base IA-2 present."}
                        # ia-2(1) intentionally missing
                    ]
                }
            }
        }
        matrix = {
            "ia-2": {
                "strategy": "merge",
                "targets": ["ia-2"],
                "sources_to_merge": ["ia-2", "ia-2(1)"],
            }
        }
        results = execute_mll_migration(ssp, matrix, self.mock_sclm_library)
        self.assertEqual(len(results), 1)
        desc = results[0]["description"]
        self.assertIn("--- Legacy Source IA-2 ---", desc)
        self.assertIn("Only base IA-2 present.", desc)
        # Missing source must not appear
        self.assertNotIn("--- Legacy Source IA-2(1) ---", desc)

    # ------------------------------------------------------------------
    # 2.13 Unknown strategy falls back safely
    # ------------------------------------------------------------------
    def test_unknown_strategy_treated_as_one_to_one(self):
        """Unrecognized strategy value is coerced to one-to-one."""
        matrix = {
            "cm-2": {"strategy": "exotic-custom", "targets": ["cm-2"]},
        }
        results = execute_mll_migration(
            self.mock_mll_ssp_source,
            matrix,
            self.mock_sclm_library,
        )
        cm2 = next((r for r in results if r["control-id"] == "cm-2"), None)
        self.assertIsNotNone(cm2)
        props = {p["name"]: p["value"] for p in cm2["props"]}
        self.assertEqual(props["migration-strategy"], "one-to-one")


# =============================================================================
# 3. RUNNER
# =============================================================================
if __name__ == "__main__":
    # High-verbosity run so the auditor sees every assertion
    unittest.main(verbosity=2)
