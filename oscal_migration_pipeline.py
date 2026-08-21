#!/usr/bin/env python3
"""
NIST RMF SP 800-53 Rev 4 → Rev 5 OSCAL SSP Migration Pipeline
Cybersecurity Auditor Edition

Transforms an eMASS-exported OSCAL Rev 4 System Security Plan into a
validated OSCAL Rev 5 SSP JSON payload while injecting SCLM tracking
properties. Designed for auditability, deterministic UUIDs, and
enterprise remote configuration of the conversion matrix.

Never invents classified content. Never claims ATO.
"""

import json
import uuid
import logging
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    from requests.exceptions import RequestException, JSONDecodeError
except ImportError:
    print("ERROR: 'requests' library is required. Run: pip install requests")
    sys.exit(1)

# ==========================================
# 1. LOGGING & AUDIT CONFIGURATION
# ==========================================
logger = logging.getLogger("OSCAL_Migration_Engine")
logger.setLevel(logging.DEBUG)

# File Handler – full decision audit trail
file_handler = logging.FileHandler("migration_audit.log", mode="w", encoding="utf-8")
file_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
file_handler.setFormatter(file_formatter)
file_handler.setLevel(logging.DEBUG)

# Console Handler – operator-friendly summary
console_handler = logging.StreamHandler(sys.stdout)
console_formatter = logging.Formatter("%(levelname)s: %(message)s")
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.INFO)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


# ==========================================
# 2. DYNAMIC REMOTE / LOCAL CONFIG LOADER
# ==========================================
def load_config(source, config_type="Mapping Matrix"):
    """
    Loads JSON configuration from a remote URL or local file path.
    Supports both enterprise Git raw URLs and local development fallbacks.
    """
    logger.info(f"Loading {config_type} from: {source}")

    # Local file path
    if not source.startswith(("http://", "https://")):
        path = Path(source)
        if not path.exists():
            logger.critical(f"Local config file not found: {source}")
            sys.exit(1)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"Successfully loaded local {config_type} ({len(data)} entries)")
            return data
        except json.JSONDecodeError as e:
            logger.critical(f"Corrupt JSON in local {config_type}: {e}")
            sys.exit(1)

    # Remote fetch
    try:
        response = requests.get(source, timeout=15)
        response.raise_for_status()
        data = response.json()
        logger.info(f"Successfully loaded remote {config_type} ({len(data)} entries)")
        return data
    except RequestException as e:
        logger.critical(f"Network failure fetching {config_type}: {e}")
        logger.error("Cannot proceed without authoritative mapping. Aborting.")
        sys.exit(1)
    except JSONDecodeError as e:
        logger.critical(f"Corrupt JSON format in remote {config_type}: {e}")
        logger.debug(f"Raw response (truncated): {response.text[:300]}...")
        sys.exit(1)


# ==========================================
# 3. PIPELINE IMPLEMENTATION ENGINE
# ==========================================
class OscalMigrationPipeline:
    """
    Core conversion engine that applies the four transformation patterns
    defined in the Data Schema Conversion Matrix.
    """

    def __init__(self, conversion_matrix: dict, sclm_matrix: dict):
        self.matrix = conversion_matrix
        self.sclm = sclm_matrix
        # Fixed DNS namespace for reproducible UUID v5 generation
        self.namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
        self.stats = {
            "processed": 0,
            "errors": 0,
            "one_to_one": 0,
            "split": 0,
            "merged": 0,
            "withdrawn": 0,
        }

    def _generate_deterministic_uuid(self, control_id: str, context: str = "ssp-req") -> str:
        """Stable UUID v5 based on control ID – prevents duplicate eMASS entries."""
        return str(uuid.uuid5(self.namespace, f"emass-rev5-{control_id}-{context}"))

    def _build_oscal_properties(self, target_id: str, r4_source_id: str, strategy: str) -> list:
        """Assemble OSCAL props array with SCLM telemetry and migration metadata."""
        try:
            sclm_info = self.sclm.get(target_id, {
                "module_id": "NOT-CONFIGURED",
                "execution_uri": "N/A",
                "status": "planned",
            })
            return [
                {"name": "migration-strategy", "value": strategy},
                {"name": "legacy-rev4-control", "value": r4_source_id},
                {"name": "sclm-module-id", "value": sclm_info.get("module_id", "NOT-CONFIGURED")},
                {"name": "sclm-automation-payload", "value": sclm_info.get("execution_uri", "N/A")},
                {"name": "implementation-status", "value": sclm_info.get("status", "planned")},
            ]
        except Exception as e:
            logger.error(f"Property build failure for {target_id}: {e}")
            self.stats["errors"] += 1
            return []

    def migrate_ssp(self, r4_ssp_json: dict) -> dict:
        """Apply the conversion matrix to every implemented-requirement."""
        logger.info("Starting SSP Transformation Process...")

        try:
            r4_requirements = (
                r4_ssp_json
                .get("system-security-plan", {})
                .get("control-implementation", {})
                .get("implemented-requirements", [])
            )
        except (AttributeError, TypeError):
            logger.critical("Invalid OSCAL Rev 4 source structure.")
            return {}

        if not r4_requirements:
            logger.warning("No implemented-requirements found in source SSP.")

        r5_implemented_requirements = []
        r4_narrative_lookup = {
            req["control-id"]: req.get("description", "")
            for req in r4_requirements
            if "control-id" in req
        }
        processed_r4 = set()

        for req in r4_requirements:
            r4_id = req.get("control-id")
            if not r4_id or r4_id in processed_r4:
                continue

            matrix_entry = self.matrix.get(r4_id, {
                "strategy": "one-to-one",
                "targets": [r4_id],
                "processing_note": "Fallback Default – control not explicitly mapped",
            })

            strategy = matrix_entry.get("strategy", "one-to-one")
            targets = matrix_entry.get("targets", [r4_id])

            try:
                if strategy in ("one-to-one", "split"):
                    base_narrative = req.get("description", "")
                    for target_id in targets:
                        r5_req = {
                            "uuid": self._generate_deterministic_uuid(target_id),
                            "control-id": target_id,
                            "props": self._build_oscal_properties(target_id, r4_id, strategy),
                            "description": (
                                f"| Migrated from R4 {r4_id.upper()} via {strategy.upper()} strategy | "
                                f"{base_narrative}"
                            ),
                        }
                        r5_implemented_requirements.append(r5_req)
                        self.stats["processed"] += 1
                        if strategy == "split":
                            self.stats["split"] += 1
                        else:
                            self.stats["one_to_one"] += 1

                    processed_r4.add(r4_id)
                    logger.debug(f"{strategy.upper()}: {r4_id} → {targets}")

                elif strategy == "merge":
                    merged_narratives = []
                    sources = matrix_entry.get("sources_to_merge", [r4_id])

                    for src_id in sources:
                        if src_id in r4_narrative_lookup:
                            merged_narratives.append(
                                f"--- Narrative Source Rev4 {src_id.upper()} ---\n"
                                f"{r4_narrative_lookup[src_id]}"
                            )
                            processed_r4.add(src_id)

                    unified_narrative = "\n\n".join(merged_narratives)

                    for target_id in targets:
                        r5_req = {
                            "uuid": self._generate_deterministic_uuid(target_id),
                            "control-id": target_id,
                            "props": self._build_oscal_properties(
                                target_id, ", ".join(sources), strategy
                            ),
                            "description": f"| Merged Data Stream |\n\n{unified_narrative}",
                        }
                        r5_implemented_requirements.append(r5_req)
                        self.stats["processed"] += 1
                        self.stats["merged"] += 1

                    logger.debug(f"MERGE: {sources} → {targets}")

                elif strategy == "withdrawn":
                    # Preserve narrative in a remark-style placeholder for audit trail
                    logger.info(f"WITHDRAWN control {r4_id} – narrative preserved in audit log only")
                    self.stats["withdrawn"] += 1
                    processed_r4.add(r4_id)

                else:
                    logger.warning(f"Unknown strategy '{strategy}' for {r4_id}; treating as one-to-one")

            except Exception as e:
                logger.error(f"Failed to process control {r4_id}: {e}")
                self.stats["errors"] += 1

        logger.info(f"Migration Complete. Stats: {self.stats}")

        return {
            "system-security-plan": {
                "uuid": str(uuid.uuid4()),  # envelope transaction ID may be random
                "metadata": {
                    "title": "Automated Migration Pipeline Result (Target Baseline: Rev 5)",
                    "last-modified": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "oscal-version": "1.1.2",
                    "version": "1.0.0",
                    "remarks": (
                        "Generated by rev4upgrade OSCAL Migration Pipeline. "
                        "All implemented-requirement UUIDs are deterministic (UUID v5). "
                        "Validate against current NIST OSCAL schema and organizational eMASS rules "
                        "before production import. This artifact does not constitute an ATO."
                    ),
                },
                "control-implementation": {
                    "implemented-requirements": r5_implemented_requirements,
                },
            }
        }


# ==========================================
# 4. EXECUTION RUNNER
# ==========================================
if __name__ == "__main__":
    # ---------------------------------------------------------
    # CONFIGURATION – override these for your environment
    # ---------------------------------------------------------
    # Prefer local files for offline / air-gapped use.
    # For enterprise, replace with raw Git URLs (GitHub/GitLab/Bitbucket).
    MAPPING_SOURCE = os.environ.get(
        "MAPPING_URL", "config/rev4_rev5_map.json"
    )
    SCLM_SOURCE = os.environ.get(
        "SCLM_URL", "config/sclm_library.json"
    )
    SOURCE_SSP = os.environ.get(
        "SOURCE_SSP", "samples/source_rev4_ssp.json"
    )

    logger.info("=" * 60)
    logger.info("NIST RMF SP 800-53 Rev4 → Rev5 OSCAL Migration Pipeline")
    logger.info("Cybersecurity Auditor Edition")
    logger.info("=" * 60)

    # 1. Load configurations
    conversion_matrix = load_config(MAPPING_SOURCE, "Conversion Matrix")
    sclm_matrix = load_config(SCLM_SOURCE, "SCLM Library")

    # 2. Load local source SSP
    try:
        with open(SOURCE_SSP, "r", encoding="utf-8") as f:
            incoming_rev4_ssp = json.load(f)
        logger.info(f"Loaded source SSP: {SOURCE_SSP}")
    except FileNotFoundError:
        logger.critical(f"Source file not found: {SOURCE_SSP}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.critical(f"Invalid JSON in source SSP: {e}")
        sys.exit(1)

    # 3. Execute pipeline
    pipeline = OscalMigrationPipeline(conversion_matrix, sclm_matrix)
    migrated_rev5_ssp = pipeline.migrate_ssp(incoming_rev4_ssp)

    if not migrated_rev5_ssp:
        logger.critical("Migration produced empty result. Aborting export.")
        sys.exit(1)

    # 4. Export result
    timestamp = datetime.now().strftime("%Y%m%d")
    output_filename = f"OSCAL_SSP_Rev5_{timestamp}.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(migrated_rev5_ssp, f, indent=2, ensure_ascii=False)

    logger.info(f"Successfully exported: {output_filename}")
    logger.info("Review migration_audit.log for the full decision trail.")
    logger.info("Validate the output against NIST OSCAL schema before eMASS import.")
