# DAAG Rev 4 to Rev 5 Transition Strategy

This folder defines the strategy and target architecture for migrating DAAG-aligned Rev 4 system-security-plan implementation narratives to NIST SP 800-53 Rev 5.

The strategy preserves the substance of the DAAG guidance. It changes the production method so each Rev 5 narrative is traceable to:

1. The target Rev 5 control and statement.
2. The Rev 4 source control or an explicit **new-control** decision.
3. The applicable DCSA guidance and evidence expectation.
4. The system-specific implementation, responsible role, frequency, and artifact references.
5. The organization-defined parameters and tailoring decisions used in the target profile.

## Strategy Documents

| Document | Purpose |
|----------|---------|
| [Architecture](architecture.md) | Target components, data flow, ownership boundaries, and design principles |
| [Transition Workflow](transition-workflow.md) | Repeatable Rev 4-to-Rev 5 processing sequence and review gates |
| [Narrative Engine](narrative-engine.md) | Narrative contract, delta classes, provenance model, and generation rules |
| [Control Mapping](control-mapping.md) | Mapping approach for DAAG guidance, Rev 4 controls, Rev 5 controls, and evidence |
| [Release and Delta Register](release-delta-register.md) | Rev 4-to-Rev 5 change data, ODP authority, withdrawals, baseline impact, and Rev 5.2.0 handling |
| [Validation Checklist](validation-checklist.md) | Quality gates for content, OSCAL, eMASS, and assessor review |

## Scope Boundary

This strategy covers **narrative migration and its supporting traceability**. It does not replace:

- The authoritative NIST catalog
- DCSA transition instructions
- eMASS import validation
- An Authorizing Official decision

A generated narrative remains a **draft** until the ISSM/ISSO, system owner, assessor, and AO-authorized process approve it.

**Never invent classified content. Never claim ATO.**

## Synchronization Rule

1. Resolve and approve the working-copy decisions.
2. Update the authoritative source delta through the approved change process.
3. Regenerate and validate the profile.
4. Regenerate implementation narratives and OSCAL/eMASS outputs from the validated profile.
5. Retain the merge report, mapping register, ODP approvals, and review decisions with the package.

## Known Transition Deltas and Risks (Summary)

| Topic | Current state | Required treatment |
|-------|---------------|--------------------|
| System context | Source delta may describe IRAD/container example; eMASS SSP may describe UNIFIED WAN | Revalidate every ODP, evidence statement, and metric for the target system before approval |
| Categorization / baseline | eMASS source may be M-L-L; working copy may select Moderate | Confirm approved Rev 5 baseline and record applicable NSS/DCSA overlay |
| DCSA overlay | Local overlay tables may cover SUSA/MUSA/ISOL/P2P | Do not apply selections directly without a documented applicability decision |
| ODPs | Candidate values exist in assignment files | Treat each as candidate; validate against Rev 5 parameter, system evidence, and approval record |
| Container-specific values | Some ODPs may reference image admits, SCA gates, container metrics | Replace with target-system logging/monitoring/scanning values or document why they apply |
| Rev 5.2.0 | Local summary may identify SA-15(13), SA-24, SI-2(7), SI-7(12) impacts | Do not add until official target catalog/profile version is confirmed |
| Legacy eMASS status | Rev 4 source contains Implemented / Planned / Compensated / Not Applicable | Preserve as source evidence only; confirm each Rev 5 status through mapping and assessment review |

## Clarifications Required Before Production Generation

| Decision needed | Owner to confirm | Why it matters |
|-----------------|------------------|----------------|
| Approved Rev 5 catalog and profile version | ISSM/SCA/AO-authorized process | Determines whether 5.2.0 changes are in scope |
| Approved baseline and DCSA/NSS overlay | System Owner, ISSM, AO-authorized process | Determines selected controls and valid N/A decisions |
| System type and boundary | System Owner and ISSO | Determines applicable local/isolated/WAN/cloud/connection guidance |
| Each copied ODP value | ISSM, control owner, System Owner | Prevents incorrect values from being represented as requirements |
| Approved exclusions and additions | ISSM/SCA with required approval authority | Maintains assessor traceability and risk treatment |
| Evidence/artifact locations and owners | ISSO and control owners | Lets the narrative make verifiable implementation claims |
| Rev 5 disposition for legacy statuses | ISSM, SCA, and System Owner | Prevents automatic carry-forward of Rev 4 compliance assertions |
