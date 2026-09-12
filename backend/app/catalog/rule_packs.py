import json

from sqlalchemy.orm import Session

from app.db.models import Detector, RulePack

DEFAULT_RULE_PACK = {
    "id": "cwe121-core",
    "detector_id": "stack-bounds",
    "version": "0.1.0",
    "name": "CWE-121 bounds + CWE-190/CWE-191 integer rules",
    "supported_cwes": ["CWE-121", "CWE-190", "CWE-191"],
    "supported_families": [
        "CWE129_fgets",
        "CWE129_fscanf",
        "CWE129_rand",
        "CWE131_loop",
        "CWE131_memcpy",
        "CWE131_memmove",
        "CWE135_widechar",
        "CWE193_char_alloca_cpy",
    ],
    "supported_violation_kinds": [
        "stack_buffer_overflow",
        "index_validation_failure",
        "unknown_index_range",
        "off_by_one",
        "copy_length_overflow",
        "wide_char_length_mismatch",
        "out_of_bounds",
        "integer_overflow",
        "integer_underflow",
    ],
}


def seed(db: Session) -> RulePack:
    if db.get(Detector, "stack-bounds") is None:
        from .detectors import seed as seed_detector

        seed_detector(db)
    row = db.get(RulePack, DEFAULT_RULE_PACK["id"])
    if row is None:
        row = RulePack(
            id=DEFAULT_RULE_PACK["id"],
            detector_id=DEFAULT_RULE_PACK["detector_id"],
            version=DEFAULT_RULE_PACK["version"],
            name=DEFAULT_RULE_PACK["name"],
        )
        db.add(row)
    # Refresh declarations so an instance seeded before a new CWE/violation
    # kind was added picks up the widened rule-pack scope.
    row.detector_id = DEFAULT_RULE_PACK["detector_id"]
    row.version = DEFAULT_RULE_PACK["version"]
    row.name = DEFAULT_RULE_PACK["name"]
    row.supported_cwes_json = json.dumps(DEFAULT_RULE_PACK["supported_cwes"])
    row.supported_families_json = json.dumps(DEFAULT_RULE_PACK["supported_families"])
    row.supported_violation_kinds_json = json.dumps(
        DEFAULT_RULE_PACK["supported_violation_kinds"]
    )
    db.commit()
    return row


def as_dict(row: RulePack) -> dict:
    return {
        "id": row.id,
        "detector_id": row.detector_id,
        "version": row.version,
        "name": row.name,
        "supported_cwes": json.loads(row.supported_cwes_json),
        "supported_families": json.loads(row.supported_families_json),
        "supported_violation_kinds": json.loads(row.supported_violation_kinds_json),
    }
