import json

from sqlalchemy.orm import Session

from app.db.models import Detector, RulePack

DEFAULT_RULE_PACK = {
    "id": "cwe121-core",
    "detector_id": "stack-bounds",
    "version": "0.1.0",
    "name": "CWE-121 core rules",
    "supported_cwes": ["CWE-121"],
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
            supported_cwes_json=json.dumps(DEFAULT_RULE_PACK["supported_cwes"]),
            supported_families_json=json.dumps(DEFAULT_RULE_PACK["supported_families"]),
            supported_violation_kinds_json=json.dumps(
                DEFAULT_RULE_PACK["supported_violation_kinds"]
            ),
        )
        db.add(row)
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
