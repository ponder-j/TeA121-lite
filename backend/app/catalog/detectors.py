import json

from sqlalchemy.orm import Session

from app.db.models import Detector

DEFAULT_DETECTOR = {
    "id": "stack-bounds",
    "version": "0.1.0",
    "name": "Stack bounds + integer overflow/underflow detector",
    "supported_cwes": ["CWE-121", "CWE-190", "CWE-191"],
    "enabled": True,
}


def seed(db: Session) -> Detector:
    row = db.get(Detector, DEFAULT_DETECTOR["id"])
    if row is None:
        row = Detector(
            id=DEFAULT_DETECTOR["id"],
            version=DEFAULT_DETECTOR["version"],
            name=DEFAULT_DETECTOR["name"],
            supported_cwes_json=json.dumps(DEFAULT_DETECTOR["supported_cwes"]),
            enabled=True,
        )
        db.add(row)
    else:
        # Refresh declarations so an instance seeded before a new CWE was
        # added picks up the widened rule-pack scope.
        row.version = DEFAULT_DETECTOR["version"]
        row.name = DEFAULT_DETECTOR["name"]
        row.supported_cwes_json = json.dumps(DEFAULT_DETECTOR["supported_cwes"])
        row.enabled = DEFAULT_DETECTOR["enabled"]
    db.commit()
    return row


def as_dict(row: Detector) -> dict:
    return {
        "id": row.id,
        "version": row.version,
        "name": row.name,
        "supported_cwes": json.loads(row.supported_cwes_json),
        "enabled": row.enabled,
    }
