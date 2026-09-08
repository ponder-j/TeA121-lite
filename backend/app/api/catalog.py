from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.catalog.detectors import as_dict as detector_dict
from app.catalog.rule_packs import as_dict as rule_dict
from app.db.models import Detector, RulePack
from app.db.session import get_db
from app.schemas.common import DetectorDescriptor, Page, RulePackDescriptor

from .deps import page_params

router = APIRouter(prefix="/api/v1", tags=["catalog"])


@router.get("/detectors", response_model=Page[DetectorDescriptor])
def detectors(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    limit, offset = page_params(limit, offset)
    rows = db.scalars(select(Detector).offset(offset).limit(limit)).all()
    total = db.scalar(select(func.count()).select_from(Detector)) or 0
    return {
        "items": [detector_dict(x) for x in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/rule-packs", response_model=Page[RulePackDescriptor])
def rule_packs(
    detector_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    limit, offset = page_params(limit, offset)
    q = select(RulePack)
    cq = select(func.count()).select_from(RulePack)
    if detector_id:
        q = q.where(RulePack.detector_id == detector_id)
        cq = cq.where(RulePack.detector_id == detector_id)
    rows = db.scalars(q.offset(offset).limit(limit)).all()
    return {
        "items": [rule_dict(x) for x in rows],
        "total": db.scalar(cq) or 0,
        "limit": limit,
        "offset": offset,
    }
