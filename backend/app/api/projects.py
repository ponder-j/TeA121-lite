import hashlib
import posixpath
import shutil

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import FileAuditRecord, Project, SourceFile
from app.db.session import get_db
from app.schemas.common import (
    Page,
    ProjectCreate,
    ProjectOut,
    SourceFileDetailOut,
    SourceFileOut,
    SourceFileUpdate,
)

from .deps import page_params, project_or_404

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


def safe_path(value: str) -> str:
    value = value.replace("\\", "/").strip()
    normalized = posixpath.normpath(value)
    if not normalized or normalized in {".", ".."} or normalized.startswith(("../", "/")):
        raise HTTPException(
            400,
            detail={
                "code": "INVALID_PATH",
                "message": "path must be relative and cannot contain ..",
                "details": {},
            },
        )
    return normalized


def _store_source_file(
    db: Session, project_id: str, target: str, content: bytes, language: str | None = None
) -> SourceFile:
    from app.config import settings

    if len(content) > settings.max_upload_bytes:
        raise HTTPException(
            413,
            detail={
                "code": "FILE_TOO_LARGE",
                "message": "source file exceeds size limit",
                "details": {"max_bytes": settings.max_upload_bytes},
            },
        )
    settings.ensure_storage()
    disk_path = settings.storage_dir / project_id / target
    disk_path.parent.mkdir(parents=True, exist_ok=True)
    disk_path.write_bytes(content)
    suffix = target.rsplit(".", 1)[-1].lower() if "." in target else "c"
    row = SourceFile(
        project_id=project_id,
        path=target,
        language=language or ("c" if suffix in {"c", "h"} else suffix),
        content=content.decode("utf-8", errors="replace"),
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    row = Project(
        name=payload.name, description=payload.description, debug_mode=payload.debug_mode
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    if payload.debug_mode:
        _store_source_file(db, row.id, "blank.c", b"")
    return row


@router.get("", response_model=Page[ProjectOut])
def list_projects(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    limit, offset = page_params(limit, offset)
    total = db.scalar(select(func.count()).select_from(Project)) or 0
    return {
        "items": db.scalars(
            select(Project).order_by(Project.created_at.desc()).offset(offset).limit(limit)
        ).all(),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: Session = Depends(get_db)):
    return project_or_404(db, project_id)


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    project = project_or_404(db, project_id)
    for f in project.files:
        db.add(FileAuditRecord(project_id=project.id, path=f.path, sha256=f.sha256))
    db.delete(project)
    db.commit()
    from app.config import settings

    shutil.rmtree(settings.storage_dir / project_id, ignore_errors=True)


@router.post("/{project_id}/files", response_model=SourceFileOut, status_code=201)
async def upload_file(
    project_id: str,
    file: UploadFile = File(...),
    path: str | None = Form(None),
    db: Session = Depends(get_db),
):
    project_or_404(db, project_id)
    target = safe_path(path or file.filename or "source.c")
    content = await file.read()
    return _store_source_file(db, project_id, target, content)


@router.get("/{project_id}/files", response_model=Page[SourceFileOut])
def list_files(project_id: str, limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    project_or_404(db, project_id)
    limit, offset = page_params(limit, offset)
    q = select(SourceFile).where(SourceFile.project_id == project_id)
    total = (
        db.scalar(
            select(func.count()).select_from(SourceFile).where(SourceFile.project_id == project_id)
        )
        or 0
    )
    return {
        "items": db.scalars(
            q.order_by(SourceFile.created_at.desc()).offset(offset).limit(limit)
        ).all(),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{project_id}/files/{file_id}", response_model=SourceFileDetailOut)
def get_file(project_id: str, file_id: str, db: Session = Depends(get_db)):
    project_or_404(db, project_id)
    row = db.scalar(
        select(SourceFile).where(SourceFile.id == file_id, SourceFile.project_id == project_id)
    )
    if not row:
        raise HTTPException(
            404,
            detail={
                "code": "FILE_NOT_FOUND",
                "message": "source file does not exist",
                "details": {},
            },
        )
    return {**SourceFileOut.model_validate(row).model_dump(), "content": row.content}


@router.put("/{project_id}/files/{file_id}", response_model=SourceFileDetailOut)
def update_file(
    project_id: str,
    file_id: str,
    payload: SourceFileUpdate,
    db: Session = Depends(get_db),
):
    project = project_or_404(db, project_id)
    if not project.debug_mode:
        raise HTTPException(
            403,
            detail={
                "code": "DEBUG_MODE_REQUIRED",
                "message": "source editing is only available in debug mode",
                "details": {},
            },
        )
    row = db.scalar(
        select(SourceFile).where(SourceFile.id == file_id, SourceFile.project_id == project_id)
    )
    if not row:
        raise HTTPException(
            404,
            detail={
                "code": "FILE_NOT_FOUND",
                "message": "source file does not exist",
                "details": {},
            },
        )
    content = payload.content.encode("utf-8")
    digest = hashlib.sha256(content).hexdigest()
    if digest == row.sha256:
        return {**SourceFileOut.model_validate(row).model_dump(), "content": row.content}
    existing = db.scalar(
        select(SourceFile).where(
            SourceFile.project_id == project_id,
            SourceFile.path == row.path,
            SourceFile.sha256 == digest,
        )
    )
    if existing:
        return {**SourceFileOut.model_validate(existing).model_dump(), "content": existing.content}
    revision = _store_source_file(db, project_id, row.path, content, row.language)
    return {**SourceFileOut.model_validate(revision).model_dump(), "content": revision.content}
