from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


def uid() -> str:
    return str(uuid4())


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    debug_mode: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=now)
    files: Mapped[list["SourceFile"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    runs: Mapped[list["AnalysisRun"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    evaluations: Mapped[list["Evaluation"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class SourceFile(Base):
    __tablename__ = "source_files"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    language: Mapped[str] = mapped_column(String(30), default="c")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=now)
    project: Mapped[Project] = relationship(back_populates="files")
    __table_args__ = (
        UniqueConstraint("project_id", "path", "sha256", name="uq_source_file_version"),
    )


class Detector(Base):
    __tablename__ = "detectors"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    supported_cwes_json: Mapped[str] = mapped_column(Text, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_packs: Mapped[list["RulePack"]] = relationship(
        back_populates="detector", cascade="all, delete-orphan"
    )


class RulePack(Base):
    __tablename__ = "rule_packs"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    detector_id: Mapped[str] = mapped_column(
        ForeignKey("detectors.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    supported_cwes_json: Mapped[str] = mapped_column(Text, default="[]")
    supported_families_json: Mapped[str] = mapped_column(Text, default="[]")
    supported_violation_kinds_json: Mapped[str] = mapped_column(Text, default="[]")
    detector: Mapped[Detector] = relationship(back_populates="rule_packs")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="queued")
    detector_id: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(40), nullable=False)
    rule_pack_id: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_pack_version: Mapped[str] = mapped_column(String(40), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(40), nullable=False)
    result_schema_version: Mapped[str] = mapped_column(String(40), default="1.0.0")
    variant: Mapped[str] = mapped_column(String(30), default="single")
    mode: Mapped[str] = mapped_column(String(20), default="normal")
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    file_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    error_message: Mapped[str | None] = mapped_column(Text)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(default=now)
    started_at: Mapped[datetime | None] = mapped_column()
    finished_at: Mapped[datetime | None] = mapped_column()
    project: Mapped[Project] = relationship(back_populates="runs")
    alarms: Mapped[list["Alarm"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    diagnostics: Mapped[list["DiagnosticRow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list["RunArtifact"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    cfg_nodes: Mapped[list["CfgNode"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    cfg_edges: Mapped[list["CfgEdge"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    trace_events: Mapped[list["TraceEvent"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class RunFile(Base):
    __tablename__ = "run_files"
    run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), primary_key=True
    )
    source_file_id: Mapped[str] = mapped_column(
        ForeignKey("source_files.id", ondelete="CASCADE"), primary_key=True
    )
    variant: Mapped[str] = mapped_column(String(30), default="single")


class Alarm(Base):
    __tablename__ = "alarms"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    alarm_key: Mapped[str] = mapped_column(String(500), nullable=False)
    detector_id: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(40), nullable=False)
    rule_pack_id: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_pack_version: Mapped[str] = mapped_column(String(40), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(30), nullable=False)
    family: Mapped[str | None] = mapped_column(String(100))
    violation_kind: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    function_name: Mapped[str | None] = mapped_column(String(200))
    block_id: Mapped[str | None] = mapped_column(String(200))
    instruction_id: Mapped[str | None] = mapped_column(String(200))
    instruction_text: Mapped[str | None] = mapped_column(Text)
    source_file_id: Mapped[str | None] = mapped_column(String(36))
    source_line: Mapped[int | None] = mapped_column(Integer)
    memory_object_id: Mapped[str] = mapped_column(String(300), nullable=False)
    object_name: Mapped[str | None] = mapped_column(String(200))
    object_size_lower: Mapped[int | None] = mapped_column(Integer)
    object_size_upper: Mapped[int | None] = mapped_column(Integer)
    offset_lower: Mapped[int | None] = mapped_column(Integer)
    offset_upper: Mapped[int | None] = mapped_column(Integer)
    access_size: Mapped[int] = mapped_column(Integer, nullable=False)
    safe_condition: Mapped[str] = mapped_column(Text, default="")
    message: Mapped[str] = mapped_column(Text, default="")
    reason_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(default=now)
    run: Mapped[AnalysisRun] = relationship(back_populates="alarms")
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "detector_id",
            "rule_pack_id",
            "instruction_id",
            "memory_object_id",
            "violation_kind",
            name="uq_alarm_identity",
        ),
        CheckConstraint("severity IN ('definite','possible')", name="ck_alarm_severity"),
    )


class DiagnosticRow(Base):
    __tablename__ = "diagnostics"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    diagnostic_id: Mapped[str | None] = mapped_column(String(200))
    code: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    location_json: Mapped[str] = mapped_column(Text, default="null")
    function_name: Mapped[str | None] = mapped_column(String(200))
    block_id: Mapped[str | None] = mapped_column(String(200))
    instruction_id: Mapped[str | None] = mapped_column(String(200))
    source_file_id: Mapped[str | None] = mapped_column(String(36))
    source_line: Mapped[int | None] = mapped_column(Integer)
    run: Mapped[AnalysisRun] = relationship(back_populates="diagnostics")
    __table_args__ = (
        CheckConstraint(
            "severity IN ('unknown_effect','unsupported','error')",
            name="ck_diag_severity",
        ),
    )


class RunArtifact(Base):
    __tablename__ = "run_artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    source_file_id: Mapped[str | None] = mapped_column(String(36))
    function_name: Mapped[str | None] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    run: Mapped[AnalysisRun] = relationship(back_populates="artifacts")


class CfgNode(Base):
    __tablename__ = "cfg_nodes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    function_name: Mapped[str] = mapped_column(String(200), default="")
    block_id: Mapped[str] = mapped_column(String(200), nullable=False)
    label: Mapped[str | None] = mapped_column(String(200))
    # Presentation metadata (IR lines, source locations, and terminator) is
    # optional so results produced by older analyzer versions remain readable.
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    entry_state_json: Mapped[str] = mapped_column(Text, default="{}")
    exit_state_json: Mapped[str] = mapped_column(Text, default="{}")
    run: Mapped[AnalysisRun] = relationship(back_populates="cfg_nodes")


class CfgEdge(Base):
    __tablename__ = "cfg_edges"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    function_name: Mapped[str] = mapped_column(String(200), default="")
    source_block: Mapped[str] = mapped_column(String(200), nullable=False)
    target_block: Mapped[str] = mapped_column(String(200), nullable=False)
    condition: Mapped[str | None] = mapped_column(String(300))
    polarity: Mapped[str | None] = mapped_column(String(10))
    run: Mapped[AnalysisRun] = relationship(back_populates="cfg_edges")


class TraceEvent(Base):
    __tablename__ = "trace_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    sequence_no: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    function_name: Mapped[str | None] = mapped_column(String(200))
    block_id: Mapped[str | None] = mapped_column(String(200))
    instruction_id: Mapped[str | None] = mapped_column(String(200))
    before_state_json: Mapped[str] = mapped_column(Text, default="{}")
    after_state_json: Mapped[str] = mapped_column(Text, default="{}")
    explanation: Mapped[str | None] = mapped_column(Text)
    run: Mapped[AnalysisRun] = relationship(back_populates="trace_events")
    __table_args__ = (UniqueConstraint("run_id", "sequence_no", name="uq_trace_sequence"),)


class Evaluation(Base):
    __tablename__ = "evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    dataset_name: Mapped[str] = mapped_column(String(200), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(100), nullable=False)
    detector_id: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(40), nullable=False)
    rule_pack_id: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_pack_version: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    filter_json: Mapped[str] = mapped_column(Text, default="{}")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(default=now)
    started_at: Mapped[datetime | None] = mapped_column()
    finished_at: Mapped[datetime | None] = mapped_column()
    project: Mapped[Project] = relationship(back_populates="evaluations")
    cases: Mapped[list["EvaluationCase"]] = relationship(
        back_populates="evaluation", cascade="all, delete-orphan"
    )


class EvaluationCase(Base):
    __tablename__ = "evaluation_cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    evaluation_id: Mapped[str] = mapped_column(
        ForeignKey("evaluations.id", ondelete="CASCADE"), index=True
    )
    case_name: Mapped[str] = mapped_column(String(300), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(30))
    family: Mapped[str | None] = mapped_column(String(100))
    bad_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL")
    )
    good_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL")
    )
    bad_outcome: Mapped[str] = mapped_column(String(20), default="clean")
    good_outcome: Mapped[str] = mapped_column(String(20), default="clean")
    classification: Mapped[str | None] = mapped_column(String(30))
    evaluation: Mapped[Evaluation] = relationship(back_populates="cases")


class FileAuditRecord(Base):
    __tablename__ = "file_audit_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(default=now)


Index("ix_run_files_source", RunFile.source_file_id)
