from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

T = TypeVar("T")


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorBody


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class Interval(BaseModel):
    lower: int | None = None
    upper: int | None = None
    is_bottom: bool = False

    @model_validator(mode="after")
    def valid(self):
        if (
            not self.is_bottom
            and self.lower is not None
            and self.upper is not None
            and self.lower > self.upper
        ):
            raise ValueError("lower must not exceed upper")
        return self


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    debug_mode: bool = False


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: str | None
    debug_mode: bool
    created_at: Any


class SourceFileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    path: str
    language: str
    sha256: str
    size_bytes: int
    created_at: Any


class SourceFileDetailOut(SourceFileOut):
    content: str


class SourceFileUpdate(BaseModel):
    content: str


class DetectorDescriptor(BaseModel):
    id: str
    version: str
    name: str
    supported_cwes: list[str]
    enabled: bool


class RulePackDescriptor(BaseModel):
    id: str
    detector_id: str
    version: str
    name: str
    supported_cwes: list[str]
    supported_families: list[str]
    supported_violation_kinds: list[str]


class RunCreate(BaseModel):
    file_ids: list[str] = Field(default_factory=list)
    detector_id: str
    rule_pack_id: str
    detector_version: str | None = None
    rule_pack_version: str | None = None
    variant: str = "single"
    mode: Literal["normal", "trace"] = "normal"
    config: dict[str, Any] = Field(default_factory=dict)
    cwe_id: str | None = None
    family: str | None = None
    violation_kind: str | None = None


class RunOut(BaseModel):
    id: str
    project_id: str
    status: str
    detector_id: str
    detector_version: str
    rule_pack_id: str
    rule_pack_version: str
    analyzer_version: str
    result_schema_version: str
    file_ids: list[str]
    variant: str
    mode: str
    config: dict[str, Any]
    progress: int
    error_message: str | None
    created_at: Any
    started_at: Any = None
    finished_at: Any = None


class AlarmOut(BaseModel):
    id: str
    run_id: str
    alarm_key: str
    detector_id: str
    detector_version: str
    rule_pack_id: str
    rule_pack_version: str
    cwe_id: str
    family: str | None = None
    violation_kind: str
    severity: Literal["definite", "possible"]
    function_name: str | None = None
    block_id: str | None = None
    instruction_id: str | None = None
    instruction_text: str | None = None
    source_file_id: str | None = None
    source_line: int | None = None
    memory_object_id: str
    object_name: str | None = None
    object_size: Interval
    offset: Interval
    access_size_bytes: int = Field(ge=0)
    safe_condition: str
    message: str
    reason: list[str]
    evidence: dict[str, Any] = Field(default_factory=dict)


class DiagnosticOut(BaseModel):
    id: str
    run_id: str
    diagnostic_id: str | None = None
    code: str
    severity: Literal["unknown_effect", "unsupported", "error"]
    message: str
    location: dict[str, Any] | None = None
    impact: str
    function_name: str | None = None
    block_id: str | None = None
    instruction_id: str | None = None
    source_file_id: str | None = None
    source_line: int | None = None


class SummaryOut(BaseModel):
    run_id: str
    status: str
    detector_id: str
    rule_pack_id: str
    alarm_count: int
    definite_count: int
    possible_count: int
    diagnostic_count: int
    unsupported_count: int
    error_count: int
    duration_ms: int | None
    functions_analyzed: int


class EvaluationCreate(BaseModel):
    dataset_name: str = Field(min_length=1)
    dataset_version: str = "1"
    detector_id: str
    rule_pack_id: str
    filter: dict[str, Any] = Field(default_factory=dict)
    cases: list[dict[str, Any]] = Field(default_factory=list)
    manifest_path: str | None = None
    max_cases: int | None = Field(default=None, ge=1, le=10000)


class EvaluationOut(BaseModel):
    id: str
    project_id: str
    dataset_name: str
    dataset_version: str
    detector_id: str
    detector_version: str
    rule_pack_id: str
    rule_pack_version: str
    status: str
    filter: dict[str, Any]
    summary: dict[str, Any]
    created_at: Any
    started_at: Any = None
    finished_at: Any = None


class EvaluationCaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    evaluation_id: str
    case_name: str
    cwe_id: str | None
    family: str | None
    bad_run_id: str | None
    good_run_id: str | None
    bad_outcome: str
    good_outcome: str
    classification: str | None


class MatrixOut(BaseModel):
    detector_id: str
    rule_pack_id: str
    cwe_id: str | None = None
    family: str | None = None
    correct: int
    false_positive: int
    false_negative: int
    inverted: int
    unsupported: int
    error: int
    total: int
    bad_recall: float | None = None
    good_specificity: float | None = None
    file_accuracy: float | None = None
