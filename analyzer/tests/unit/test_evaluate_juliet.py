from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from evaluate_juliet import _summary, classify_pair, classify_result, compact_analyzer_result, discover_cases


def touch_case(root: Path, *names: str) -> None:
    for name in names:
        path = root / name
        path.write_text("", encoding="utf-8")


def test_discover_single_and_split_variants(tmp_path):
    touch_case(
        tmp_path,
        "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c",
        "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_51a.c",
        "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_51b.c",
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_81a.cpp",
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_81_bad.cpp",
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_81_goodG2B.cpp",
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_81_goodB2G.cpp",
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_81.h",
    )
    cases = discover_cases(tmp_path)
    by_name = {case.case_name: case for case in cases}
    assert len(cases) == 3
    assert len(by_name["CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01"].bad_files) == 1
    split = by_name["CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_51"]
    assert len(split.bad_files) == len(split.good_files) == 2
    cpp = by_name["CWE121_Stack_Based_Buffer_Overflow__CWE135_81"]
    assert {path.name for path in cpp.bad_files} == {
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_81a.cpp",
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_81_bad.cpp",
    }
    assert len(cpp.good_files) == 3
    assert any(path.suffix == ".h" for path in cpp.files)


def test_outcome_classification_keeps_unknown_as_unsupported():
    assert classify_result({"status": "succeeded", "alarms": [], "diagnostics": []}) == "clean"
    assert classify_result({"status": "succeeded", "alarms": [{"severity": "definite"}], "diagnostics": []}) == "alarm"
    assert classify_result({"status": "succeeded", "alarms": [], "diagnostics": [{"severity": "unknown_effect"}]}) == "unsupported"
    assert classify_result({"status": "error", "alarms": [], "diagnostics": []}) == "error"


def test_pair_matrix_and_conservative_summary():
    assert classify_pair("alarm", "clean") == "correct"
    assert classify_pair("clean", "alarm") == "inverted"
    assert classify_pair("alarm", "alarm") == "false_positive"
    assert classify_pair("clean", "clean") == "false_negative"
    assert classify_pair("alarm", "unsupported") == "unsupported"
    assert classify_pair("error", "clean") == "error"
    cases = [
        {"bad": {"outcome": "alarm"}, "good": {"outcome": "clean"}, "classification": "correct"},
        {"bad": {"outcome": "clean"}, "good": {"outcome": "clean"}, "classification": "false_negative"},
        {"bad": {"outcome": "alarm"}, "good": {"outcome": "unsupported"}, "classification": "unsupported"},
    ]
    summary = _summary(cases)
    assert summary["total_cases"] == 3
    assert summary["valid_pairs"] == 2
    assert summary["side_outcomes"] == {"alarm": 2, "clean": 3, "unsupported": 1, "error": 0}
    assert summary["pair_classification"]["correct"] == 1
    assert summary["effective_bad_recall"] == 0.5
    assert summary["effective_good_silence_rate"] == 1.0
    assert summary["conservative_pair_accuracy"] == summary["pair_accuracy"] == 0.333333


def test_batch_suite_discovery_and_case_collection(tmp_path):
    from evaluate_cwe121 import collect_cases, discover_suites

    cwe = tmp_path / "testcases" / "CWE121_Stack_Based_Buffer_Overflow"
    for suite in ("s01", "s02", "s03"):
        directory = cwe / suite
        directory.mkdir(parents=True)
        touch_case(directory, f"CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_{suite[1:]}.c")

    suites = discover_suites(tmp_path / "testcases")
    assert [suite.name for suite in suites] == ["s01", "s02", "s03"]
    assert [suite.name for suite in discover_suites(cwe, ["s02"])] == ["s02"]
    collected = collect_cases(suites, "02")
    assert [(suite, case.variant) for suite, case in collected] == [("s02", "02")]


def test_batch_summary_reports_binary_confusion_and_suites():
    from evaluate_cwe121 import score_summary

    def case(suite: str, bad: str, good: str) -> dict:
        return {
            "suite": suite,
            "family": "family",
            "variant": "01",
            "bad": {"outcome": bad},
            "good": {"outcome": good},
            "classification": classify_pair(bad, good),
        }

    cases = [
        case("s01", "alarm", "clean"),
        case("s01", "clean", "clean"),
        case("s02", "alarm", "alarm"),
        case("s02", "unsupported", "unsupported"),
    ]
    summary = score_summary(cases)
    assert summary["binary_confusion"] == {
        "tp": 2,
        "fp": 1,
        "fn": 1,
        "tn": 2,
        "unsupported": 2,
        "error": 0,
    }
    assert summary["binary_metrics"]["supported_recall"] == 0.666667
    assert summary["binary_metrics"]["supported_specificity"] == 0.666667
    assert summary["by_suite"]["s01"]["binary_confusion"]["tp"] == 1
    assert summary["by_suite"]["s02"]["binary_confusion"]["unsupported"] == 2


def test_compact_analyzer_result_keeps_evidence_and_drops_bulk():
    result = {
        "status": "succeeded",
        "summary": {"alarm_count": 1},
        "alarms": [{
            "severity": "possible",
            "cwe_id": "CWE-121",
            "violation_kind": "buffer_overflow",
            "message": "out of bounds",
            "instruction_id": "store",
            "location": {"line": 7},
        }],
        "diagnostics": [{
            "severity": "unknown_effect",
            "code": "UNKNOWN_CALL",
            "message": "unknown",
        }],
        "cfg": [{"bulk": True}],
        "block_states": [{"bulk": True}],
        "trace": [{"bulk": True}],
    }
    compact = compact_analyzer_result(result)
    assert compact["status"] == "succeeded"
    assert compact["alarms"][0]["instruction_id"] == "store"
    assert compact["diagnostics"][0]["code"] == "UNKNOWN_CALL"
    assert compact["truncated"] == {"alarms": 0, "diagnostics": 0}
    assert "cfg" not in compact and "block_states" not in compact and "trace" not in compact
