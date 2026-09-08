from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from evaluate_juliet import _summary, classify_pair, classify_result, discover_cases


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
