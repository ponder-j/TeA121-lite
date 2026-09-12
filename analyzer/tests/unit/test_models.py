from tea121.analysis import LibraryModelRegistry
from tea121.analysis import AnalysisEngine


def test_library_registry_is_replaceable():
    registry = LibraryModelRegistry().with_enabled(("memcpy", "strcpy"))
    assert registry.supports("memcpy")
    assert not registry.supports("memset")


def test_known_global_string_makes_strcpy_precise():
    module = {
        "schema_version": "1.0.0",
        "globals": [{"id": "literal", "size_bytes": 5, "string_length": 4}],
        "functions": [{"name": "copy", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 5},
            {"id": "c", "op": "call", "callee": "strcpy", "args": ["b", "literal"]}
        ]}]}]
    }
    result = AnalysisEngine(module).run()
    assert result.alarms == []


def test_unknown_global_string_is_not_assumed_safe():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "copy", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 5},
            {"id": "c", "op": "call", "callee": "strcpy", "args": ["b", "unknown_source"]}
        ]}]}]
    }
    result = AnalysisEngine(module).run()
    assert result.alarms and result.alarms[0]["severity"] == "possible"
    assert any(item["code"] == "UNKNOWN_STRING_LENGTH" for item in result.diagnostics)


def test_memcpy_constant_length_reports_definite_overflow():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "copy", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 4},
            {"id": "c", "op": "call", "callee": "memcpy", "args": ["b", "source", 5]}
        ]}]}]
    }
    result = AnalysisEngine(module).run()
    assert result.alarms and result.alarms[0]["severity"] == "definite"


def test_fgets_uses_count_as_bounded_write_width():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "read", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 8},
            {"id": "r", "op": "call", "callee": "fgets", "args": ["b", 8, "stdin"], "result": "r"},
        ]}]}],
    }
    result = AnalysisEngine(module).run()
    assert result.alarms == []
    assert not any(item["code"] == "UNKNOWN_INPUT_LENGTH" for item in result.diagnostics)


def test_recv_reports_possible_overflow_and_propagates_return_range():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "read", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 4},
            {"id": "r", "op": "call", "callee": "recv", "args": ["sock", "b", 5, 0], "result": "n"},
        ]}]}],
    }
    result = AnalysisEngine(module).run()
    assert result.alarms and result.alarms[0]["severity"] == "definite"
    assert result.block_states[0]["exit_state"]["integers"]["n"] == {"lower": -1, "upper": 5, "is_bottom": False}


def test_scalar_pure_call_result_is_abstracted():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "read", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "r", "op": "call", "callee": "atoi", "args": ["text"], "result": "value"},
        ]}]}],
    }
    result = AnalysisEngine(module).run()
    assert result.block_states[0]["exit_state"]["integers"]["value"] == {"lower": None, "upper": None, "is_bottom": False}


def test_store_load_preserves_scalar_value():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "memory", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 1, "element_size": 4},
            {"id": "s", "op": "store", "pointer": "b", "value": 7, "width": 4},
            {"id": "l", "op": "load", "pointer": "b", "result": "value", "width": 4},
        ]}]}],
    }
    result = AnalysisEngine(module).run()
    assert result.block_states[0]["exit_state"]["integers"]["value"] == {"lower": 7, "upper": 7, "is_bottom": False}


def test_fscanf_integer_format_is_bounded_but_string_format_is_unknown():
    integer_module = {
        "schema_version": "1.0.0",
        "globals": [{"id": "fmt", "size_bytes": 3, "string_length": 2, "string_value": "%d"}],
        "functions": [{"name": "read", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 4},
            {"id": "r", "op": "call", "callee": "fscanf", "args": ["stdin", "fmt", "b"], "result": "r"},
        ]}]}],
    }
    integer_result = AnalysisEngine(integer_module).run()
    assert integer_result.alarms == []
    assert not any(item["code"] == "UNKNOWN_INPUT_LENGTH" for item in integer_result.diagnostics)

    string_module = dict(integer_module)
    string_module["globals"] = [{"id": "fmt", "size_bytes": 3, "string_length": 2, "string_value": "%s"}]
    string_result = AnalysisEngine(string_module).run()
    assert any(item["code"] == "UNKNOWN_INPUT_LENGTH" for item in string_result.diagnostics)


def test_snprintf_count_is_checked_in_bytes():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "format", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 50},
            {"id": "c", "op": "call", "callee": "snprintf", "args": ["b", 100, "fmt", "source"]},
        ]}]}],
    }
    result = AnalysisEngine(module).run()
    assert result.alarms and result.alarms[0]["severity"] == "definite"


def test_swprintf_count_is_scaled_to_wide_bytes():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "format", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 50, "element_size": 4},
            {"id": "c", "op": "call", "callee": "swprintf", "args": ["b", 51, "fmt", "source"]},
        ]}]}],
    }
    result = AnalysisEngine(module).run()
    assert result.alarms and result.alarms[0]["severity"] == "definite"


def test_local_nul_store_enables_wide_string_overflow_check():
    module = {
        "schema_version": "1.0.0",
        "functions": [{"name": "copy", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "src", "op": "alloca", "result": "src", "count": 400, "element_size": 1},
            {"id": "tail", "op": "gep", "result": "tail", "base": "src", "index": 99, "element_size": 4},
            {"id": "nul", "op": "store", "pointer": "tail", "value": 0, "width": 4},
            {"id": "dst", "op": "alloca", "result": "dst", "count": 50, "element_size": 4},
            {"id": "c", "op": "call", "callee": "wcscpy", "args": ["dst", "src"]},
        ]}]}],
    }
    result = AnalysisEngine(module).run()
    assert result.alarms and result.alarms[0]["severity"] == "definite"
    assert not any(item["code"] == "UNKNOWN_STRING_LENGTH" for item in result.diagnostics)


def test_wmemset_width_is_scaled_to_wide_bytes():
    safe = {
        "schema_version": "1.0.0",
        "functions": [{"name": "fill", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 50, "element_size": 4},
            {"id": "c", "op": "call", "callee": "wmemset", "args": ["b", 65, 50]},
        ]}]}],
    }
    assert AnalysisEngine(safe).run().alarms == []
    unsafe = dict(safe)
    unsafe["functions"] = [{"name": "fill", "entry": "e", "blocks": [{"id": "e", "instructions": [
        {"id": "b", "op": "alloca", "result": "b", "count": 50, "element_size": 4},
        {"id": "c", "op": "call", "callee": "wmemset", "args": ["b", 65, 51]},
    ]}]}]
    result = AnalysisEngine(unsafe).run()
    assert result.alarms and result.alarms[0]["severity"] == "definite"


def test_aggregate_gep_bound_distinguishes_struct_field_from_whole_struct():
    base = {
        "schema_version": "1.0.0",
        "globals": [{"id": "src", "size_bytes": 80}],
        "functions": [{"name": "copy", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "s", "op": "alloca", "result": "s", "count": 1, "element_size": 80},
            {"id": "field", "op": "gep", "result": "field", "base": "s", "index": 0, "element_size": 1, "bound_size": 64},
            {"id": "element", "op": "gep", "result": "element", "base": "field", "index": 0, "element_size": 1},
            {"id": "c", "op": "call", "callee": "memcpy", "args": ["element", "src", 80]},
        ]}]}],
    }
    bad = AnalysisEngine(base).run()
    assert bad.alarms and bad.alarms[0]["severity"] == "definite"

    safe = dict(base)
    safe["functions"] = [{"name": "copy", "entry": "e", "blocks": [{"id": "e", "instructions": [
        {"id": "s", "op": "alloca", "result": "s", "count": 1, "element_size": 80},
        {"id": "field", "op": "gep", "result": "field", "base": "s", "index": 0, "element_size": 1, "bound_size": 64},
        {"id": "element", "op": "gep", "result": "element", "base": "field", "index": 0, "element_size": 1},
        {"id": "c", "op": "call", "callee": "memcpy", "args": ["element", "src", 64]},
    ]}]}]
    assert AnalysisEngine(safe).run().alarms == []
