from tea121.analysis import AnalysisEngine


def make_module(index):
    return {"schema_version": "1.0.0", "functions": [
        {"name": "main", "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "call", "op": "call", "callee": "write_index", "args": [index]}
        ]}]},
        {"name": "write_index", "parameters": ["index"], "entry": "e", "blocks": [{"id": "e", "instructions": [
            {"id": "b", "op": "alloca", "result": "b", "count": 4},
            {"id": "p", "op": "gep", "result": "p", "base": "b", "index": "index", "element_size": 1},
            {"id": "s", "op": "store", "pointer": "p", "width": 1}
        ]}]}
    ]}


def test_constant_argument_is_propagated_to_callee():
    assert AnalysisEngine(make_module(3)).run().alarms == []
    result = AnalysisEngine(make_module(4)).run()
    assert len(result.alarms) == 1
    assert result.alarms[0]["severity"] == "definite"


def test_recursive_call_is_conservatively_diagnosed():
    module = {"schema_version": "1.0.0", "functions": [{"name": "loop", "entry": "e", "blocks": [{"id": "e", "instructions": [{"id": "r", "op": "call", "callee": "loop", "args": []}]}]}]}
    result = AnalysisEngine(module).run()
    assert any(item["code"] == "RECURSIVE_CALL" for item in result.diagnostics)


def test_global_scalar_memory_is_preserved_across_calls():
    module = {
        "schema_version": "1.0.0",
        "globals": [{"id": "flag", "size_bytes": 4, "integer_value": 0}],
        "functions": [
            {"name": "main", "entry": "e", "blocks": [{"id": "e", "instructions": [
                {"id": "c", "op": "call", "callee": "helper", "args": []}
            ]}]},
            {"name": "helper", "entry": "e", "blocks": [
                {"id": "e", "instructions": [
                    {"id": "load", "op": "load", "pointer": "flag", "result": "condition", "width": 4},
                ], "terminator": {"op": "br", "condition": "condition", "true": "dead", "false": "safe"}},
                {"id": "dead", "instructions": [
                    {"id": "b", "op": "alloca", "result": "b", "count": 4, "element_size": 1},
                    {"id": "p", "op": "gep", "result": "p", "base": "b", "index": 4, "element_size": 1},
                    {"id": "store", "op": "store", "pointer": "p", "value": 0, "width": 1},
                ]},
                {"id": "safe", "instructions": []},
            ]},
        ],
    }
    assert AnalysisEngine(module).run().alarms == []


def test_reference_parameter_store_is_visible_to_caller():
    module = {
        "schema_version": "1.0.0",
        "functions": [
            {"name": "main", "entry": "e", "blocks": [{"id": "e", "instructions": [
                {"id": "data", "op": "alloca", "result": "data", "count": 4, "element_size": 4},
                {"id": "call", "op": "call", "callee": "set_value", "args": ["data"]},
                {"id": "load", "op": "load", "pointer": "data", "result": "index", "width": 4},
                {"id": "buf", "op": "alloca", "result": "buf", "count": 4, "element_size": 1},
                {"id": "gep", "op": "gep", "result": "p", "base": "buf", "index": "index", "element_size": 1},
                {"id": "store", "op": "store", "pointer": "p", "value": 0, "width": 1},
            ]}]},
            {"name": "set_value", "parameters": ["ref"], "entry": "e", "blocks": [{"id": "e", "instructions": [
                {"id": "store", "op": "store", "pointer": "ref", "value": 4, "width": 4},
            ], "terminator": {"op": "ret"}}]},
        ],
    }
    result = AnalysisEngine(module).run()
    assert len(result.alarms) == 1
    assert result.alarms[0]["severity"] == "definite"
