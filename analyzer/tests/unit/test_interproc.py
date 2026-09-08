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
