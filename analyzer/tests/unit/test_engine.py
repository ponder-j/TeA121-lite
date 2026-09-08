from tea121.analysis import AnalysisEngine


def module_with_access(index):
    return {"schema_version": "1.0.0", "functions": [{"name": "demo", "entry": "entry", "blocks": [{"id": "entry", "instructions": [{"id": "a", "op": "alloca", "result": "buf", "count": 4, "element_size": 1}, {"id": "p", "op": "gep", "result": "ptr", "base": "buf", "index": index, "element_size": 1}, {"id": "s", "op": "store", "pointer": "ptr", "width": 1}]}]}]}


def test_bounds_alarm_for_constant_oob():
    result = AnalysisEngine(module_with_access(4)).run()
    assert len(result.alarms) == 1
    assert result.alarms[0]["severity"] == "definite"


def test_safe_access_is_silent():
    result = AnalysisEngine(module_with_access(3)).run()
    assert result.alarms == []


def test_unknown_call_is_diagnostic():
    module = module_with_access(0)
    module["functions"][0]["blocks"][0]["instructions"].append({"id": "c", "op": "call", "callee": "external", "args": ["buf"]})
    result = AnalysisEngine(module).run()
    assert any(item["code"] == "UNKNOWN_CALL" for item in result.diagnostics)


def test_known_observational_call_does_not_escape_pointer():
    module = module_with_access(3)
    module["functions"][0]["blocks"][0]["instructions"].append({"id": "c", "op": "call", "callee": "printLine", "args": ["buf"]})
    result = AnalysisEngine(module).run()
    assert result.alarms == []
    assert not any(item["code"] == "UNKNOWN_CALL" for item in result.diagnostics)
