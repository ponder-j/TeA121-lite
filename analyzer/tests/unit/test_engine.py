from tea121.analysis import AnalysisConfig, AnalysisEngine


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


def test_cfg_contains_presentable_nodes_branches_and_loop_back_edge():
    module = {
        "schema_version": "1.0.0",
        "functions": [
            {
                "name": "loop_demo",
                "entry": "bb0",
                "blocks": [
                    {
                        "id": "bb0",
                        "instructions": [
                            {
                                "id": "init",
                                "op": "const",
                                "result": "i",
                                "value": 0,
                                "location": {"file": "loop.c", "line": 3, "column": 5},
                            }
                        ],
                        "terminator": {"op": "br", "target": "bb1"},
                    },
                    {
                        "id": "bb1",
                        "instructions": [
                            {
                                "id": "cmp",
                                "op": "icmp",
                                "result": "keep_going",
                                "predicate": "slt",
                                "left": "i",
                                "right": 3,
                                "location": {"file": "loop.c", "line": 4, "column": 12},
                            }
                        ],
                        "terminator": {
                            "op": "br",
                            "condition": "keep_going",
                            "true": "bb2",
                            "false": "bb3",
                        },
                    },
                    {
                        "id": "bb2",
                        "instructions": [
                            {
                                "id": "inc",
                                "op": "add",
                                "result": "i",
                                "left": "i",
                                "right": 1,
                                "location": {"file": "loop.c", "line": 5, "column": 9},
                            }
                        ],
                        "terminator": {"op": "br", "target": "bb1"},
                    },
                    {"id": "bb3", "instructions": [], "terminator": {"op": "ret"}},
                ],
            }
        ],
    }

    result = AnalysisEngine(module).run()

    assert [node["display_index"] for node in result.cfg_nodes] == [1, 2, 3, 4]
    assert result.cfg_nodes[1]["instructions"][0]["id"] == "cmp"
    assert result.cfg_nodes[1]["source_lines"] == [4]
    assert result.cfg_nodes[1]["terminator"]["true"] == "bb2"
    assert {
        (edge["source_block"], edge["target_block"], edge["polarity"])
        for edge in result.cfg
    } >= {
        ("bb1", "bb2", "true"),
        ("bb1", "bb3", "false"),
        ("bb2", "bb1", None),
    }


def module_with_loop(bound):
    """MiniIR equivalent of ``for (i = 0; i <= bound; i++) buffer[i]``."""
    return {
        "schema_version": "1.0.0",
        "functions": [
            {
                "name": "main",
                "entry": "bb0",
                "blocks": [
                    {
                        "id": "bb0",
                        "instructions": [{"id": "buf", "op": "alloca", "result": "buf", "count": 10, "element_size": 4}],
                        "terminator": {"op": "br", "target": "bb1"},
                    },
                    {
                        "id": "bb1",
                        "instructions": [
                            {
                                "id": "phi",
                                "op": "phi",
                                "result": "i",
                                "incoming": [{"value": 0, "block": "bb0"}, {"value": "inc", "block": "bb2"}],
                            },
                            {"id": "cmp", "op": "icmp", "result": "cond", "predicate": "sle", "left": "i", "right": bound},
                        ],
                        "terminator": {
                            "op": "br",
                            "condition": {"op": "icmp", "predicate": "sle", "left": "i", "right": bound},
                            "true": "bb2",
                            "false": "bb3",
                        },
                    },
                    {
                        "id": "bb2",
                        "instructions": [
                            {"id": "gep", "op": "gep", "result": "ptr", "base": "buf", "index": "i", "element_size": 4},
                            {"id": "store", "op": "store", "pointer": "ptr", "width": 4},
                            {"id": "inc", "op": "add", "result": "inc", "left": "i", "right": 1},
                        ],
                        "terminator": {"op": "br", "target": "bb1"},
                    },
                    {"id": "bb3", "instructions": [], "terminator": {"op": "ret", "value": 0}},
                ],
            }
        ],
    }


def test_safe_loop_is_silent_after_branch_refinement_and_narrowing():
    result = AnalysisEngine(module_with_loop(9)).run()
    assert result.alarms == []
    body = next(state for state in result.block_states if state["block_id"] == "bb2")
    assert body["entry_state"]["integers"]["i"] == {"lower": 0, "upper": 9, "is_bottom": False}


def test_unsafe_loop_keeps_possible_alarm():
    result = AnalysisEngine(module_with_loop(10)).run()
    assert len(result.alarms) == 1
    assert result.alarms[0]["severity"] == "possible"
    assert result.alarms[0]["offset"] == {"lower": 0, "upper": 40, "is_bottom": False}


def test_false_branch_refines_guard_before_access():
    module = {
        "schema_version": "1.0.0",
        "functions": [
            {
                "name": "main",
                "entry": "entry",
                "blocks": [
                    {
                        "id": "entry",
                        "instructions": [
                            {"id": "buf", "op": "alloca", "result": "buf", "count": 10, "element_size": 4},
                            {"id": "lo", "op": "const", "result": "lo", "value": 0},
                            {"id": "hi", "op": "const", "result": "hi", "value": 10},
                            {"id": "i", "op": "select", "result": "i", "true_value": "lo", "false_value": "hi"},
                            {"id": "cmp", "op": "icmp", "result": "cond", "predicate": "sge", "left": "i", "right": 10},
                        ],
                        "terminator": {
                            "op": "br",
                            "condition": {"op": "icmp", "predicate": "sge", "left": "i", "right": 10},
                            "true": "safe",
                            "false": "write",
                        },
                    },
                    {"id": "safe", "instructions": [], "terminator": {"op": "ret"}},
                    {
                        "id": "write",
                        "instructions": [
                            {"id": "gep", "op": "gep", "result": "ptr", "base": "buf", "index": "i", "element_size": 4},
                            {"id": "store", "op": "store", "pointer": "ptr", "width": 4},
                        ],
                        "terminator": {"op": "ret"},
                    },
                ],
            }
        ],
    }

    result = AnalysisEngine(module).run()
    assert result.alarms == []
    write = next(state for state in result.block_states if state["block_id"] == "write")
    assert write["entry_state"]["integers"]["i"] == {"lower": 0, "upper": 9, "is_bottom": False}


def test_constant_false_branch_is_unreachable():
    module = {
        "schema_version": "1.0.0",
        "functions": [
            {
                "name": "main",
                "entry": "entry",
                "blocks": [
                    {
                        "id": "entry",
                        "instructions": [{"id": "buf", "op": "alloca", "result": "buf", "count": 4, "element_size": 1}],
                        "terminator": {
                            "op": "br",
                            "condition": {"op": "icmp", "predicate": "sge", "left": 10, "right": 10},
                            "true": "safe",
                            "false": "bad",
                        },
                    },
                    {"id": "safe", "instructions": [], "terminator": {"op": "ret"}},
                    {
                        "id": "bad",
                        "instructions": [
                            {"id": "gep", "op": "gep", "result": "ptr", "base": "buf", "index": 4, "element_size": 1},
                            {"id": "store", "op": "store", "pointer": "ptr", "width": 1},
                        ],
                        "terminator": {"op": "ret"},
                    },
                ],
            }
        ],
    }

    result = AnalysisEngine(module).run()
    assert result.alarms == []
    bad = next(state for state in result.block_states if state["block_id"] == "bad")
    assert bad["entry_state"]["reachable"] is False


def module_with_char_increment(start):
    """MiniIR equivalent of ``char ch = start; ch++;``."""
    return {
        "schema_version": "1.0.0",
        "functions": [
            {
                "name": "main",
                "entry": "entry",
                "blocks": [
                    {
                        "id": "entry",
                        "instructions": [
                            {"id": "ch", "op": "alloca", "result": "ch", "count": 1, "element_size": 1},
                            {"id": "st0", "op": "store", "pointer": "ch", "value": start, "width": 1},
                            {"id": "ld", "op": "load", "pointer": "ch", "result": "v", "width": 1},
                            {"id": "inc", "op": "add", "result": "r", "left": "v", "right": 1, "bits": 8},
                            {"id": "st1", "op": "store", "pointer": "ch", "value": "r", "width": 1},
                        ],
                    }
                ],
            }
        ],
    }


def test_char_increment_overflow_is_detected_as_cwe190():
    result = AnalysisEngine(module_with_char_increment(127)).run()
    assert len(result.alarms) == 1
    alarm = result.alarms[0]
    assert alarm["violation_kind"] == "integer_overflow"
    assert alarm["cwe_id"] == "CWE-190"
    assert alarm["severity"] == "definite"
    assert alarm["offset"] == {"lower": 128, "upper": 128, "is_bottom": False}
    assert alarm["object_size"] == {"lower": -128, "upper": 127, "is_bottom": False}


def test_char_increment_in_range_stays_silent():
    assert AnalysisEngine(module_with_char_increment(126)).run().alarms == []


def test_integer_overflow_can_be_disabled():
    engine = AnalysisEngine(module_with_char_increment(127), AnalysisConfig(check_integer_overflow=False))
    assert engine.run().alarms == []


def test_possible_integer_overflow_is_reported():
    module = {
        "schema_version": "1.0.0",
        "functions": [
            {
                "name": "main",
                "entry": "entry",
                "blocks": [
                    {
                        "id": "entry",
                        "instructions": [
                            {"id": "lo", "op": "const", "result": "a", "value": 100},
                            {"id": "hi", "op": "const", "result": "b", "value": 200},
                            {"id": "sel", "op": "select", "result": "v", "true_value": "a", "false_value": "b"},
                            {"id": "inc", "op": "add", "result": "r", "left": "v", "right": 1, "bits": 8},
                        ],
                    }
                ],
            }
        ],
    }
    result = AnalysisEngine(module).run()
    assert len(result.alarms) == 1
    assert result.alarms[0]["severity"] == "possible"


def test_narrowing_assignment_overflow_is_detected():
    """``char c = 127; c = c + 1;`` lowers to a wide add plus an i8 store."""
    module = {
        "schema_version": "1.0.0",
        "functions": [
            {
                "name": "main",
                "entry": "entry",
                "blocks": [
                    {
                        "id": "entry",
                        "instructions": [
                            {"id": "c", "op": "alloca", "result": "c", "count": 1, "element_size": 1},
                            {"id": "init", "op": "store", "pointer": "c", "value": 127, "width": 1},
                            {"id": "read", "op": "load", "pointer": "c", "result": "v", "width": 1},
                            {"id": "add", "op": "add", "result": "w", "left": "v", "right": 1, "bits": 32},
                            {"id": "trunc", "op": "copy", "result": "t", "value": "w"},
                            {"id": "write", "op": "store", "pointer": "c", "value": "t", "width": 1},
                        ],
                    }
                ],
            }
        ],
    }
    result = AnalysisEngine(module).run()
    assert len(result.alarms) == 1
    alarm = result.alarms[0]
    assert alarm["cwe_id"] == "CWE-190"
    assert alarm["violation_kind"] == "integer_overflow"
    assert alarm["instruction_id"] == "write"
    assert alarm["severity"] == "definite"
