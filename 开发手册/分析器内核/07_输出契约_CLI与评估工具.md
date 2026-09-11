# 07 输出契约、CLI 与评估工具

> 前置：`00~06`。本文讲"分析结果长什么样、怎么被 CLI 拼出来、Juliet 评估怎么用四态打分"。
> 对应源码：
> - `analyzer/src/tea121/report/result.py`（结果组装与文本渲染）
> - `analyzer/src/tea121/cli.py`（命令行）
> - `contracts/schemas/analyzer-result.schema.json`（结果契约）
> - `analyzer/tools/evaluate_juliet.py`（评估 runner）

---

## 1. 结果 JSON 解剖（`report/result.py::build_result`）

`build_result(output, ...)` 把 `AnalysisOutput`（alarms/diagnostics/cfg/block_states/trace）
包成一个版本化信封：

```jsonc
{
  "schema_version": "1.0.0",        // 结果 schema 版本（非 MiniIR 版本）
  "run_id": "<uuid>",
  "analyzer_version": "0.1.0",
  "detector_id": "stack-bounds",    // 检测器身份，写死
  "detector_version": "0.1.0",
  "rule_pack_id": "cwe121-core",    // 规则包身份，写死
  "rule_pack_version": "0.1.0",
  "status": "succeeded",            // succeeded | unsupported | error
  "summary": {"alarm_count": 1, "diagnostic_count": 0,
              "unsupported_count": 0, "error_count": 0},
  "inputs": [{"path": "..."}],
  "config": {"mode": "normal", "widen_after": 3},
  "alarms": [ ... ],                // 见 04 §7 字段
  "diagnostics": [ ... ],
  "artifacts": [],                  // .c/.ll 输入时含 normalized_ir + sha256（frontend 填）
  "cfg": [ {source_block, target_block, condition, polarity}, ... ],
  "block_states": [ {function_name, block_id, entry_state, exit_state}, ... ],
  "trace": [ {sequence_no, event_type, ..., before_state, after_state}, ... ],
  "generated_at": "<UTC ISO 时间>"
}
```

### status 是怎么定的（result.py 8-11 行）

```python
status = "error" if 任一诊断 severity=="error"
    else "unsupported" if 任一诊断 severity=="unsupported"
    else "succeeded"
```

注意：**`unknown_effect` 诊断不会把 status 变成 unsupported**——所以"指针可能逃逸"的
unknown_effect 用例 status 仍是 succeeded，但 JSON 里带着诊断。**评估端**在分类时会把
任何 unknown_effect/unsupported 诊断都判成 unsupported（§4），所以这不会污染 clean 统计。

### 输出稳定性

`alarm_key`、诊断顺序、block_states/trace 顺序都来自确定性的 worklist 遍历；
UUID 与时间只在信封层（run_id/generated_at），保证"同一输入重复运行语义结果一致"
（任务书 5.3 的要求）。

---

## 2. 文本渲染（`result_to_text`）

一行状态 + 每个 alarm 一行 + 每个诊断一行，**仅供人读**，后端集成一律用 JSON：

```text
tea121 succeeded | alarms=1 diagnostics=0
DEFINITE: main  object=main/v0 offset=[10,10] size=[10,10] width=1 (out_of_bounds)
```

---

## 3. CLI（`cli.py`）

```text
tea121 --version
tea121 analyze <input> [--format text|json] [--output PATH]
                     [--mode normal|trace] [--widen-after N]
```

输入可以是 `.c/.cc/.cpp/.ll/.json/.miniir`（.c/.ll 走 frontend.py 全链，.json 直接装载）。

错误处理（cli.py 39-58 行）有三条路：
1. `FrontendError` → 造一个 error/unsupported 结果信封，诊断 code 用异常里的 code
   （`COMPILE_FAILED`、`LLVM_TOOLCHAIN_MISSING`、`EXTRACTION_FAILED`…）；
2. OSError/ValueError/JSONDecodeError → `INVALID_INPUT` error 结果；
3. 正常 → `build_result(...)`，并补 `config` 与 `artifacts`。

退出码：正常 0，status=error 时 1，参数错误 2。后端正是靠"退出码 + 结果 JSON"集成
（后端 TEA121_ANALYZER_COMMAND=tea121）。

---

## 4. 评估工具 `evaluate_juliet.py`

### 4.1 用例发现（discover_cases）

用**文件名的 flow 变体规则**找同一个 case 的 bad/good 侧（仅在"找文件"这一步使用命名，
分析语义与文件名无关）：

```python
NAME = re.compile(r"^(?P<base>.+)_(?P<flow>\d{2})(?P<part>[a-z])?(?P<role>_(?:bad|goodB2G|goodG2B))?\.(...)$")
```

- 单文件：bad 与 good 都是同一份源码（函数内 `_bad()`/`_good()` 由宏选择，见下）；
- `51a/51b` split 文件：bad/good 两侧把 51a 与对应 role 文件一起编译；
- C++ `81a + _bad/_good*`：按 role 后缀分侧；
- `family` 从 `base.rsplit("__",1)` 提取（如 `CWE193_char_alloca_cpy`），**仅供报告分组**。

### 4.2 单侧执行（analyze_side）

对 bad 侧与 good 侧**各自独立**执行一次完整管线：
编译（含 `std_testcase.h` 等 include-dir）→ 可能 `llvm-link` 合并多文件 →
`mem2reg` → `tea121-extract` → `tea121 analyze`，并记录命令、SHA-256、耗时、原始结果。
编译失败记 `error`，**不静默排除**。

### 4.3 四态分类与配对矩阵

`classify_result`（单侧）：

| 条件 | 判定 |
|---|---|
| 进程错误 / status=error / 有 error 诊断 | `error` |
| status=unsupported 或 有 unsupported/unknown_effect 诊断 | `unsupported` |
| 有 alarms | `alarm` |
| 否则 | `clean` |

`classify_pair`（bad 侧 × good 侧）：

| bad \ good | clean | alarm | unsupported/error |
|---|---|---|---|
| alarm | **correct**（检出正确） | false_positive | unsupported |
| clean | **false_negative**（漏报） | inverted（反了） | unsupported |
| unsupported/error | unsupported | unsupported | unsupported |

指标（`_summary`）：
- `effective_bad_recall` = correct /（不含 unsupported 的配对中 bad 应报警数）；
- `effective_good_silence_rate` = good 静默比例；
- `conservative_pair_accuracy`：全量（含 unsupported/error）口径的配对正确率。

### 4.4 当前实测基线（引用 `开发手册/分析端status.md` I8.2）

- s01 全量 532 对、18 worker 约 12 秒；
- 侧面 `223 alarm / 333 clean / 508 unsupported / 0 error`；
- 配对：`32 correct / 85 false_positive / 143 false_negative / 15 inverted / 257 unsupported`；
- 保守 bad 召回 23.12%，有效配对 bad 召回 42.55%，有效配对 good 静默率 63.64%。

> 结论性提示：unsupported 仍占一半——主要来自提取器不支持的指令/输入源形态。
> 阅读/改进顺序建议：先把 unsupported 降下来，再谈召回。

---

## 5. 测试怎么读（对照本文档）

| 测试文件 | 覆盖点（对应章节） |
|---|---|
| `tests/unit/test_interval.py` | 03 Interval 格运算（含单侧无穷算术、narrow 与溢出退化） |
| `tests/unit/test_models.py` | 05 注册表开关、strcpy/memcpy/fgets/recv/fscanf 模型、标量 store/load |
| `tests/unit/test_engine.py` | 04 常量越界、循环 widening/narrowing、true/false guard、PHI 与不可达分支 |
| `tests/unit/test_interproc.py` | 05 用户函数间调用与摘要 |
| `tests/unit/test_evaluate_juliet.py` | 07 用例发现、四态分类、配对矩阵与指标 |

容器内跑全部单测：`docker run --rm --entrypoint pytest tea121-lite-backend:latest -q /workspace/analyzer/tests`
（现状：37 个用例全过，见 分析端status.md）。

> 回归已覆盖 `Interval(0,2).join(Interval(0,None)) = Interval(0,None)`、安全/越界循环配对、
> `i >= 10` false 边精化，以及常量条件确定不可达时的分支消解。
