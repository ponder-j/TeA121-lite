# 04 求解器：worklist 主循环与逐指令转移函数（逐行）

> 前置：`01/03`。本文是**分析核心**，逐段读 `analyzer/src/tea121/analysis/solver.py`
> （408 行）。读完你应能对着任意一条 MiniIR 指令说出它如何更新状态、何时产生告警/诊断。
>
> 阅读提示：文中行号均指 solver.py 的行号；先通读 §1-§3 建立骨架，再精读 §4-§7。

---

## 1. 三个数据结构（13-33 行）

```python
@dataclass(frozen=True)
class AnalysisConfig:
    widen_after: int = 3      # 访问第 >3 次（即第 4 次起）对块出口做 widen
    narrowing_rounds: int = 1 # widening 稳定后执行一轮可收敛的 narrowing 阶段
    mode: str = "normal"      # normal | trace（trace 额外记逐指令事件）
    max_call_depth: int = 8   # 用户函数调用展开的最大深度（资源上限）
    models: tuple[str, ...] = ("memcpy","memmove","memset","strcpy","strncpy")

@dataclass
class AnalysisOutput:          # run() 的产物（可变，engine 边跑边往里 append）
    alarms / diagnostics / cfg / block_states / trace

@dataclass(frozen=True)
class FunctionSummary:         # 用户函数摘要：只记返回值
    return_interval: Interval | None
    return_pointer: PointerValue | None
```

`FunctionSummary` 是"函数间分析"的缓存单位（见 05）：**摘要只含返回值**，函数对内存的副作用
（改对象、改标量摘要）靠"调用时把 caller 状态复制进 callee 内联分析、再把 caller 状态接回来"
来体现——所以这里不是经典的"独立摘要"，而是**调用点上下文内联 + 返回值回填**（见 05 细讲）。

---

## 2. `AnalysisEngine.__init__`（36-59 行）：一次运行前的准备

- 保存 module/config；`output` 初始化空列表（40 行）；
- `_objects: dict[str, MemoryObject]`——分析期登记对象的全局侧表（41 行，见 §6 alloca）；
- `_library_models = LibraryModelRegistry().with_enabled(self.config.models)`（42 行）：按 config 过滤可用的库模型名；
- `_functions`：按名字索引所有函数（43 行）；
- `_summaries: dict[(callee_name, caller_name:inst_id), FunctionSummary]`（44 行）：**按调用点缓存**摘要；
- `_global_objects / _global_strings / _global_string_values`（45-59 行）：把 MiniIR 顶层 globals 转成
  MemoryObject、`string_length` 区间、`string_value` 文本，用于初始状态和 strcpy/fscanf 模型。

---

## 3. `run()`（61-66 行）：从"根函数"出发

```python
called = {str(inst.get("callee")) for fn in self._functions.values()
          for block in fn.get("blocks", []) for inst in block.get("instructions", [])
          if inst.get("op") == "call" and inst.get("callee") in self._functions}
roots = [fn for name, fn in self._functions.items() if name not in called] or list(self._functions.values())
for function in roots:
    self._analyze_function(function)
```

- 第一行收集**被模块内其它函数调用过的函数名**；
- 根 = 没被调用过的函数（通常是 `main`）；若全是互相调用（没根）就退化为"所有函数都当根"；
- 对每个根跑一次完整函数分析。用户函数体里再遇到 call 时走 §5（05 文档）的展开逻辑。

---

## 4. `_analyze_function`：状态求解、narrowing 与效应重放

### 4.1 建 CFG 表（69-86 行）

- `by_id`：块 id → 块；
- `entry`：函数的 entry；
- 遍历块：先取 `block["successors"]`；若 terminator 是 `br`，**以 terminator 为准**重新算后继
  （无条件 br → `[target]`；条件 br → `[true, false]`，81 行）；
- 顺便给 `output.cfg` 记一条边（86 行），带 `condition` 与 `polarity`（true/false/None）——
  这就是结果 JSON 里可画图的 CFG 边的来源。

### 4.2 初始化与主循环

```python
entry_states = {bid: State.unreachable() for bid in by_id}   # 默认所有块不可达
exit_states  = {bid: State.unreachable() for bid in by_id}
entry_states[entry] = initial_state or self._initial_state() # 入口从全局对象/字符串开始
queue = [entry]
visits = {bid: 0 for bid in by_id}
while queue:
    bid = queue.pop(0)                          # FIFO
    ...
    if bid != entry:                            # 入口块之外：
        state, incoming_states = self._block_input_state(...)
        # incoming_states[p] = 从 p 出口沿 p→bid 边精化后的状态
        # state = 对所有 reachable incoming_states 做 join
        if state == entry_states[bid] and state.reachable:
            continue                            # 入口没变 → 这轮不用再算（加速）
        entry_states[bid] = state
    state = entry_states[bid]
    visits[bid] += 1
    new_state = self._transfer_block(..., incoming_states)  # 逐指令转移
    if visits[bid] > self.config.widen_after:   # 第 4 次访问起
        new_state = exit_states[bid].widen(new_state)   # 对出口做 widen
    if new_state == exit_states[bid] and visits[bid] > 1:
        continue                                # 出口也没变 → 不扩散
    exit_states[bid] = new_state
    queue.extend(后继中在函数内且不在队列里的块)
```

要点：

1. **entry 合并**：非入口块的状态 = 所有可达前驱出口状态经**边精化**后 join；同时把每个
   `(前驱块, 精化后状态)` 保存成 `incoming_states`，供 PHI 按边取值。
2. **收敛判据**：入口不变 → 跳过；出口不变（且不是第一次）→ 不把后继再入队。
3. **Widening 触发点**：`visits[bid] > widen_after`，即某个块被反复访问到第 4 次时，
   出口状态与"上一轮出口"做 `State.widen`（03 §4.5 讲过：先 join 再 Interval.widen）。
   这通常发生在**循环头**（它被前驱和自己反复入队）。
4. **Narrowing**：只要发生过 widen，worklist 稳定后再执行 `_narrow_states`。它按前驱状态
   重新计算入口，并用 `State.narrow`（各抽象域 meet、区间取交集）收回 widening 丢掉的有限界；
   同一 narrowing 轮内部只做 meet，重复扫描直到本阶段稳定，因此不会重新发散。
5. **终止性**：widen 把递增界推成 +∞ 后，再合并不会产生新界 → 状态稳定 → 队列空 → 停；
   narrowing 只会缩小状态，也不会重新使队列失去终止性。
6. **稳定状态重放**：worklist 与 narrowing 期间只算状态，不落 Alarm/Diagnostic/Trace；
   最终固定点确定后，再对每个可达块重放一次 `_transfer_block`。这样中间轮次的 Top
   不会留下“后来已被证明安全”的陈旧 Alarm。

### 4.3 收尾：block_states 与函数摘要

- 为每个块导出 `{entry_state, exit_state}` 到 `block_states`（**最终**入口/出口，不是中间轮次）；
- 把所有 `ret` 块的出口 join 成 `returned`；
- 找第一个带返回值的 `ret`，取其 `value`；
- 若 value 是指针 → `FunctionSummary(return_pointer=...)`；否则 → `FunctionSummary(return_interval=get_int(value))`。

---

## 5. `_edge_state`：分支边上的约束精化

每条边进目标块前，若源块 terminator 是带条件的 `br`，就把“走到这条边意味着条件
成立/不成立”的信息打进状态：

```python
target 是 true/false：
  condition 是内联 icmp → _refine_cmp(...)
  condition 是状态中的布尔值 → true 边 meet [1,+∞)，false 边 meet (-∞,0]
```

`_refine_cmp` 先按边极性把谓词取反（false 边 = 原谓词的否定），再执行约束传播。
变量和常量可以出现在任一侧；常量不再是“无法精化”的障碍。

| 谓词（真边） | left 约束 | right 约束 |
|---|---|---|
| `lt` / `le` | `left.upper ≤ right.upper(-1/0)` | `right.lower ≥ left.lower(+1/0)` |
| `gt` / `ge` | `left.lower ≥ right.lower(+1/0)` | `right.upper ≤ left.upper(-1/0)` |
| `eq` | 两侧都 meet 交集 | 两侧都 meet 交集 |
| `ne` | 对端为单点时常量点排除 | 对端为单点时常量点排除 |

`slt/ult/sle/ule/sgt/ugt/sge/uge` 去掉 `s/u` 前缀后走同一张表。false 边通过否定映射
（例如 `sle` 的 false 边按 `sgt` 处理），所以 `if (i >= 10) break` 的 false 分支会得到
`i ≤ 9`，循环体 guard 后的访问可以正常证明安全或报告越界。

未知谓词或无法表示的约束保持原状态，不产生错误，只是损失精度。

---

## 6. 逐指令转移 `_transfer`（149-207 行）

`_transfer_block`（141-153 行）只是"for 每条指令：`state = _transfer(...)`；trace 模式下
把 before/after 状态 append 进 `output.trace`"。真正的语义在 `_transfer`：

### 6.1 标量计算族

| op | 行为 | 说明 |
|---|---|---|
| `const/constant` | `with_int(result, Interval.const(value))` | 常量立即数 |
| `add/sub/mul` | `getattr(left, op)(right, bits=inst.bits, signed=inst.signed)` | 03 §1.4 的区间算术；可能溢出→Top |
| `phi` | 对每个 incoming，先在前驱块对应的精化后状态中查 value，再对有可达边的区间做 join | 边敏感：未达到的后继边不会用未知 Top 污染 PHI |
| `select` | true/false 两个分支值 join | select 被当成"二选一" |
| `icmp` | `_comparison_interval(pred, l, r)` | 见 §6.5 |
| `copy`（cast） | 指针→拷指针；否则拷整数区间 | sext/zext/trunc/bitcast 都按"值不变"处理 |

### 6.2 内存对象族

**alloca（176-181 行）**：
```python
size = count * element_size            # 区间乘法
object_id = f"{function名}/{result}"   # 如 main/v0 —— 全程序唯一
obj = MemoryObject(object_id, size, allocation_site)
self._objects[object_id] = obj         # 侧表登记（防止 join 丢了对象仍能查到）
return with_object(obj).with_pointer(result, PointerValue({object_id}, offset=0))
```
一个栈对象的 **id 就是 `函数名/SSA名`**，这也是告警里 `memory_object_id=main/v0` 的来历。

**gep（183-186 行）**：
```python
base = 取 base 指针; index = 取 index 区间; scale = element_size
return with_pointer(result, PointerValue(base.bases,
                     base.offset_bytes + index*scale, base.unknown_base))
```
对基址集合里的每个 base 用同一个偏移——**偏移按字节**，`element_size` 由提取器给出。

### 6.3 load/store（188-202 行）——检查 + 摘要

```python
pointer = state.get_pointer(inst["pointer"]); width = inst["width"]
# 特例：从外部声明加载指针（stdin、socket 句柄等）不做访问检查，
# 只把结果置成 unknown 指针（192 行注释）。否则：
if not (load 且 pointer_result 且 base 未知):
    self._check_access(inst, pointer, width, ..., write=(op=="store"))   # ★ 告警点
if load 且 pointer_result: return with_pointer(result, PointerValue.unknown())
if load 且 指针不是 unknown 且 offset 是单点 且 base 唯一:   # 标量摘要读
    return with_int(result, get_memory_int(base, offset))
if store 且 指针不是 unknown 且 offset 是单点:              # 标量摘要写
    对每个 base: with_memory_int(base, value, offset)
return ...
```

要点：
- **任何 load/store 先做访问检查**（`_check_access`，§7）——这就是"每次访问都可能产生告警"的位置；
- 只有**常量偏移**（单点）且单基址时才能读回/写入标量摘要 `scalar_memory`；
  区间偏移或 unknown base 时不做摘要（保守）；
- 外部句柄指针（stdin 等）load 时不制造 UNKNOWN_BASE 噪音（192 行注释是专门为 Juliet 用例加的）。

### 6.4 call 与 unsupported（203-207 行）

- `call` → `_call_model`（整个 05 文档）；
- `unsupported` → `UNSUPPORTED_INSTRUCTION` 诊断后原样返回状态；
- 其它（理论上不会出现）→ 静默返回原状态。

### 6.5 `_comparison_interval`（模块级）

icmp 结果（一个 0/1 整数）的抽象：
- `eq/ne` 且两边都是单点 → 精确 `[1,1]/[0,0]`；
- `eq/ne` 且区间不相交 → 精确 `[0,0]/[1,1]`；
- `lt/le/gt/ge` 可由区间端点证明为真或假时 → `[1,1]/[0,0]`；
- 其余 → `[0,1]`（不确定）。

---

## 7. `_check_access`（209-223 行）：越界判定与告警生成（灵魂函数）

```python
if pointer.unknown_base or not pointer.bases:
    → UNKNOWN_BASE 诊断（unknown_effect），不产生 alarm
for object_id in pointer.bases:
    obj = state.memory_objects.get(object_id) or self._objects.get(object_id)
    if obj is None:
        → UNKNOWN_OBJECT 诊断，continue
    offset = pointer.offset_bytes
    safe     = width is not None and offset.lower is not None and offset.lower >= 0
               and offset.upper is not None
               and obj.size_bytes.lower is not None
               and offset.upper + width <= obj.size_bytes.lower
    definite = width is not None and offset.lower is not None
               and obj.size_bytes.upper is not None
               and (offset.lower < 0 or offset.lower + width > obj.size_bytes.upper)
    if not safe:
        severity = "definite" if definite else "possible"
        → append alarm {...}
```

逐字翻译（对照 01 §2.4 的三条判定）：
- **safe** = 偏移下界 ≥0（不向前越界）、偏移上界已知、上界+宽度 ≤ 对象**最小**大小；
  ⚠️ 用的是 `size_bytes.lower`（最小可能大小）——若大小是区间，必须以最小大小证明安全；
- **definite** = 偏移下界已知，且 `下界 < 0`（必然向前越界）或 `下界+宽度 > 对象最大大小`
  （必然向后越界）；⚠️ 注意判据里 `offset.upper` 没有参与 definite——
  用的是**下界 + 宽度**与 `size_bytes.upper` 比，即"最靠前的一次访问都会越界"才算 definite；
- 不 safe → 生成 alarm：severe = definite/possible；
- 其余情况（safe 为真）→ **静默**。

Alarm 字段逐项：

| 字段 | 来源 | 例子（test.c） |
|---|---|---|
| `alarm_key` | `函数名:指令id:对象id` | `main::main/v0` |
| `detector_id/rule_pack_id` | 写死 `stack-bounds` / `cwe121-core` | |
| `cwe_id` | `CWE-121`；`family` 置 None（不由文件名回填） | |
| `violation_kind` | `out_of_bounds` | |
| `severity` | `definite`/`possible` | `definite` |
| `function_name/block_id/instruction_id` | 上下文 | 注意 store 的 instruction_id 常为 `""`（void 指令没有 SSA 名） |
| `memory_object_id` | alloca 生成的 `函数/SSA名` | `main/v0` |
| `object_size` | 对象大小区间 | `[10,10]` |
| `offset` | 指针偏移区间 | `[10,10]` |
| `access_size` | 访问宽度（未知时为 0） | `1` |
| `safe_condition` | 人类可读的安全条件字符串 | `offset.lower >= 0 and offset.upper + access_size <= object_size.lower` |
| `reason` | 固定文案列表 | `["access range is not provably inside the stack object", ...]` |
| `source_location` | DebugLoc | `{file,line,column}` |

> 观察：`reason` 目前是**模板化**的两条固定文案，第二条只在 width 未知时换成
> "access width is unknown"。它记录"为什么没证明安全"，但还没有细分到具体是
> 下界为负、上界未知、还是宽度超界——属于可解释性的后续改进点。

---

## 8. 诊断与状态导出

- `_diagnostic(code, message, severity, ...)`（373-376 行）统一生成诊断 dict，severity 限定
  `unknown_effect | unsupported | error`；
- `_state_json/_interval_json` 把 State/Interval 转成 JSON 用的可序列化 dict
  （`lower/upper/is_bottom`，`bases` 排序保证输出稳定）。

---

## 9. 一张表记住"每种 op 会产生什么"

| op | 更新状态 | 可能产生 Alarm | 可能产生 Diagnostic |
|---|---|---|---|
| const/constant | int | – | – |
| add/sub/mul | int（可能 Top） | – | – |
| phi/select | int join | – | – |
| icmp | int 0/1 | – | – |
| copy | int/指针拷贝 | – | – |
| alloca | 新对象 + 指针 | – | – |
| gep | 指针偏移累加 | – | – |
| load/store | 检查 + 摘要 | ✅ definite/possible | UNKNOWN_BASE / UNKNOWN_OBJECT |
| call | 见 05 | ✅（经库模型/内联里的访问检查） | 多种 |
| unsupported | – | – | UNSUPPORTED_INSTRUCTION |

下一步：`05` 把 `call` 这一格展开——库函数模型与用户函数间分析。

---

## 10. 循环与条件分支增强的实现手段（本轮落地）

把“循环/分支支持差”拆成五个可验证的根因，并分别落地：

1. **比较精化覆盖不全**：`_refine_cmp` 统一处理 `eq/ne/lt/le/gt/ge` 及其 signed/unsigned
   前缀；false 边先取逻辑否定，再按同一张约束表传播。常量在右侧或左侧都能参与。
2. **guard 的 false 边丢失**：例如 `i >= 10` 的 false 边会转为 `i < 10`，把上界压到 9，
   从而证明 `buffer[i]` 安全；未知条件不会错误删除循环头已经得到的上界。
3. **PHI 路径不敏感**：worklist 为每条可达前驱边保存 `incoming_states`，PHI 在每个前驱的
   精化状态里取值后再 join；未到达的回边不会用 Top 污染第一次循环头状态。
4. **Widening 后精度不可恢复**：worklist 第一次收敛后执行 bounded narrowing 阶段，以
   `State.narrow`（各域 meet）逐轮恢复循环条件可证明的界；每个 narrowing round 只减不增，
   因而不影响终止性。
5. **中间状态产生陈旧告警**：求解阶段关闭副作用，固定点/narrowing 结束后才用最终状态重放
   `_transfer_block`。告警、诊断和 trace 都对应最终展示的 `block_states`，避免“状态已安全但
   告警仍留在结果里”。

配套回归：

- `test_safe_loop_is_silent_after_branch_refinement_and_narrowing`：`i <= 9` 的安全循环静默，
  且循环体入口状态为 `i ∈ [0,9]`；
- `test_unsafe_loop_keeps_possible_alarm`：`i <= 10` 的 off-by-one 循环仍产生 possible；
- `test_false_branch_refines_guard_before_access`：`i >= 10` 的 false 边收紧为 `i <= 9`；
- 真实 C 端到端回归覆盖 `test_loop_safe.c`、`test_loop.c`、`test_loop_br.c` 和
  `loop_guard_oob.c`。
