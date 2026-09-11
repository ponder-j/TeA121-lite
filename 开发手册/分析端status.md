# 分析端开发状态

> 更新日期：2026-09-11
> 当前版本：`0.1.0-I8.3`
> 负责人范围：`analyzer/`、分析端契约示例和容器构建

## 三端联调更新（2026-09-06）

- 分析器已由 backend 容器真实调用，不再只通过 fixture importer 联调。
- C/LLVM 输入结果新增 normalized IR artifact 与 SHA-256，供 backend 持久化和 Web 工作台读取。
- `simple_oob.c` 三端 smoke 实测输出 1 条 definite Alarm、1 个 block state、7 条 Trace 和 53 行 normalized IR。
- analyzer 21 条测试和 3 个 analyzer-result fixture 契约校验通过。

## 当前结论

分析端已经从空仓库建立了一个可脱离后端运行的最小闭环：Docker 内固定
LLVM/Clang 15，C 文件可以被编译为 LLVM IR，经 C++ 提取器转换为 MiniIR，
再由 Python 区间分析器输出结构化 CWE-121 结果。一个真实 C 样例已经验证
为 `definite` 越界并保留源码行列号。

这仍然是教学 MVP，不是最终的 Juliet 评估版。当前最重要的缺口是全局/字符串
摘要的更多形态、完整库函数四态测试以及 628 对的真实评估；循环和条件分支已在本轮补齐
`icmp` 全谓词/双边精化、边敏感 PHI、widening 后 narrowing 和稳定状态重放。

## 已完成

| 范围 | 状态 | 证据 |
| --- | --- | --- |
| Interval Top/Bottom、join/meet/widen/narrow、单侧无穷算术和溢出退化 | 已完成 | `domain/interval.py`，单测覆盖 |
| PointerValue、栈对象和 escaped 状态 | 已完成 | `domain/pointer.py`、`domain/state.py` |
| 标量 store/load 内存摘要 | I8.2 MVP 完成 | `State.scalar_memory`，按对象与偏移保留常量或 Top |
| MiniIR loader 与 1.0.0 契约 | 已完成 | `ir/loader.py`、`contracts/schemas/miniir.schema.json` |
| CFG worklist、全谓词分支精化、边敏感 PHI、widening/narrowing、最终状态重放 | 已完成（当前范围） | `analysis/solver.py`，单元与真实 C 回归 |
| definite/possible 边界告警与 unknown/unsupported/error 诊断 | 已完成 | `report/result.py`，三个结果 fixture |
| C++ LLVM 15 提取器 | MVP 完成 | `llvm-extractor/extractor.cpp`；CFG、Value-ID、DataLayout、DebugLoc |
| C/LLVM -> MiniIR -> Python 分析桥接 | 已完成 | `frontend.py`；参数数组调用、临时目录和失败诊断 |
| `mem2reg` 规范化和全局字符串摘要 | I6 MVP 完成 | `opt-15`、全局字符串长度、`strcpy` 精确宽度 |
| k=1 用户函数间调用传播 | I7 MVP 完成 | 形参绑定、返回值回填、根函数去重 |
| Docker 可复现环境 | 已完成 | `Dockerfile`、`docker-compose.yml`；镜像构建成功 |
| CLI、文本/JSON、trace 输出 | 已完成 | `python -m tea121 analyze ...` |
| 单元与契约校验 | 已完成 | `37 passed`，3 个结果 fixture 校验通过 |
| Juliet runner | I8 MVP 完成 | 按 bad/good 侧执行编译、链接、mem2reg、提取和分析，输出四态、CSV、哈希与命令审计 |

## 与最终目标的距离

按手册 I0-I9 迭代划分，I0-I7 的 MVP 已建立，约完成 **60%～70%** 的迭代
里程碑；按“课设交付版 v1”的可验收内容估计约 **50%～60%**。这个比例
不等同于检出率，当前没有合法的全量 Juliet 指标，不能声称达到手册中的
85%～93% 目标区间。

距离最终目标还缺：

1. 工具链、DataLayout、命令参数、输入 SHA-256 和规范化 IR artifact 的完整元数据；
2. 宽字符元素宽度、`strncpy` 截断语义和更复杂全局常量摘要；
3. 将 FunctionModel 行为从 solver 中完全拆出，并补齐每个模型的四态测试；
4. 更严格的调用上下文快照和关系域分析（当前 narrowing 仍只恢复区间/指针分量）；
5. 至少 20 个手写 C 端到端样例、split-file 样例和 LLVM 映射测试；
6. Juliet CWE-121 s01 的 628 对四态终结、分组矩阵、保守指标和性能数据；
7. normal 模式源码/规范化 IR artifact、完整 CFG 状态和稳定结果排序；
8. 支持矩阵、已知限制、五个告警解释案例及最终演示脚本。

## 当前风险

- 本机开发环境没有 LLVM；真实 C 回归必须在 Docker 中执行。
- 提取器目前对复杂 GEP、多级索引、PHI、内存 SSA 和部分 LLVM 指令仍会
  产生 `unsupported` 或未知基址诊断。
- Juliet runner 已能真实执行分析；当前仓库的 Juliet 支持文件已补齐后，仍有
  `unknown_effect`/未实现 LLVM 指令样本，按规范计为 `unsupported`，不能计为
  clean，也不能用有效子集指标冒充全量召回率。
- Python 核心已接入后端 importer 并完成单文件跨端 smoke；多文件链接与 Juliet 批量尚未进入 Web 联调。

## 已完成的 I6 验收

本轮已达到以下 MVP 目标：

- C/LLVM 前端在存在 `opt-15` 时固定执行 `-passes=mem2reg`；
- 全局字符串进入 MiniIR 和初始状态，已知 `strcpy` 写入宽度包含终止符；
- `strcpy` 安全、确定越界和未知长度用例，以及 `memcpy` 确定越界用例已覆盖；
- 容器内单测、契约校验和 3 个 C 端到端样例通过；
- 所有未知语义仍保留独立 Diagnostic，不被折算为 clean。

## 已完成的 I7 验收

本轮已达到以下 MVP 目标：

- 用户函数参数绑定到被调函数形参，返回整数/指针摘要可回填调用者；
- 被调用函数不再作为独立根函数重复分析，调用点摘要按调用点区分；
- 递归调用输出 `RECURSIVE_CALL`，深度上限输出 `MAX_CALL_DEPTH`；
- 安全和越界辅助函数、递归样例已加入回归，容器内 `12 passed`。

## I8 原始计划

重点转向 Juliet runner 和评估闭环：读取 bad/good manifest，逐案例调用容器内
CLI，记录 `alarm/clean/unsupported/error` 四态，输出有效样本与全量保守指标，
并先在 s01 的小子集上验证可重复性，再扩展到全量 628 对。

## I8 迭代进展（2026-09-06）

本轮已完成评估闭环的第一阶段：

- `analyzer/tools/evaluate_juliet.py` 支持单文件、`51a/51b` split-file、
  C++ `81a + _bad/_good*` 形态；bad/good 侧分别使用 `OMITGOOD`/`OMITBAD`。
- 每个侧面记录源文件及其依赖头文件的 SHA-256、编译/`llvm-link`/`opt`/提取器/
  分析器命令、耗时、原始结果和失败原因；`--keep-artifacts` 可保留规范化 IR
  与 MiniIR。
- 输出 `alarm/clean/unsupported/error` 四态、正确区分/误报/漏报/倒置和
  `bad_recall`、`good_silence_rate`、文件级与配对级指标，并可同时输出 CSV。
- 增加 4 态分类、配对发现和保守指标单测；Docker 内单测由 12 个增至 **16 个**。
- Juliet 支持文件接入后，s01 flow-01 的 13 对已真实运行：bad/good 两侧合计
  `4 alarm / 12 clean / 10 unsupported / 0 error`；配对为
  `2 correct / 1 false_positive / 5 false_negative / 5 unsupported`。
  有效配对上的 bad 召回为 2/8，但全量保守配对正确率为 2/13（15.38%）。
  该数字是当前实现的实测基线，不是最终检出率；主要限制仍是输入源、循环、
  宽字符和字符串摘要。
- 将 LLVM 后缀化 `llvm.memcpy/memmove/memset` intrinsic 映射到既有内存模型，
  并把 `printLine`、`strlen`、`rand`、网络初始化等只读/纯调用从未知副作用中
  分离，避免无关输出调用污染评估。
- 支持文件补齐后，flow-51 的 3 对 smoke 运行无编译/链接错误，得到
  `0 alarm / 2 clean / 4 unsupported`（两侧合计），并验证了 `51a/51b` 的
  多文件链接路径；`fgets`/`fscanf` 和未知基址仍按 unsupported 处理。
- 支持文件补齐后已完成当前仓库 s01 的全量逻辑案例运行：**532 对**、耗时约
  90 秒，bad/good 两侧合计 `124 alarm / 282 clean / 658 unsupported / 0 error`；
  配对为 `32 correct / 37 false_positive / 118 false_negative / 14 inverted /
  331 unsupported`。全量保守 bad 召回为 `13.72%`，配对正确率为 `6.02%`；
  201 对不含 unsupported 的有效配对上，bad 召回为 `34.33%`，good 静默率为
  `74.63%`。结果保存在 `analysis-output/juliet-s01-all.json/.csv`（该目录被
  `.gitignore` 忽略，便于本地重复实验）。
- 当前 `juliet测试集/manifest.xml` 与 `testcases/CWE121.../s01` 交叉核对后也是
  532 个 `<testcase>` 逻辑条目；手册中的 628 对是另一种 bad/good 变体展开
  口径，不能直接与本轮 532 对相比较，后续需在 runner 中显式实现该展开规则。
- 根据 18 核环境要求，runner 新增 `--jobs N` 并行参数和
  `scripts/docker-evaluate-juliet.sh`（默认 `TEA121_JOBS=18`）。并行 smoke 与串行
  结果一致；全量 532 对在 18 worker 下约 **13 秒**完成（串行基线约 1 分钟），汇总为
  `analysis-output/juliet-s01-all-parallel.json/.csv`。

## I8.1 迭代进展（2026-09-06）

本轮围绕输入源和 CFG 提取缺口完成了一次可测迭代：

- LLVM 提取器新增原生 `phi` 指令映射，并标记指针类型 `load`；solver 对 PHI
  做区间 join，对外部声明指针加载保留未知指针而不提前制造 `UNKNOWN_BASE`。
- 新增 `fgets`、`recv` 的最大写入宽度模型；新增 `fscanf` 格式识别，数字转换按
  标量宽度检查，字符串转换继续以未知长度处理。
- `atoi`、`strlen`、`wcslen`、`rand`、socket 等纯/观察调用现在会传播返回值：已知
  字符串长度返回精确区间，其余标量返回 `Top`，不再错误继承初始化值。
- 容器内回归由 16 个增至 **20 个**，全部通过；LLVM 15 extractor 已重建。
- 18 worker 重跑 s01 全量 532 对（约 12 秒）无编译错误：侧面
  `229 alarm / 327 clean / 508 unsupported / 0 error`；配对为
  `32 correct / 85 false_positive / 137 false_negative / 21 inverted /
  257 unsupported / 0 error`。全量保守 bad 召回 **23.12%**，有效配对 bad 召回
  **42.55%**，有效配对 good 静默率 **61.45%**。结果更新于
  `analysis-output/juliet-s01-all.json/.csv`。
- 与上一轮基线相比，unsupported 侧面由 658 降至 508，保守 bad 召回由 13.72%
  提升至 23.12%；`fscanf`/`fgets`/socket 家族已从纯 unsupported 转为部分可评估，
  但数字输入和复杂控制流仍带来明显误报/漏报。

I8 尚未完成的工作：

1. 收敛 `fscanf` 数字输入的别名/内存读取误报，并补齐宽字符 `wcscpy`、循环和更多 LLVM 指令语义；
2. 加入 Juliet 全部 flow variant 的运行分层和 family/variant 分组矩阵；
3. 处理 split-file 的公共头/支持库编译缓存，降低 628 对运行时间；
4. 生成完整 s01 原始 JSON/CSV 和资源峰值记录，再据此更新真实指标。

## I8.2 迭代进展（2026-09-06）

本轮针对 `fscanf` 数字输入的安全源误报补充了最小标量内存摘要：

- LLVM 提取器为 `store` 保留写入值；`State` 新增按 `(memory_object, offset)` 索引的
  标量摘要，solver 在常量 `store/load` 间传播精确区间，在输入写入后置为 `Top`。
- 新增常量 store/load 回归，容器内分析端测试由 20 个增至 **21 个**，全部通过；
  analyzer contract 校验仍通过 3 个 fixture。
- 18 worker 重跑 s01 全量 532 对（约 12 秒）无编译错误：侧面
  `223 alarm / 333 clean / 508 unsupported / 0 error`；配对为
  `32 correct / 85 false_positive / 143 false_negative / 15 inverted /
  257 unsupported / 0 error`。保守 bad 召回 **23.12%**，有效配对 bad 召回
  **42.55%**，有效配对 good 静默率 **63.64%**。
- 相比 I8.1，有效配对 good 静默率提升约 2.18 个百分点，说明安全常量源的状态
  传播已经生效；unsupported 数量未下降，下一轮需优先覆盖剩余 LLVM 指令。
- 最新结果仍写入 `analysis-output/juliet-s01-all.json/.csv`，当前仓库口径为 532
  个逻辑 testcase，不能与手册中的 628 对展开口径混用。

## I8.3 循环与条件分支增强（2026-09-11）

本轮针对“循环和条件分支支持差”完成以下实现：

- `_refine_cmp` 覆盖 `eq/ne/lt/le/gt/ge` 与 `slt/ult/sle/ule/sgt/ugt/sge/uge`，
  true/false 两边都精化；变量/常量可以出现在任一侧，常量分支若确定不可达则直接下沉为
  `State.unreachable()`。
- PHI 改为边敏感：`_block_input_state` 保存每个可达前驱的精化状态，PHI 只读取对应
  `incoming.block` 的值；LLVM 提取器同时修正 PHI incoming 的 basic-block 名称映射。
- widening 触发后执行 bounded narrowing：`State.narrow` 对整数、指针偏移、对象大小、
  字符串和标量摘要做 meet，循环条件可恢复的上界不会永久丢失。
- 区间 `add/sub/mul` 支持单侧无穷传播，例如 `[None,9]+1=[None,10]`、
  `[None,9]×4=[None,36]`，使 guard 后的 GEP 仍保留有限偏移上界。
- 求解阶段与效应阶段分离：Alarm/Diagnostic/Trace 在最终固定点上重放，解决中间轮次
  Top 产生陈旧告警、而 `block_states` 最终更精确的不一致问题。

验证记录：

| 样例 | 结果 | 证据 |
| --- | --- | --- |
| 单元/契约回归 | `37 passed`，3 个 fixture 通过 | `analyzer/tests/unit`、`scripts/check_analyzer_contract.py` |
| `test_loop_safe.c` (`i <= 9`) | `alarms=0 diagnostics=0` | 循环体入口 `.0=[0,9]` |
| `test_loop.c` (`i <= 10`) | possible 1 条，offset `[0,40]` | off-by-one 真阳性 |
| `test_loop_br.c` | `alarms=0 diagnostics=0` | `i>=10` false 边收紧到 `i<=9` |
| `test_br_safe.c`、`test_br_safe2.cpp` | `alarms=0` | 常量不可达分支与 false guard 均正确 |
| `loop_guard_oob.c` | possible 1 条，offset `[0,400]` | 未知 guard 不再造成漏报 |

容器验证使用 LLVM 15 extractor 重建镜像
`tea121-lite:branch-loop-test`；后续正式镜像可在提交后通过 `docker compose build` 更新。
