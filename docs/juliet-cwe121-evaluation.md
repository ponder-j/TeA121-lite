# Juliet CWE-121 批量评测报告

> 数据集：`tests/testcases/CWE121_Stack_Based_Buffer_Overflow/s01..s09`
> 最终代码：本报告提交前的 `main`
> 运行环境：Docker Desktop，10 CPU / 约 7.75 GiB，8 workers

## 1. 可复现命令

```bash
TEA121_SUITE=s01 TEA121_FLOW=01 TEA121_LIMIT=20 \
  scripts/docker-evaluate-cwe121.sh

# 全量 s01..s09；脚本在本机自动选择 8 workers
scripts/docker-evaluate-cwe121.sh
```

默认输出：

- `analysis-output/juliet-cwe121-all.json`
- `analysis-output/juliet-cwe121-all.csv`

脚本遍历全部 `sNN`，按 bad/good 两侧分别编译和分析。`unsupported` 表示分析器发现了未建模语义或无法解析的对象，不能作为 clean 使用。全量 JSON 使用紧凑证据模式，只保留 verdict 所需的 alarm/diagnostic 摘要，避免完整 CFG/state 结果导致容器 OOM。

## 2. 总体结果

本数据集包含 4,944 个逻辑 testcase、9,888 个 side。最终全量运行没有编译/进程错误。

| 指标 | 初始基线 | 当前 |
| --- | ---: | ---: |
| TP（bad alarm） | 604 | **2,677** |
| TN（good clean） | 496 | **2,707** |
| FP（good alarm） | 163 | **36** |
| FN（bad clean） | 55 | **9** |
| unsupported side | 8,570 | **4,459** |
| correct pair | 442 | **2,650** |
| false-positive pair | 162 | **27** |
| false-negative pair | 54 | **0** |
| inverted pair | 1 | **9** |
| unsupported pair | 4,285 | **2,258** |
| conservative bad recall | 12.22% | **54.15%** |
| conservative good silence | 10.03% | **54.75%** |
| supported-only bad recall | 91.65% | **99.66%** |
| supported-only good specificity | 75.27% | **98.69%** |

precision 为 **98.67%**，supported balanced accuracy 为 **99.18%**。全量运行约 420 秒，Docker 峰值内存低于 1 GiB。

### 按 suite

| suite | cases | correct | FP | FN | inverted | unsupported |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| s01 | 532 | 329 | 11 | 0 | 9 | 183 |
| s02 | 600 | 315 | 0 | 0 | 0 | 285 |
| s03 | 600 | 299 | 1 | 0 | 0 | 300 |
| s04 | 600 | 310 | 0 | 0 | 0 | 290 |
| s05 | 600 | 304 | 1 | 0 | 0 | 295 |
| s06 | 568 | 306 | 2 | 0 | 0 | 260 |
| s07 | 576 | 314 | 2 | 0 | 0 | 260 |
| s08 | 592 | 310 | 5 | 0 | 0 | 277 |
| s09 | 276 | 163 | 5 | 0 | 0 | 108 |

## 3. 主要优化

- `db204b5`：未知标量指令从“整体 unsupported”改为保守 Top，恢复 `rand` 等路径的可判定性。
- `cd51843`：无跟踪指针参数的未知调用不再阻断分析；有指针参数的未知调用仍保守标记。
- `d3c1853`：加入 `snprintf/swprintf`、`strcat/wcscat`、`strncat/wcsncat`、`strncpy/wcsncpy`、`wcscpy`、`wmemset` 与局部 NUL/字符串长度摘要。
- `2703224`、`219a437`、`f682c8b`：跟踪聚合子对象剩余大小，修复结构体字段越界，同时避免数组元素和循环访问误报。
- `aeaa415`、`7ba6391`：传播全局整数常量和 Juliet 布尔支撑函数，剪除常量死分支。
- `f494474`、`d10203b`、`1cc6119`：传播 `memcpy/strcpy` 初始化的字符串长度，支持宽字符串常量/元素宽度，并保守处理宽字符串按字节 `strlen`。
- `82ff6cb`：区分数组整体分配大小与标量元素宽度，消除 CWE135 修复对 char 循环的副作用。
- `fb6c798` 与 `ad8b031`：引用参数副作用和 `load_origins` 曾在 `scalar_element_size` 修复前造成回退；前置问题修复后重新应用，并在全量上确认净收益。

## 4. 剩余缺口

1. unsupported 的主要来源是 C++ STL 容器/异常运行时的内部指针状态（`UNKNOWN_BASE`）、间接调用和 C++ 变体；下一步优先做容器抽象或调用相关函数过滤。
2. 剩余 FP 主要来自循环 flow variants 与 `fscanf` 数值输入分支；下一步应做“至少执行一次/循环归纳变量”推理，而不是放宽告警。
3. s01 的 9 个 inverted pair 来自复杂输入/控制流组合，当前没有 false-negative pair；后续重点是避免安全路径误报。
4. JSON/CSV 已保留诊断码，可按 `UNKNOWN_BASE`、`UNKNOWN_LENGTH`、`UNKNOWN_STRING_LENGTH` 建立增量回归门禁。
