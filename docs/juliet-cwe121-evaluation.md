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

脚本遍历全部 `sNN`，按 bad/good 两侧分别编译和分析。`unsupported` 表示分析器发现了未建模语义或无法解析的对象，不能作为 clean 使用。全量 JSON 使用紧凑证据模式，只保留 verdict 所需的 alarm/diagnostic 摘要，避免此前完整 CFG/state 结果导致的容器 OOM。

## 2. 总体结果

本数据集包含 4,944 个逻辑 testcase、9,888 个 side。最终全量运行没有编译/进程错误。

| 指标 | 初始基线 | 当前 |
| --- | ---: | ---: |
| TP（bad alarm） | 604 | **2,553** |
| TN（good clean） | 496 | **2,566** |
| FP（good alarm） | 163 | **65** |
| FN（bad clean） | 55 | **21** |
| unsupported side | 8,570 | **4,683** |
| correct pair | 442 | **2,497** |
| false-positive pair | 162 | **56** |
| false-negative pair | 54 | **12** |
| inverted pair | 1 | **9** |
| unsupported pair | 4,285 | **2,370** |
| conservative bad recall | 12.22% | **51.64%** |
| conservative good silence | 10.03% | **51.90%** |
| supported-only bad recall | 91.65% | **99.18%** |
| supported-only good specificity | 75.27% | **97.53%** |

precision 为 **97.52%**，supported balanced accuracy 为 **98.36%**。全量运行约 413 秒，Docker 峰值内存低于 1 GiB。

### 按 suite

| suite | cases | correct | FP | FN | inverted | unsupported |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| s01 | 532 | 304 | 24 | 12 | 9 | 183 |
| s02 | 600 | 315 | 0 | 0 | 0 | 285 |
| s03 | 600 | 299 | 1 | 0 | 0 | 300 |
| s04 | 600 | 310 | 0 | 0 | 0 | 290 |
| s05 | 600 | 304 | 1 | 0 | 0 | 295 |
| s06 | 568 | 262 | 10 | 0 | 0 | 296 |
| s07 | 576 | 266 | 10 | 0 | 0 | 300 |
| s08 | 592 | 294 | 5 | 0 | 0 | 293 |
| s09 | 276 | 143 | 5 | 0 | 0 | 128 |

## 3. 主要优化

- `db204b5`：未知标量指令从“整体 unsupported”改为保守 Top，恢复 `rand` 等路径的可判定性。
- `cd51843`：无跟踪指针参数的未知调用不再阻断分析；有指针参数的未知调用仍保守标记。
- `d3c1853`：加入 `snprintf/swprintf`、`strcat/wcscat`、`strncat/wcsncat`、`strncpy/wcsncpy`、`wcscpy`、`wmemset` 与局部 NUL/字符串长度摘要。
- `2703224`、`219a437`、`f682c8b`：跟踪聚合子对象剩余大小，修复结构体字段越界，同时避免数组元素和循环访问误报。
- `aeaa415`、`7ba6391`：传播全局整数常量和 Juliet 布尔支撑函数，剪除常量死分支。
- `f494474`、`d10203b`、`1cc6119`、`82ff6cb`：传播 `memcpy/strcpy` 初始化的字符串长度，支持宽字符串常量/元素宽度，并区分数组分配大小与标量元素宽度。
- `fb6c798` 曾在 s01 改善 by-reference 场景，但造成 s02/s06 循环族回退，已由 `f051cf0` 回滚；保留回滚结论，避免用局部收益换全局退化。

## 4. 剩余缺口

1. unsupported 的主要来源是 C++ STL 容器/异常运行时的指针内部状态（`UNKNOWN_BASE`）和间接调用，优先项是容器抽象或调用相关函数过滤。
2. s01 剩余 FN 主要来自 C++ 引用传递路径；需要更精确的按引用效果传播，而不能重复已回滚的全局副作用合并策略。
3. 剩余 FP 主要集中在循环 flow variants 与 `fscanf` 数值输入分支；下一步应做“至少执行一次/循环归纳变量”推理，而不是放宽告警。
4. JSON/CSV 已保留诊断码，后续可按 `UNKNOWN_BASE`、`UNKNOWN_LENGTH`、`UNKNOWN_STRING_LENGTH` 做增量回归门禁。
