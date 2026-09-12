# Juliet CWE-190/191 整数溢出与下溢评测

> 数据集：`tests/testcases/CWE190_Integer_Overflow`、`tests/testcases/CWE191_Integer_Underflow`
> 运行环境：Docker Desktop，10 CPU / 约 7.75 GiB，8 workers
> 编译策略：`-fsigned-char`，`unsigned_int` family 单独使用 unsigned 类型边界

## 1. 复现命令

```bash
TEA121_INTEGER_CWES=190,191 \
TEA121_IMAGE=tea121-lite:llvm15 \
scripts/docker-evaluate-integer-cwes.sh
```

默认输出：

- `analysis-output/juliet-cwe190-all.json` / `.csv`
- `analysis-output/juliet-cwe191-all.json` / `.csv`

可限制 suite/flow：

```bash
TEA121_INTEGER_CWES=191 TEA121_SUITE=s01 TEA121_FLOW=01 \
  scripts/docker-evaluate-integer-cwes.sh
```

## 2. 数据规模

| CWE | suites | logical cases |
| --- | ---: | ---: |
| CWE-190 Integer Overflow | s01–s07 | 3,960 |
| CWE-191 Integer Underflow | s01–s05 | 2,952 |

runner 自动处理单文件、`51–68` split-file、`72–84` C++ 多文件 family，以及 `OMITBAD`/`OMITGOOD` side 宏。

## 3. 总体结果

| 指标 | CWE190 初始基线 | CWE190 当前 | CWE191 初始基线 | CWE191 当前 |
| --- | ---: | ---: | ---: | ---: |
| TP（bad alarm） | 799 | **3,128** | 865 | **2,388** |
| TN（good clean） | 2,711 | **2,603** | 1,761 | **2,334** |
| FP（good alarm） | 298 | **579** | 542 | **108** |
| FN（bad clean） | 2,240 | **85** | 1,435 | **51** |
| unsupported side | 1,872 | **1,525** | 1,301 | **1,023** |
| correct pair | 495 | **2,527** | 433 | **2,290** |
| false-positive pair | 298 | **569** | 432 | **96** |
| false-negative pair | 2,213 | **71** | 1,328 | **44** |
| conservative bad recall | 20.18% | **78.99%** | 29.30% | **80.89%** |
| conservative good silence | 68.46% | **65.73%** | 59.65% | **79.07%** |
| supported-only recall | 26.29% | **97.35%** | 37.61% | **97.91%** |
| supported-only specificity | 90.10% | **81.80%** | 76.47% | **95.58%** |

当前 precision 分别为 **84.38%**、**95.67%**，supported balanced accuracy 分别为 **89.58%**、**96.74%**。全量运行约 575 秒，无 error。

## 4. 按 suite

### CWE190

| suite | cases | correct | FP | FN | inverted | unsupported |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| s01 | 528 | 280 | 107 | 10 | 3 | 128 |
| s02 | 528 | 360 | 33 | 5 | 0 | 130 |
| s03 | 528 | 252 | 137 | 3 | 0 | 136 |
| s04 | 528 | 277 | 109 | 14 | 3 | 125 |
| s05 | 480 | 192 | 143 | 27 | 2 | 116 |
| s06 | 684 | 583 | 20 | 6 | 0 | 75 |
| s07 | 684 | 583 | 20 | 6 | 0 | 75 |

### CWE191

| suite | cases | correct | FP | FN | inverted | unsupported |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| s01 | 528 | 390 | 0 | 14 | 2 | 122 |
| s02 | 528 | 402 | 0 | 5 | 0 | 121 |
| s03 | 528 | 360 | 28 | 15 | 3 | 122 |
| s04 | 684 | 569 | 34 | 5 | 1 | 75 |
| s05 | 684 | 569 | 34 | 5 | 1 | 75 |

## 5. 实现要点

- LLVM 整数类型 signless，CLI 新增 `--integer-signedness`；runner 对 `unsigned_int` 自动使用 unsigned，并探测目标平台的 char signedness。
- 提取器保留 `zext`/`sext`/`trunc` 语义、整数位宽和 unsigned `icmp` 谓词。
- 中间溢出不再一律退化为 Top，而是回到类型完整范围，使后续 trunc/store 仍可判断方向。
- 溢出高于类型上界标为 CWE-190；低于下界标为 CWE-191，并输出 `integer_underflow`。
- `%c` 按一个字符的固定写入建模；数值 `fscanf` 按目标元素宽度写入。
- 评测层忽略 `RAND32/RAND64` 支撑宏所在行的 incidental alarm，避免把测试脚手架当作目标缺陷。
- `-fsigned-char` 使 AArch64 上的 Juliet char 语义与数据集意图一致。

## 6. 剩余缺口

1. CWE190 的 square 家族仍受 `abs(data) < sqrt((double)MAX)` guard 影响，缺少浮点/`sqrt` 常量摘要，当前 good 侧误报较多。
2. CWE190/CWE191 的 split-file `72–84` C++ 系列仍有大量 unsupported，主要是 STL/间接调用和跨 translation unit 内部状态。
3. `fscanf` 的 qualifier（例如 `%hhd`/`%lld`）目前主要通过目标元素宽度推断，格式字符串级别建模仍可加强。
4. `72–84` flow 的噪声与真实缺陷定位需要按函数/调用关联做进一步过滤。
