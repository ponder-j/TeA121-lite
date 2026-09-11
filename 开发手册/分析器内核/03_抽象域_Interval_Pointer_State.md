# 03 抽象域：Interval / Pointer / State（逐行）

> 前置：`01 原理`。本文逐函数读三个数据类：
> - `analyzer/src/tea121/domain/interval.py`（整数区间格）
> - `analyzer/src/tea121/domain/pointer.py`（指针抽象）
> - `analyzer/src/tea121/domain/state.py`（程序状态 = 多个 map + 不可达标记）
>
> 它们全部是 **frozen dataclass**：状态只增不改，任何更新都返回新对象。这保证了 worklist
> 迭代里"旧状态/新状态"可以安全地共存、比较、join。

---

## 1. `Interval`（interval.py，全文件 140 行）

### 1.1 表示法与构造器（9-41 行）

```python
@dataclass(frozen=True)
class Interval:
    lower: Optional[int] = None
    upper: Optional[int] = None
    bottom: bool = False
```

- `[lower, upper]` 是闭区间；`None` 表示开向无穷（docstring："None as an open infinity"）。
  所以 `Interval()` 即 `[None,None]` = Top；`Interval(0,None)` = `[0,+∞)`。
- `bottom` 是**显式旗标**：Bottom 必须和 Top 区分（否则 `[None,None]` 会被误读成 Top），
  这是引入 `bottom` 字段的原因（13-14 行注释）。
- `const(v)` = 单点 `[v,v]`；`range(lo,hi)` 在 `lo>hi` 时返回 Bottom（空区间）；`top()/bottom_value()` 见上。

### 1.2 属性（43-58 行）

- `is_top`：非 bottom 且两端都是 None；
- `is_bottom`：看旗标；
- `is_singleton`：非 bottom、两端相等（**常量**，很多精化逻辑靠它判断）；
- `__str__`：`Bottom` / `[-inf, 10]` 之类，给人读。

### 1.3 join（并）与 meet（交）

```python
def join(self, other):
    if self.bottom: return other
    if other.bottom: return self
    if self.is_top or other.is_top: return Interval.top()
    lower = min(self.lower, other.lower) if self.lower is not None and other.lower is not None else None
    upper = max(self.upper, other.upper) if self.upper is not None and other.upper is not None else None
    return Interval(lower, upper)
```

语义是"两个区间覆盖范围的并的最小包络"：
- `[0,2] ⊔ [1,5] = [0,5]` ✓
- `[0,2] ⊔ Bottom = [0,2]` ✓（Bottom 吸收为空）
- `[0,2] ⊔ [0,+∞) = [0,+∞)` ✓（任一端无穷，结果对应端仍为无穷）
- `Top ⊔ [0,2] = Top` ✓（Top 是吸收元）

```python
from tea121.domain import Interval
Interval(0,2).join(Interval(0,None))   # → [0, +inf)
Interval.top().join(Interval(0,2))     # → Top
```

`meet` 是并集的对偶运算：`[0,2] ⊓ [0,+∞) = [0,2]`，`Top ⊓ [0,2] = [0,2]`。

### 1.4 算术：add / sub / mul（86-102 行）

- `add`：用**同向端点相加** `(self.lower+other.lower, self.upper+other.upper)`；
- `sub`：注意是 **反向端点相减**：`[a,b] - [c,d] = [a-d, b-c]`（减法取最大跨度需要交叉）；
- `mul`：单点因子走 `_scale`，可保留因子的正负方向和另一侧的单侧无穷；两个一般区间都有限时取
  四个交叉乘积的 min/max（`[a,b]×[c,d]` 的最值必出现在端点组合上）；
- 三者共同点：任一操作数是 Bottom → Bottom；一侧端点未知时仍保留另一侧可证明的界，例如
  `[None,9] + 1 = [None,10]`、`[None,9] × 4 = [None,36]`；只有两侧都完全未知才直接 Top；
- 最后都过 `_bounded(lower, upper, bits, signed)`。

### 1.5 定宽溢出检查 `_bounded`（126-136 行）—— 关键的一行

```python
lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed \
    else (0, (1 << bits) - 1)
if not signed:
    lower = 0 if lower is None else lower
    upper = hi if upper is None else upper
if (lower is not None and lower < lo) or (upper is not None and upper > hi):
    return Interval.top()   # 可能溢出 → 不能假装没溢出
return Interval(lower, upper)
```

例如 32 位有符号 `add`：`[1, 2147483647] + [1,1]` 上界越界 → Top；而 `[None,9]+1`
可以保留 `[None,10]`，供后续分支/边界检查继续使用其上界。
这就是任务书"**按固定位宽解释整数运算；无法证明不溢出时提升为 Top，不能用数学整数结果证明访问安全**"
的实现。`bits=None`（比如手写 fixture 没给 bits）则不做溢出检查。

### 1.6 widen（104-111 行）

```python
lower = self.lower if other.lower is not None and self.lower is not None and other.lower >= self.lower else None
upper = self.upper if other.upper is not None and self.upper is not None and other.upper <= self.upper else None
```

外推规则：**这次没超出上次的界 → 保留；超出了（或这次已是无穷）→ 推到无穷**。
`widen([0,3],[0,4]) = [0,None]`（上界在长 → +∞）；`widen([0,3],[0,2]) = [0,3]`（反而收缩 → 保留）。
这就是循环变量第 4 轮从 `[0,3]` 变 `[0,+∞)` 的机制（见 06）。

### 1.7 narrow、精化与其它

- `narrow(other)` 对区间取交集，作为 widening 后的恢复算子；对当前区间域它与 `meet` 等价，
  但调用语义明确限定为"从 widened 上界向下收缩"；
- `refine_lower(v)` / `refine_upper(v)` = 与 `[v,+∞)` / `(-∞,v]` 做 meet（分支约束用）；
- `contains(v)`、`subset_of` 是判定辅助；文件尾 `TOP/BOTTOM` 是模块级快捷量。

---

> 重点修复（循环/分支增强）：`join` 的无穷吸收、单侧无穷算术、以及 `narrow` 三者共同保证
> 循环 widening 不再把 `[0,9]` 误退化成 Top；guard false 边收紧后，GEP 计算出的字节偏移仍能
> 保留 `[.., 36]` 这样的有限上界。

---

## 2. `PointerValue`（pointer.py，25 行整）

```python
@dataclass(frozen=True)
class PointerValue:
    bases: frozenset[str]          # 可能指向的栈/全局对象 id 集合（多基址）
    offset_bytes: Interval         # 距各基址的字节偏移区间
    unknown_base: bool             # 基址完全未知？
```

- `unknown()`：`unknown_base=True, offset=Top`，表示"不知道指哪"（外部声明指针的 load 等）。
- `join(other)`：bases 取并集、offset 取并、unknown 取或——两条路径合并后指针可能指向任一对象。
- 判定越界时，`_check_access` 对 **每个 base** 分别用同一个 offset 区间检查；
  offset 是"相对该对象"的偏移（多基址意味着对各对象用同一偏移判断，是保守近似）。

---

## 3. `MemoryObject`（state.py 10-15 行）

```python
@dataclass(frozen=True)
class MemoryObject:
    id: str
    size_bytes: Interval
    allocation_site: dict          # {function, block, instruction} 或 {"kind":"global"}
    escaped: bool = False
```

栈对象大小是**区间**（一般是个单点 `[10,10]`，但也可能来自不确定的 alloca count）。

---

## 4. `State`（state.py 18-99 行）：一个程序点上的完整抽象状态

### 4.1 字段（19-26 行）

| 字段 | 类型 | 装什么 |
|---|---|---|
| `integers` | `dict[str, Interval]` | SSA 名 → 整数区间 |
| `pointers` | `dict[str, PointerValue]` | SSA 名 → 指针抽象 |
| `memory_objects` | `dict[str, MemoryObject]` | 对象 id → 对象（大小/逃逸） |
| `string_lengths` | `dict[str, Interval]` | 对象 id → 已知字符串长度 |
| `reachable` | `bool` | False = 该路径不可达（Bottom 状态） |
| `reasons` | `tuple[str,...]` | 状态里蕴含的"为什么保守"的说明 |
| `scalar_memory` | `dict[(object_id, offset), Interval]` | 栈上标量摘要（store/load 常量传播） |

### 4.2 读取辅助 get_*（32-48 行）——操作数解析的统一入口

- `get_int(value)`：bool→`[1,1]/[0,0]`；int→单点；字符串→先试按 0 进制转 int
  （所以 MiniIR 里的数字常量操作数能直接查）；否则按 SSA 名查 `integers`，**查不到返回 Top**。
- `get_pointer(value)`：已是指针对象直接返回；字符串名查 `pointers`，查不到返回 `PointerValue.unknown()`。

> 注意：查不到整数返回 Top、查不到指针返回 unknown，与 `_check_access` 的兜底逻辑配套：
> "不在状态里"被当成"完全未知"，而不是"安全"。

### 4.3 写辅助 with_*（50-71 行）

全部是"拷贝 dict → 改一项 → `dataclasses.replace` 生成新 State"，维持不可变性。
`with_object` 登记/覆盖对象；`with_memory_int(object_id, value, offset)` 写标量摘要。

### 4.4 join（73-94 行）——按字段逐个并

```python
if not self.reachable: return other      # Bottom ⊔ x = x
if not other.reachable: return self
```

- `integers`：两边的键取并集，每个键 `self.get(k,Top) ⊔ other.get(k,Top)`；任一侧为 Top 时结果为 Top；
- `pointers`：**只并两边都有的键**（交集），再补上各自独有的（避免把缺失当成 unknown 去 join）；
- `memory_objects`：同 id 的对象合并 size、escaped 取或；只在一侧的出现保留；
- `string_lengths`、`scalar_memory`：与 integers 相同的按并集 join；
- `reachable=True`，`reasons` 去重拼接。

### 4.5 widen（96-99 行）——先 join 再对整数域 widen

```python
def widen(self, other):
    joined = self.join(other)          # 先把两边的键合到一起
    ints = {k: self.integers.get(k, Top).widen(joined.integers.get(k, Top)) for k in joined.integers}
    return replace(joined, integers=ints)
```

`join` 对无穷端点保持吸收性（Top/无穷不会被子集"拉回"有界），因此 widen 能真正推动循环状态收敛。
pointer/object/string/scalar 域不参与 widen（只有整数域被加宽），这是"只对循环变量加宽"的近似。

### 4.6 narrow（State.narrow）——widening 后的恢复

`State.narrow(other)` 对同类抽象域做 meet：整数/字符串/标量摘要取区间交集，引用明确时指针基址取交集、
偏移取交集，对象大小取交集；只可能缩小状态，不会重新引入 widening 已丢弃的界。
solver 在 widening 收敛后按前驱重新计算入口并执行 narrowing，然后再重放最终的访问检查。

---

## 5. 一句话串起来

> 一条指令的转移 = "读几个 get_* → 算新 Interval/PointerValue → with_* 生成新 State"；
> 一个基本块入口 = 各前驱出口状态**先沿边精化再 join**；
> 循环头反复访问时，出口状态用 `State.widen`（join + Interval.widen）外推以保证 worklist 终止。
> 抽象域就绪，下一份 `04` 讲真正的执行引擎。
