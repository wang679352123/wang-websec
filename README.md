# wang-websec

个人 Web 安全练习工具集（Python），仅用于本地靶场与已授权测试。

> ⚠️ 本项目仅用于安全学习与授权环境测试，禁止用于任何未经授权的系统。

## 项目简介

把手工做 Web 漏洞练习时重复的步骤脚本化。目前包含：

- 一个公共底座（HTTP 请求、参数解析、判断标志探测）
- 一个布尔盲注模块（二分猜解数据）
- 一个列数探测模块（order by 二分）

## 功能模块

| 文件 | 类 | 说明 |
|---|---|---|
| `sqli_blind.py` | `SQLInjection` | 公共底座：请求、参数、判断标志探测 |
| `Bool_sqli.py` | `BoolSQLi` | 布尔盲注：二分猜解 + 结果还原 |
| `time_bool.py` | `UnionInjection` | 列数探测：order by 二分 |

## 目录结构

```text
wang-websec/
├── sqli_blind.py   # 公共底座
├── Bool_sqli.py    # 布尔盲注
├── time_bool.py    # 列数探测（order by）
├── README.md
└── LICENSE
```

## 环境要求

- Python 3.8+
- 第三方依赖：`requests`

> `logging`、`re`、`threading`、`html` 属于 Python 标准库，无需安装。

```bash
pip install requests
```

## 快速开始

```bash
git clone https://github.com/wang679352123/wang-websec.git
cd wang-websec
```

### 示例 1：布尔盲注（sqli-labs Less-8）

```python
from Bool_sqli import BoolSQLi

with BoolSQLi(
    url="http://127.0.0.1:{port}/Less-8/?id=1",
    table_name="users",
    columns=["username", "password"],
    prefix="-1'",
    suffix=" -- ",
    op="OR",
) as tool:
    data = tool.run()      # 自动探测判断标志 + 二分猜解
    print(data)
```

### 示例 2：列数探测（order by）

```python
from time_bool import UnionInjection

g = UnionInjection(
        "http://localhost:{port}/Less-11/?uname=&passwd&submit=Submit",
        columns="password",
        prefix="admin'",

         op="or",
         method="POST",
         extra_params={"submit":"Submit","passwd":"admin"})
    print("列数:", g.action())
```

## 参数说明（公共底座）

| 参数 | 默认值 | 说明 |
|---|---|---|
| `url` | 必填 | 目标地址 |
| `method` | `"get"` | 请求方法：`get` / `post` |
| `body_type` | `"form"` | POST 请求体格式：`form` / `json` |
| `headers` | `None` | 自定义请求头，默认使用内置 UA |
| `prefix` | `"-1'"` | 注入点闭合前缀 |
| `suffix` | `" -- "` | 注释符后缀 |
| `op` | `"OR"` | 连接词：`AND` / `OR` |
| `table_name` | `"users"` | 要读取的表名 |
| `columns` | 必填 | 要读取的列名，字符串或列表 |
| `keyword` | `None` | 判断标志，`None` 表示自动探测 |
| `params_name` | `None` | 注入参数名，`None` 表示从 URL 自动解析 |
| `timeout` | `10` | 单次请求超时（秒） |
| `max_length` | `250` | 最多猜解的字符数 |
| `extra_params` | `None` | 除注入点外每次请求需携带的字段 |

## 工作原理

### 公共底座

1. 从 URL 或 `params_name` 确定候选参数；
2. 对每个参数发送 `1=1` 与 `1=2`，两次采样取交集，排除动态内容；
3. 找到“稳定且有区分度”的文字作为判断标志，并锁定注入参数。

### 布尔盲注

```sql
ascii(substr((select group_concat(列) from 表), 位置, 1)) > mid
```

在 0~127 内二分：页面含标志说明条件为真，字符大于 `mid`；否则记录 `mid` 并向下收窄。

### 列数探测

`order by N` 在 `N` 不超过列数时正常返回，超过时报错。用二分找到最大的合法 `N`，即列数。

## 已知限制

- 布尔盲注目前只支持 ASCII 0~127，暂不支持多字节字符
- 需要已知表名与列名
- 受 MySQL `group_concat_max_len` 限制，超长数据会被截断
- 列数探测需要页面有数据，`prefix` 要用有效 id
- 尚未实现时间盲注、联合注入、报错注入

## 后续计划

- [ ] 时间盲注模块
- [ ] 联合注入模块
- [ ] 报错注入模块

## 免责声明

本项目仅供安全学习、CTF 与已获得书面授权的测试使用。

使用者应自行确保测试行为合法合规，因滥用造成的后果由使用者自行承担。

## 许可证

见 [LICENSE](LICENSE) 文件。
