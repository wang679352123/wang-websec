# wang-websec

个人 Web 安全练习工具集（Python），仅用于本地靶场与已授权测试。

> ⚠️ 本项目仅用于安全学习与授权环境测试，禁止用于任何未经授权的系统。

## 项目简介

把手工做 Web 漏洞练习时重复的步骤脚本化，目前包含一个**布尔盲注自动化**模块：

- 自动判定注入参数与判断标志
- 二分查找逐字符猜解数据
- 结果自动还原为 `{用户名: 密码}`

## 已实现

| 模块 | 文件 | 说明 |
|---|---|---|
| 布尔盲注 | `sqli_blind.py` | 支持 GET/POST、表单/JSON、自定义前缀/注释符/连接词 |

## 目录结构

```text
wang-websec/
├── sqli_blind.py   # 布尔盲注自动化
├── README.md
└── LICENSE
```

## 环境要求

- Python 3.8+
- 第三方依赖：`requests`

> `logging`、`re`、`threading` 属于 Python 标准库，无需安装。

```bash
pip install requests
```

## 快速开始

```bash
git clone https://github.com/wang679352123/wang-websec.git
cd wang-websec
```

### 示例 1：sqli-labs

```python
from sqli_blind import SQLInjection

with SQLInjection(
    url="http://127.0.0.1:{port}/Less-8/?id=1",  # 注入参数可手动传入，也可由脚本自动获取,将{port}改为实际端口，比如:8080
    table_name="users",
    columns=["username", "password"],
    prefix="-1'",
    suffix=" -- ",
    op="OR",
) as tool:
    tool.detect_keyword()
    data = tool.blind_sql()
    print(data)
```

### 示例 2：pikachu

```python
from sqli_blind import SQLInjection

tool = SQLInjection(
    url="http://127.0.0.1/pikachu/vul/sqli/sqli_blind_b.php",
    params_name="name",
    table_name="users",
    columns=["username", "password"],
    extra_params={"submit": "查询"},  # 需要额外提交的字段
)
```

## 参数说明

| 参数 | 示例 | 说明 |
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

1. **判定注入点**：对每个参数发送 `1=1` 与 `1=2`，比较响应差异；
2. **找判断标志**：真假各请求两次，取“两次真都有、两次假都没有”的稳定文本；
3. **二分猜字符**：构造 `ascii(substr((select group_concat(列) from 表), 位置, 1)) > mid`，在 0~127 内折半；
4. **还原结果**：按 `group_concat` 的逗号、`concat_ws` 的冒号拆分为字典。

单个字符约 7 次请求，相比线性猜解显著减少请求量。

## 已知限制

- 仅支持布尔盲注，暂不支持时间盲注与报错注入
- 需要已知表名与列名
- 受 MySQL `group_concat_max_len` 限制，超长数据会被截断
- 二分范围为 ASCII 0~127，暂不支持多字节字符

## 后续计划

- [ ] 时间盲注模块
- [ ] 报错注入模块
- [ ] 更多 Web 漏洞检测模块

## 免责声明

本项目仅供安全学习、CTF 与已获得书面授权的测试使用。

使用者应自行确保测试行为合法合规，因滥用造成的后果由使用者自行承担。

## 许可证

见 [LICENSE](LICENSE) 文件。
