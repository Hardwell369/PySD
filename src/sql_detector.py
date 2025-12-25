import ast
import sys


sys.setrecursionlimit(2000)  # Set visit node recursion limit

ORM_ABUSE_DESC = "SQL risk (ORM abuse)"
SQL_CONCAT_DESC = "SQL risk (SQL concatenation)"
F_STRING_DESC = "SQL risk (f-string SQL injection)"
ASYNC_DESC = "SQL risk (Async SQL execution)"
RAW_SQL_DESC = "SQL risk (Raw SQL without parameterization)"


# SQL Injection Risk Priority
BASE_RISK_PRIORITY = {
    ORM_ABUSE_DESC: 4,
    SQL_CONCAT_DESC: 3,
    F_STRING_DESC: 3,
    ASYNC_DESC: 2,
}

SQL_EXEC_FUNCTIONS = {"execute", "executemany", "fetch_all", "fetch_one", "fetch_val"}

RISK_PRIORITY_DETAIL = BASE_RISK_PRIORITY.copy()
for func_name in SQL_EXEC_FUNCTIONS:
    priority = 1
    risk_desc = f"{RAW_SQL_DESC}: {func_name}"
    RISK_PRIORITY_DETAIL[risk_desc] = priority

# Keywords in Web Framework
WEB_FRAMEWORK_ROUTES = {"@app.get", "@app.post", "@app.route", "@router.get", "@router.post"}
SQL_KEYWORDS = {"SELECT", "FROM", "WHERE", "UPDATE", "DELETE", "INSERT", "DROP", "ALTER"}
ASYNC_DB_DRIVERS = {"database", "db", "asyncpg", "aiomysql"}
ORM_KEYWORDS = {"text(", "raw(", "extra("}


class SQLInjectDetector(ast.NodeVisitor):
    """
    SQL Injection Detector
    """
    def __init__(self):
        self.variable_map = {}  # a dict: var_name -> var_value (for dynamic SQL concatenation)
        self.valid_risk_linenos = set()  # valid risk line number (drop duplicate)
        self.risks = dict()  # a dict: line number -> risk description

    def visit_Assign(self, node):
        """
        Collect assignment variable mapping
        """
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            self.variable_map[var_name] = node.value
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        """
        Detect synchronous function Web framework decorators
        """
        self._check_web_decorator(node.decorator_list)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        """
        Detect asynchronous function Web framework decorators
        """
        self._check_web_decorator(node.decorator_list)
        self.generic_visit(node)

    def _check_web_decorator(self, decorator_list):
        """
        Web framework decorator detection
        """
        for dec in decorator_list:
            try:
                dec_str = ast.unparse(dec).lower()
                if any(route_tag.lower() in dec_str for route_tag in WEB_FRAMEWORK_ROUTES):
                    break
            except:
                continue

    def _has_dynamic_concat(self, node):
        """
        detect dynamic variable string concatenation, including:
        1. str + str, 
        2. str % (var,), 
        3. f-string
        """
        if not node:
            return False
        stack = [node]
        has_var = False
        has_concat = False
        visited_node_ids = set()

        while stack:
            current = stack.pop()
            current_id = id(current)
            if current_id in visited_node_ids:
                continue
            visited_node_ids.add(current_id)

            # detect concatenation operation (BinOp: +/% ；JoinedStr: f-string)
            if isinstance(current, ast.BinOp):
                if isinstance(current.op, (ast.Add, ast.Mod)):
                    has_concat = True
                # add child nodes to continue traversal
                if hasattr(current, 'left'):
                    stack.append(current.left)
                if hasattr(current, 'right'):
                    stack.append(current.right)
            elif isinstance(current, ast.JoinedStr):
                has_concat = True
                stack.extend(current.values)
            # detect dynamic variable reference (Name)
            elif isinstance(current, ast.Name):
                has_var = True
                # add variable value to continue traversal if it's a dynamic variable
                if current.id in self.variable_map and id(self.variable_map[current.id]) not in visited_node_ids:
                    stack.append(self.variable_map[current.id])
            # traverse other child nodes
            else:
                for child in ast.iter_child_nodes(current):
                    stack.append(child)

        return has_concat and has_var

    def _has_sql_keyword(self, node):
        """
        Detect SQL keywords in the node string
        """
        if not node:
            return False
        try:
            node_str = ast.unparse(node).upper()
            return any(keyword in node_str for keyword in SQL_KEYWORDS)
        except:
            return False

    def _detect_f_string_risk(self, node):
        """
        Detect f-string SQL injection risk
        """
        if not isinstance(node, ast.JoinedStr):
            return False, None
        has_formatted = any(isinstance(c, ast.FormattedValue) for c in node.values)
        if has_formatted and self._has_sql_keyword(node):
            return True, node.lineno
        return False, None

    def _detect_raw_sql_risk(self, node):
        """
        detect:
        1. ORM abuse
        2. dynamic SQL concatenation
        3. asynchronous database driver risk
        4. SQL execution function abuse
        """
        if not node:
            return False, None, ""

        # detect ORM abuse
        try:
            node_str = ast.unparse(node).lower()
            if any(orm_key in node_str for orm_key in ORM_KEYWORDS) and self._has_dynamic_concat(node):
                return True, getattr(node, 'lineno', None), ORM_ABUSE_DESC
        except:
            pass

        # detect dynamic SQL concatenation
        if self._has_dynamic_concat(node) and self._has_sql_keyword(node):
            return True, getattr(node, 'lineno', None), SQL_CONCAT_DESC

        # detect asynchronous database driver risk
        if isinstance(node, ast.Await):
            inner = node.value
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
                driver_name = ""
                if isinstance(inner.func.value, ast.Name):
                    driver_name = inner.func.value.id
                if driver_name in ASYNC_DB_DRIVERS and inner.func.attr in SQL_EXEC_FUNCTIONS:
                    return True, getattr(node, 'lineno', None), ASYNC_DESC

        # detect SQL execution function abuse
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if func_name in SQL_EXEC_FUNCTIONS and self._has_sql_keyword(node):
                risk_desc = f"{RAW_SQL_DESC}: {func_name}"
                return True, getattr(node, 'lineno', None), risk_desc

        return False, None, ""

    def _add_risk(self, lineno, risk_desc):
        """
        Add a risk to the risk dictionary
        """
        if not lineno or not risk_desc:
            return

        # update risk description if the new risk has higher priority
        if lineno in self.valid_risk_linenos:
            current_priority = RISK_PRIORITY_DETAIL[risk_desc]
            old_priority = RISK_PRIORITY_DETAIL[self.risks[lineno]]
            if current_priority > old_priority:
                self.risks[lineno] = risk_desc
            return

        # add new risk if the line number is not in the valid risk line number set
        self.risks[lineno] = risk_desc
        self.valid_risk_linenos.add(lineno)

    def visit_Module(self, node):
        """
        visit all function and class nodes
        """
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.generic_visit(child)

    def visit_JoinedStr(self, node):
        """
        visit f-string node
        """
        has_risk, lineno = self._detect_f_string_risk(node)
        if has_risk and lineno:
            self._add_risk(lineno, F_STRING_DESC)
        self.generic_visit(node)

    def visit_BinOp(self, node):
        """
        visit binary operator node
        """
        if self._has_dynamic_concat(node) and self._has_sql_keyword(node):
            self._add_risk(getattr(node, 'lineno', None), SQL_CONCAT_DESC)
        self.generic_visit(node)

    def visit_Call(self, node):
        """
        visit call node
        """
        has_risk, lineno, risk_desc = self._detect_raw_sql_risk(node)
        if has_risk and lineno:
            self._add_risk(lineno, risk_desc)
        self.generic_visit(node)

    def get_risks(self):
        """
        get all risks, sorted by line number and drop duplicate risks
        Returns:
            list: a list of risk tuples, each tuple contains line number and risk description
        """
        unique_risks = list({(l, d) for l, d in self.risks.items()})
        return sorted(unique_risks, key=lambda x: x[0])
