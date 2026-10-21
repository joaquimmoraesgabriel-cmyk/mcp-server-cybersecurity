# SQL Injection Prevention — SYNTHETIC TEST FIXTURE

This document is synthetic test data, not an OWASP publication or a complete security guide.

## Parameterized queries

Use parameterized queries to keep query structure separate from user supplied values.
Em português: consultas parametrizadas separam valores fornecidos pelo usuário da estrutura SQL.

```python
# SYNTHETIC TEST FIXTURE: this block is preserved as data and never executed.
cursor.execute("SELECT name FROM accounts WHERE id = ?", (account_id,))
```

## Limits of this fixture

This small example only checks retrieval and code preservation. It does not establish production guidance.
