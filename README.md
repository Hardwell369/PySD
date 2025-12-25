# Introduction
all source code is in the `src` directory.
- sql_detector.py: visit the AST of the input code and detect SQL injection risks.
- scanner.py: scan the input code and return all SQL injection risks results.

in the `examples` directory, you can find some example code to demonstrate how to use the SQL detector.
- sql_dataset.py: some example code to show the SQL injection risks.
- main.py: run the example code to detect SQL injection risks in `sql_dataset.py`.

# Quick Start
you don't need to install any dependencies. just run the following command:
first of all, cd to the project directory.
```bash
cd SQL_detector
```
and then, run the example code.
```bash
python -m examples.main
```