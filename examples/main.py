import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import scan_py_file


if __name__ == "__main__":
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), r"sql_dataset.py")

    a = scan_py_file(file_path)
    
    for line_no, risk_desc in a:
        print(f"line_no: {line_no}, risk_desc: {risk_desc}")
