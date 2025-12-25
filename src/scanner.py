import ast
import os
import warnings
from multiprocessing import Pool

from .sql_detector import SQLInjectDetector


def scan_py_file(file_path):
    """
    scan a python file and return all risks
    Args:
        file_path (str): the path of python file
    Returns:
        list: a list of risk tuples, each tuple contains line number and risk description
    """
    # skip large file (threshold: 1MB, can be adjusted)
    try:
        file_size = os.path.getsize(file_path)
        if file_size > 1024 * 1024:
            print(f"[Skip] large file ({file_size/1024:.2f} KB): {file_path}")
            return []
    except Exception as e:
        print(f"[Warning] cannot get file size {file_path}: {e}")
        return []

    all_risks = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source_code = f.read()

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=SyntaxWarning, message="invalid escape sequence")
            tree = ast.parse(source_code, filename=file_path)

        sql_detector = SQLInjectDetector()
        sql_detector.visit(tree)
        all_risks = sql_detector.get_risks()
        return all_risks
    except Exception as e:
        print(f"[Error] scan file {file_path} failed: {e}")
        return []


def scan_dir(directory, batch_size=10):
    """
    scan a web project directory and return all risks
    Args:
        directory (str): the path of web project directory
        batch_size (int, optional): the number of files to scan in each batch. Defaults to 10.
    Returns:
        dict: a dict of risk files and risks, key is file path, value is risk list
    """
    py_file_list = []
    for root, _, files in os.walk(directory):
        for file_name in files:
            if file_name.endswith(".py"):
                full_file_path = os.path.abspath(os.path.join(root, file_name))
                py_file_list.append(full_file_path)

    risk_result_dict = {}
    if not py_file_list:
        print(f"[Info] No valid Python files found in directory: {directory}")
        return risk_result_dict

    with Pool(processes=os.cpu_count()) as pool:
        for batch_start in range(0, len(py_file_list), batch_size):
            batch_file_paths = py_file_list[batch_start: batch_start + batch_size]
            batch_risk_results = pool.map(scan_py_file, batch_file_paths)
            for file_path, risk_list in zip(batch_file_paths, batch_risk_results):
                if risk_list:
                    risk_result_dict[file_path] = risk_list

    return risk_result_dict