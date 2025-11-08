import sys
import subprocess
import importlib
import os
from typing import Dict


PIP_PACKAGE_BY_IMPORT: Dict[str, str] = {
    "pandas": "pandas",
    "sklearn": "scikit-learn",
    "joblib": "joblib",
    "tldextract": "tldextract",
    # Only needed if you load Excel files (e.g., data/data-load.py)
    "openpyxl": "openpyxl",
}


def install_package(pip_name: str) -> None:
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", pip_name]
    subprocess.check_call(cmd)


def ensure_dependencies() -> None:
    missing = []
    for import_name, pip_name in PIP_PACKAGE_BY_IMPORT.items():
        try:
            importlib.import_module(import_name)
        except Exception:
            missing.append(pip_name)

    if not missing:
        return

    print(f"Installing missing packages: {', '.join(missing)}")
    for pip_name in missing:
        try:
            install_package(pip_name)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {pip_name}: {e}")
            sys.exit(1)


def run_training_script() -> int:
    project_root = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(project_root, "src", "train_model.py")
    if not os.path.exists(script_path):
        print(f"Could not find training script at: {script_path}")
        return 1

    return subprocess.call([sys.executable, script_path])


if __name__ == "__main__":
    ensure_dependencies()
    exit_code = run_training_script()
    sys.exit(exit_code)


