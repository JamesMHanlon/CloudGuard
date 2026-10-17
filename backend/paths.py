"""
Central path resolver — works in both dev mode and PyInstaller bundle.

In dev:      BASE_DIR = project root  (e.g. D:/Coding/Uniwork/Dis)
In bundle:   BASE_DIR = sys._MEIPASS  (PyInstaller _internal/ directory)
"""

import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    # Running inside a PyInstaller bundle
    BASE_DIR = Path(sys._MEIPASS)
else:
    # Running normally — two levels up from this file (backend/paths.py → project root)
    BASE_DIR = Path(__file__).parent.parent

DATA_DIR      = BASE_DIR / "data"
FRONTEND_DIR  = BASE_DIR / "frontend"
ML_MODEL_PATH = BASE_DIR / "backend" / "ml" / "trained_model.joblib"
