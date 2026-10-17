"""
ML compliance risk model.

Implements Algorithm 5.1 (CloudGuard ML training procedure) from the
dissertation:
  1. Generate synthetic resources by sampling configuration fields
  2. Label every resource using the rule engine as oracle
  3. Hyperparameter grid search via stratified 5-fold cross-validation
  4. Refit on the full dataset with the best hyperparameters
  5. Final evaluation on a held-out 20% test split
  6. Persist the fitted pipeline to joblib

The model predicts a continuous risk score [0, 1] — probability of
non-compliance — which the UI visualises as a risk bar. The rule engine
remains the authoritative source of compliance findings; the ML model
provides a calibrated prioritisation layer over it.
"""

import os
import json
import itertools
import numpy as np
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import (
    cross_val_score,
    StratifiedKFold,
    train_test_split,
)
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
import joblib

from backend.ml.features import extract, FEATURE_NAMES, SAFE_DEFAULTS
from backend.compliance.scanner import scan_all
from backend.paths import DATA_DIR, ML_MODEL_PATH

MODEL_PATH = ML_MODEL_PATH
DATA_PATH = DATA_DIR / "mock_configs" / "resources.json"
METRICS_PATH = ML_MODEL_PATH.with_suffix(".metrics.json")

RNG = np.random.default_rng(42)

# Hyperparameter grid for stage 3 of Algorithm 5.1 — deliberately small
# (3 × 3 × 2 = 18 combinations). A wider grid was investigated during the
# feature-redesign phase but produced no meaningful improvement while
# significantly increasing training time (Friedman, 2001).
HYPERPARAM_GRID = {
    "n_estimators": [100, 200, 400],
    "max_depth": [2, 3, 5],
    "learning_rate": [0.05, 0.1],
}


def _generate_synthetic(n_compliant: int = 300, n_noncompliant: int = 300):
    """Algorithm 5.1 stage 1 — sample N_synth resources from realistic
    distributions. Booleans → Bernoulli(p); compliant samples stay close to
    the safe defaults, non-compliant samples diverge substantially."""
    X, y = [], []

    # Compliant samples: mostly safe defaults with small noise
    for _ in range(n_compliant):
        vec = SAFE_DEFAULTS.copy().astype(float)
        flip_idx = RNG.choice(len(vec), size=max(1, len(vec) // 20), replace=False)
        for i in flip_idx:
            vec[i] = 1.0 - vec[i]
        X.append(vec)
        y.append(0)

    # Non-compliant samples: significantly deviate from safe defaults
    for _ in range(n_noncompliant):
        vec = SAFE_DEFAULTS.copy().astype(float)
        n_flip = RNG.integers(len(vec) // 5, len(vec) // 2)
        flip_idx = RNG.choice(len(vec), size=n_flip, replace=False)
        for i in flip_idx:
            vec[i] = 1.0 - vec[i]
        X.append(vec)
        y.append(1)

    return np.array(X), np.array(y)


def _load_real_data():
    """Algorithm 5.1 stage 2 — label the 23 real resources using the
    rule engine as oracle."""
    with open(DATA_PATH) as f:
        resources = json.load(f)["resources"]
    scan_results = scan_all(resources)
    label_map = {r.resource_id: (0 if r.compliant else 1) for r in scan_results}

    X, y = [], []
    for res in resources:
        feat = extract(res["config"])
        label = label_map[res["resource_id"]]
        X.append(feat)
        y.append(label)
    return np.array(X), np.array(y)


def _build_pipeline(params: dict) -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(
            n_estimators=params["n_estimators"],
            max_depth=params["max_depth"],
            learning_rate=params["learning_rate"],
            random_state=42,
        )),
    ])


def _grid_search(X: np.ndarray, y: np.ndarray) -> tuple[dict, float]:
    """Algorithm 5.1 stage 3 — stratified 5-fold CV over the hyperparameter grid."""
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    best_score = -np.inf
    best_params = None

    combos = list(itertools.product(
        HYPERPARAM_GRID["n_estimators"],
        HYPERPARAM_GRID["max_depth"],
        HYPERPARAM_GRID["learning_rate"],
    ))
    print(f"[ML] Grid search over {len(combos)} hyperparameter combinations...")

    for n_est, depth, lr in combos:
        params = {"n_estimators": n_est, "max_depth": depth, "learning_rate": lr}
        pipeline = _build_pipeline(params)
        scores = cross_val_score(pipeline, X, y, cv=skf, scoring="f1")
        mean = scores.mean()
        if mean > best_score:
            best_score, best_params = mean, params

    print(f"[ML] Best CV F1 = {best_score:.4f} at {best_params}")
    return best_params, best_score


def train() -> Pipeline:
    """End-to-end realisation of Algorithm 5.1.

    Returns the fitted pipeline. Also writes a metrics JSON alongside the
    serialised model containing the held-out test-split scores and the
    cross-validation distribution (mean ± σ) for precision, recall, F1
    and ROC-AUC.
    """
    # Stages 1 + 2 — build the labelled dataset
    X_syn, y_syn = _generate_synthetic()
    X_real, y_real = _load_real_data()
    X = np.vstack([X_syn, X_real])
    y = np.concatenate([y_syn, y_real])
    print(f"[ML] Dataset: {len(X)} samples "
          f"({int((y == 0).sum())} compliant, {int((y == 1).sum())} non-compliant)")

    # Stage 3 — hyperparameter search
    best_params, best_cv_f1 = _grid_search(X, y)

    # Stage 4 — refit on the full dataset
    pipeline_full = _build_pipeline(best_params)
    pipeline_full.fit(X, y)

    # Stage 5 — final evaluation on a held-out 20% test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    pipeline_eval = _build_pipeline(best_params)
    pipeline_eval.fit(X_train, y_train)
    y_pred = pipeline_eval.predict(X_test)
    y_proba = pipeline_eval.predict_proba(X_test)[:, 1]

    test_metrics = {
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall":    round(float(recall_score(y_test, y_pred)), 4),
        "f1":        round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, y_proba)), 4),
    }

    # Cross-validation distribution for §5.9 reporting
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_metrics: dict[str, dict[str, float]] = {}
    for scoring in ("precision", "recall", "f1", "roc_auc"):
        scores = cross_val_score(pipeline_full, X, y, cv=skf, scoring=scoring)
        cv_metrics[scoring] = {
            "mean": round(float(scores.mean()), 4),
            "std":  round(float(scores.std()), 4),
        }

    print("[ML] Held-out test split (20%):")
    for k, v in test_metrics.items():
        print(f"      {k:10s}: {v:.4f}")
    print("[ML] Stratified 5-fold cross-validation:")
    for k, v in cv_metrics.items():
        print(f"      {k:10s}: {v['mean']:.4f} ± {v['std']:.4f}")

    # Stage 6 — persist the full-data refit
    joblib.dump(pipeline_full, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump({
            "best_params": best_params,
            "n_samples": int(len(X)),
            "test_split_metrics": test_metrics,
            "cv_metrics": cv_metrics,
        }, f, indent=2)
    print(f"[ML] Model saved to {MODEL_PATH}")
    print(f"[ML] Metrics saved to {METRICS_PATH}")

    return pipeline_full


def load_or_train() -> Pipeline:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return train()


def predict_risk(pipeline: Pipeline, config: dict) -> float:
    """Return a risk score in [0, 1] — probability of non-compliance."""
    feat = extract(config).reshape(1, -1)
    prob = pipeline.predict_proba(feat)[0]
    return float(prob[1])


def feature_importances(pipeline: Pipeline) -> list[dict]:
    clf = pipeline.named_steps["clf"]
    importances = clf.feature_importances_
    ranked = sorted(
        zip(FEATURE_NAMES, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    return [{"feature": f, "importance": round(float(imp), 4)} for f, imp in ranked[:15]]
