"""
Evaluation Metrics Generator — CyberShield / ET AI Hackathon PS7

Produces REAL numbers for your PPT/PDF instead of claims. Judges score on:
  - Anomaly/threat detection rate & false positive rate
  - Detection accuracy
  - MTTD-style timing (time to classify)

This script evaluates your EXISTING RF+GB phishing model (detection-engine/app/ml)
against a held-out labeled test set and writes results to metrics.json + a
markdown table you can paste straight into slides.

USAGE:
    cd detection-engine
    python scripts/evaluation_metrics.py

WHAT YOU NEED TO PLUG IN (marked below with TODO):
    1. `load_model_and_features()` — import your actual trained model + the
       function that turns a URL into your 20 features. These already exist
       in app/ml/train_model.py and your prediction pipeline.
    2. A labeled test set. If you don't have one, this script FALLS BACK to
       generating one from well-known safe domains + known phishing-pattern
       URLs, so it still runs and produces real (if smaller-scale) numbers
       instead of nothing.
"""

import json
import time
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "evaluation_output"
OUTPUT_DIR.mkdir(exist_ok=True)


def load_model_and_features():
    """
    TODO: Replace this with your real imports, e.g.:
        from app.ml.predict import predict_url, extract_features
        return predict_url
    Must return a function: predict(url: str) -> dict with at least
    {"is_phishing": bool, "score": float}
    """
    try:
        from app.ml.predict import predict_url  # your actual module
        return predict_url
    except Exception as e:
        print(f"[WARN] Could not import real model ({e}). Using stub predictor "
              f"so the script still runs — REPLACE THIS before final submission.")

        def stub_predict(url: str):
            suspicious_signals = ["login", "verify", "secure", "@", "-update",
                                   "account", ".xyz", ".top", "bit.ly"]
            score = sum(1 for s in suspicious_signals if s in url.lower()) / len(suspicious_signals)
            return {"is_phishing": score > 0.15, "score": score}

        return stub_predict


def get_labeled_test_set():
    """
    TODO: Replace with your real held-out test split (the one your
    train_model.py sets aside, or a fresh labeled sample you didn't train on).
    Fallback set below is illustrative only — swap in real data for a
    defensible number in front of judges.
    """
    safe = [
        "https://www.google.com", "https://github.com", "https://www.wikipedia.org",
        "https://www.microsoft.com", "https://www.python.org", "https://www.nic.in",
        "https://www.rbi.org.in", "https://uidai.gov.in", "https://www.iitb.ac.in",
        "https://www.amazon.in",
    ]
    phishing = [
        "http://paypal-secure-login.xyz/verify", "http://192.168.44.12/login",
        "http://account-update-microsoft.top/reset", "http://bit.ly/verify-account-now",
        "http://secure-login.paypal.com.malicious-domain.ru",
        "http://icloud-verify-account.com/login", "http://sbi-online-update.xyz",
        "http://hdfcbank-secure-alert.top/verify", "http://gov-in-refund.xyz/claim",
        "http://amaz0n-account-suspended.com/login",
    ]
    return [(u, 0) for u in safe] + [(u, 1) for u in phishing]


def compute_metrics(predict_fn, test_set):
    tp = fp = tn = fn = 0
    latencies = []

    for url, true_label in test_set:
        start = time.time()
        result = predict_fn(url)
        latencies.append(time.time() - start)

        pred_label = 1 if result["is_phishing"] else 0
        if pred_label == 1 and true_label == 1:
            tp += 1
        elif pred_label == 1 and true_label == 0:
            fp += 1
        elif pred_label == 0 and true_label == 0:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0  # = detection rate
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    avg_latency_ms = (sum(latencies) / len(latencies)) * 1000 if latencies else 0.0

    return {
        "sample_size": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall_detection_rate": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_detection_latency_ms": round(avg_latency_ms, 2),
    }


def write_outputs(metrics: dict):
    with open(OUTPUT_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    md = f"""## CyberShield — Detection Performance (Evaluation Set: {metrics['sample_size']} URLs)

| Metric | Value |
|---|---|
| Detection Rate (Recall) | {metrics['recall_detection_rate']*100:.1f}% |
| False Positive Rate | {metrics['false_positive_rate']*100:.1f}% |
| Precision | {metrics['precision']*100:.1f}% |
| F1 Score | {metrics['f1_score']*100:.1f}% |
| Accuracy | {metrics['accuracy']*100:.1f}% |
| Avg. Detection Latency | {metrics['avg_detection_latency_ms']:.1f} ms |

_Confusion matrix — TP: {metrics['true_positives']}, FP: {metrics['false_positives']}, TN: {metrics['true_negatives']}, FN: {metrics['false_negatives']}_
"""
    with open(OUTPUT_DIR / "metrics_table.md", "w") as f:
        f.write(md)

    print(md)
    print(f"\nWritten to: {OUTPUT_DIR/'metrics.json'} and {OUTPUT_DIR/'metrics_table.md'}")
    print("IMPORTANT: swap in your real model + real held-out test set before "
          "quoting these numbers to judges. Stub numbers are for structure only.")


if __name__ == "__main__":
    predict_fn = load_model_and_features()
    test_set = get_labeled_test_set()
    metrics = compute_metrics(predict_fn, test_set)
    write_outputs(metrics)