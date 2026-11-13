"""Trains and evaluates PhishGuard, and writes the figures used in the report."""
import csv, json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, roc_curve, auc,
                             classification_report)
import joblib

from features import extract_many, FEATURE_NAMES

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = os.path.join(HERE, "figures")
os.makedirs(FIG, exist_ok=True)

with open(os.path.join(HERE, "urls.csv")) as f:
    rows = list(csv.DictReader(f))
urls = [r["url"] for r in rows]
y = np.array([int(r["label"]) for r in rows])
X = np.array(extract_many(urls), dtype=float)
print("dataset:", X.shape, "phishing:", int(y.sum()), "legitimate:", int((1 - y).sum()))

Xtr, Xte, ytr, yte, utr, ute = train_test_split(
    X, y, urls, test_size=0.25, random_state=42, stratify=y)

models = {
    "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
    "Random Forest": RandomForestClassifier(n_estimators=250, random_state=42),
}

results = {}
for name, model in models.items():
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    proba = model.predict_proba(Xte)[:, 1]
    cv = cross_val_score(model, X, y, cv=5, scoring="f1")
    results[name] = {
        "accuracy": round(accuracy_score(yte, pred), 4),
        "precision": round(precision_score(yte, pred), 4),
        "recall": round(recall_score(yte, pred), 4),
        "f1": round(f1_score(yte, pred), 4),
        "cv_f1_mean": round(cv.mean(), 4),
        "cv_f1_std": round(cv.std(), 4),
        "confusion": confusion_matrix(yte, pred).tolist(),
    }
    fpr, tpr, _ = roc_curve(yte, proba)
    results[name]["auc"] = round(auc(fpr, tpr), 4)
    results[name]["_roc"] = (fpr.tolist(), tpr.tolist())
    print("\n==", name, "==")
    print(classification_report(yte, pred, target_names=["legitimate", "phishing"], digits=4))

best_name = max(results, key=lambda k: results[k]["f1"])
best = models[best_name]
print("best model:", best_name)

# ---- figure 1: ROC curves -------------------------------------------------
plt.figure(figsize=(5.2, 4))
for name in results:
    fpr, tpr = results[name]["_roc"]
    plt.plot(fpr, tpr, lw=2, label="%s (AUC %.3f)" % (name, results[name]["auc"]))
plt.plot([0, 1], [0, 1], "k--", lw=1)
plt.xlabel("False positive rate"); plt.ylabel("True positive rate")
plt.title("ROC curve - PhishGuard"); plt.legend(loc="lower right", fontsize=8)
plt.tight_layout(); plt.savefig(os.path.join(FIG, "roc.png"), dpi=160); plt.close()

# ---- figure 2: confusion matrix of the best model -------------------------
cm = np.array(results[best_name]["confusion"])
plt.figure(figsize=(4.2, 3.8))
plt.imshow(cm, cmap="Blues")
for i in range(2):
    for j in range(2):
        plt.text(j, i, cm[i, j], ha="center", va="center",
                 color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=13)
plt.xticks([0, 1], ["legitimate", "phishing"]); plt.yticks([0, 1], ["legitimate", "phishing"])
plt.xlabel("Predicted"); plt.ylabel("Actual"); plt.title("Confusion matrix - " + best_name)
plt.tight_layout(); plt.savefig(os.path.join(FIG, "confusion.png"), dpi=160); plt.close()

# ---- figure 3: feature importance ----------------------------------------
rf = models["Random Forest"]
imp = rf.feature_importances_
order = np.argsort(imp)
plt.figure(figsize=(5.6, 4))
plt.barh([FEATURE_NAMES[i] for i in order], imp[order], color="#2a6ebb")
plt.xlabel("Importance"); plt.title("Which URL features matter most")
plt.tight_layout(); plt.savefig(os.path.join(FIG, "importance.png"), dpi=160); plt.close()

joblib.dump(best, os.path.join(HERE, "model.joblib"))
for r in results.values():
    r.pop("_roc", None)
with open(os.path.join(HERE, "metrics.json"), "w") as f:
    json.dump({"best": best_name, "results": results,
               "top_features": [FEATURE_NAMES[i] for i in np.argsort(imp)[::-1][:5]]}, f, indent=2)
print(json.dumps(results, indent=2))
