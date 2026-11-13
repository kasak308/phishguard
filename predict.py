"""Command-line demo: score a few URLs with the trained PhishGuard model."""
import os, sys
import joblib
import numpy as np
from features import extract

HERE = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(HERE, "model.joblib"))

SAMPLES = [
    "https://unilibrary.ac.in/courses/ai",
    "http://192.168.44.10/secure/login.php4821",
    "https://campusmail.com/account/settings",
    "http://verify.signin.statebank.tk/account/suspended",
    "https://medplus.in@k3f9xqp2vd7m.click/login",
    "https://cityhospital-student-portal-2025.ac.in/login/verify",
]


def score(url):
    x = np.array([extract(url)], dtype=float)
    p = float(model.predict_proba(x)[0][1])
    return p, ("PHISHING" if p >= 0.5 else "legitimate")


if __name__ == "__main__":
    urls = sys.argv[1:] or SAMPLES
    print("%-62s %-11s %s" % ("URL", "VERDICT", "RISK"))
    print("-" * 86)
    for u in urls:
        p, verdict = score(u)
        print("%-62s %-11s %5.1f%%" % (u[:62], verdict, p * 100))
