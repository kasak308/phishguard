"""Minimal web interface for PhishGuard."""
import os
import joblib
import numpy as np
from flask import Flask, request, render_template_string
from features import extract, FEATURE_NAMES

HERE = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(HERE, "model.joblib"))
app = Flask(__name__)

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>PhishGuard</title>
<style>
 body{font-family:system-ui,Segoe UI,Arial;background:#0f1724;color:#e8eef7;margin:0;padding:40px}
 .card{max-width:720px;margin:0 auto;background:#172234;border-radius:14px;padding:28px 32px;
       box-shadow:0 8px 30px rgba(0,0,0,.4)}
 h1{margin:0 0 4px;font-size:26px} .sub{color:#8fa3bf;margin-bottom:22px;font-size:14px}
 input[type=text]{width:100%;padding:12px 14px;border-radius:8px;border:1px solid #2c3d57;
       background:#101a29;color:#e8eef7;font-size:15px;box-sizing:border-box}
 button{margin-top:12px;padding:11px 22px;border:0;border-radius:8px;background:#2a6ebb;
       color:#fff;font-size:15px;cursor:pointer}
 .verdict{margin-top:24px;padding:18px;border-radius:10px;font-size:19px;font-weight:600}
 .bad{background:#3a1420;border:1px solid #7d2440;color:#ff9db0}
 .good{background:#10281c;border:1px solid #1f6b43;color:#79e0a8}
 table{width:100%;margin-top:18px;border-collapse:collapse;font-size:13px}
 td,th{padding:6px 8px;border-bottom:1px solid #243247;text-align:left}
 th{color:#8fa3bf;font-weight:500}
</style></head><body><div class="card">
<h1>PhishGuard</h1>
<div class="sub">Machine-learning check for suspicious web links &middot; FAI Mini Project</div>
<form method="post">
  <input type="text" name="url" placeholder="Paste a link, e.g. http://verify.login.bank.tk/account"
         value="{{ url or '' }}" autofocus>
  <button type="submit">Check this link</button>
</form>
{% if url %}
  <div class="verdict {{ 'bad' if risk >= 50 else 'good' }}">
    {{ 'Likely PHISHING' if risk >= 50 else 'Looks legitimate' }} &mdash; risk score {{ risk }}%
  </div>
  <table><tr><th>Feature</th><th>Value</th></tr>
  {% for n, v in feats %}<tr><td>{{ n }}</td><td>{{ v }}</td></tr>{% endfor %}
  </table>
{% endif %}
</div></body></html>"""


@app.route("/", methods=["GET", "POST"])
def index():
    url = request.form.get("url", "").strip()
    risk, feats = None, []
    if url:
        vec = extract(url)
        risk = round(float(model.predict_proba(np.array([vec], dtype=float))[0][1]) * 100, 1)
        feats = list(zip(FEATURE_NAMES, vec))
    return render_template_string(PAGE, url=url, risk=risk, feats=feats)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8086)
