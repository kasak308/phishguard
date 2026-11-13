# PhishGuard

Machine-learning detection of phishing links, using the text of the URL alone.

**Live demo portfolio:** https://sites.google.com/view/phishguard-ai-mini-project

## What it does

PhishGuard converts a web link into 15 numeric features - length, host shape, dots,
hyphens, digits, the @ trick, IP host, HTTPS, bait words, risky top-level domains,
domain entropy, brand-in-subdomain and non-standard port - and classifies it as
legitimate or phishing. The last three features were added after Google Gemini
reviewed the original twelve and named them as missing; they lifted accuracy from
94.0% to 96.0%.

## Result

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Logistic Regression | 0.9111 | 0.9302 | 0.8889 | 0.9091 | 0.9717 |
| Random Forest | 0.9600 | 0.9520 | 0.9689 | 0.9604 | 0.9893 |

Best model: **Random Forest**, measured on 450 unseen links. Five-fold
cross-validation gave a mean F1 of 0.956.

## How to run

```bash
pip install -r requirements.txt
python dataset.py      # build the labelled URL corpus
python train.py        # train, evaluate and write figures
python predict.py      # score a few sample links
python app.py          # open http://127.0.0.1:8086
```

## Files

| File | Purpose |
|---|---|
| `dataset.py` | builds the labelled URL corpus |
| `features.py` | turns a URL into the 15 numeric features |
| `train.py` | trains both models, evaluates them, writes the figures |
| `predict.py` | command-line demo |
| `app.py` | Flask web interface |

## Data note

The dataset is generated from documented URL characteristics, not collected from
real users or a live feed, so no real phishing site is contacted or copied and the
brand names used are invented. It exists so the pipeline can be demonstrated end to
end and reproduced by anyone who clones the repository. The scores therefore
describe the model on this data and would shift on a live sample.

## Limitations

The model reads only the link text, so a phishing page hosted on a clean-looking
domain is invisible to it. This is a classroom prototype that should support a
human decision, never replace one.

---

Fundamentals of Artificial Intelligence - Practical 10 - Kasak Shah (KU202600053)
B.Tech Cyber Security, Unitedworld Institute of Technology, Karnavati University
