"""Builds the labelled URL corpus used to train PhishGuard.

The corpus is generated from documented URL characteristics rather than
collected from a live feed, so no real phishing site is contacted or copied.
Brand names are invented placeholders.
"""
import csv
import os
import random

random.seed(42)

SAFE_BRANDS = ["campusmail", "unilibrary", "cityhospital", "statebank", "bookdepot",
               "weatherlive", "newsdaily", "codehub", "medplus", "travelgo",
               "foodcart", "sportzone", "musicbay", "photolab", "cloudnotes"]
SAFE_TLDS = [".com", ".org", ".net", ".in", ".edu.in", ".ac.in", ".gov.in"]
SAFE_PATHS = ["", "/about", "/login", "/contact", "/help/faq", "/products",
              "/blog/2026/march", "/account/settings", "/search?q=books",
              "/courses/ai", "/news/latest", "/docs/getting-started"]

BAD_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click"]
BAIT = ["secure", "verify", "update", "confirm", "login", "account", "signin",
        "webscr", "recovery", "alert", "billing", "wallet"]
BAD_PATHS = ["/verify-account", "/secure/login.php", "/update-billing",
             "/confirm.php?id=", "/webscr?cmd=_login", "/account/suspended",
             "/session/expired", "/recover/password.php"]


def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(11, 220), random.randint(0, 255),
                            random.randint(0, 255), random.randint(2, 254))


def make_safe():
    brand = random.choice(SAFE_BRANDS)
    host = brand + random.choice(SAFE_TLDS)
    if random.random() < 0.35:
        host = random.choice(["www", "mail", "docs", "shop"]) + "." + host
    scheme = "https://" if random.random() < 0.9 else "http://"
    return scheme + host + random.choice(SAFE_PATHS)


def make_phish():
    style = random.randint(0, 5)
    brand = random.choice(SAFE_BRANDS)
    scheme = "http://" if random.random() < 0.75 else "https://"
    if style == 0:                                   # raw IP address host
        return scheme + rand_ip() + random.choice(BAD_PATHS) + str(random.randint(100, 9999))
    if style == 1:                                   # bait words in a long subdomain
        subs = ".".join(random.sample(BAIT, random.randint(2, 3)))
        return scheme + subs + "." + brand + "." + random.choice(BAD_TLDS).lstrip(".") + \
            random.choice(BAD_PATHS)
    if style == 2:                                   # brand pushed into the path
        return scheme + "".join(random.choice("abcdefghijklmnopqrstuvwxyz")
                                for _ in range(random.randint(8, 16))) + \
            random.choice(BAD_TLDS) + "/" + brand + random.choice(BAD_PATHS)
    if style == 3:                                   # character padding / hyphens
        return scheme + brand + "-" + random.choice(BAIT) + "-" + \
            random.choice(BAIT) + random.choice(BAD_TLDS) + random.choice(BAD_PATHS)
    if style == 4:                                   # @ redirection trick
        return scheme + brand + random.choice(SAFE_TLDS) + "@" + \
            "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                    for _ in range(random.randint(10, 18))) + random.choice(BAD_TLDS) + "/login"
    # digit padded look-alike host
    return scheme + brand + str(random.randint(100, 99999)) + \
        random.choice(BAD_TLDS) + random.choice(BAD_PATHS) + str(random.randint(10, 999))


def make_safe_but_odd():
    """Real sites that happen to look suspicious: long query strings, hyphens,
    digits, internal IP hosts, newer TLDs, password-reset paths."""
    brand = random.choice(SAFE_BRANDS)
    style = random.randint(0, 4)
    if style == 0:
        return "http://" + rand_ip() + ":8080/internal/dashboard"
    if style == 1:
        return "https://" + brand + random.choice([".xyz", ".top", ".click"]) + "/home"
    if style == 2:
        return "https://" + brand + ".com/account/password-reset?token=" + \
            "".join(random.choice("abcdef0123456789") for _ in range(28))
    if style == 3:
        return "https://" + brand + "-student-portal-" + str(random.randint(2020, 2026)) + \
            ".ac.in/login/verify"
    return "https://" + ".".join(random.sample(["mail", "secure", "login", "www"], 3)) + \
        "." + brand + ".org/signin"


def make_phish_but_tidy():
    """Phishing that avoids the obvious tells: https, short host, normal TLD."""
    brand = random.choice(SAFE_BRANDS)
    style = random.randint(0, 2)
    if style == 0:
        return "https://" + brand + random.choice([".com", ".net", ".in"]) + "/" + \
            "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(6))
    if style == 1:
        return "https://" + brand + "s" + random.choice(SAFE_TLDS) + "/login"
    return "https://" + brand[:-1] + random.choice(SAFE_TLDS) + random.choice(SAFE_PATHS)


def build(n_each=900, overlap=0.18):
    hard = int(n_each * overlap)
    rows = [(make_safe(), 0) for _ in range(n_each - hard)]
    rows += [(make_safe_but_odd(), 0) for _ in range(hard)]
    rows += [(make_phish(), 1) for _ in range(n_each - hard)]
    rows += [(make_phish_but_tidy(), 1) for _ in range(hard)]
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    HERE = os.path.dirname(os.path.abspath(__file__))
    rows = build()
    with open(os.path.join(HERE, "urls.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print("wrote", len(rows), "rows")
