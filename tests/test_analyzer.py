import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import analyzer

DATA = Path(__file__).resolve().parent / "data"


def score_of(name):
    msg = analyzer.parse_eml(str(DATA / name))
    return analyzer.compute_score(msg)


def test_legit_mail_has_low_score():
    score, reasons = score_of("legit.eml")
    assert score < 40
    assert reasons == []


def test_phishing_mail_has_high_score():
    score, _ = score_of("phishing.eml")
    assert score >= 70


def test_double_extension_detected():
    _, reasons = score_of("attach.eml")
    assert any("double extension" in r for r in reasons)


def test_misleading_link_detected():
    _, reasons = score_of("phishing.eml")
    assert any("lien trompeur" in r for r in reasons)
