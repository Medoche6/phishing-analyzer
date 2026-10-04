import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import analyzer

DATA = Path(__file__).resolve().parent / "data"


def score_of(name):

    msg = analyzer.parse_eml(str(DATA / name))
    return analyzer.compute_score(msg)

def score_of_text(tmp_path, raw):

    path = tmp_path / "mail.eml"
    path.write_text(raw, encoding="utf-8")
    msg = analyzer.parse_eml(str(path))
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

def test_reply_low_score(tmp_path):
    raw = (
        "From: contact@societe.example\n"
        "Reply-To: autre@gmail.example\n"
        "Subject: bonjour\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "message simple.\n"
    )
    score, reasons = score_of_text(tmp_path, raw)
    assert score == 15
    assert len(reasons) == 1
    assert "Reply-To" in reasons[0]
    assert analyzer.risk_level(score) == "FAIBLE"


def test_mail_no_links(tmp_path):
    raw = (
        "From: contact@societe.example\n"
        "Subject: Info\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Pas de HTML ici, juste du texte.\n"
    )
    msg_path = tmp_path / "plain.eml"
    msg_path.write_text(raw, encoding="utf-8")
    msg = analyzer.parse_eml(str(msg_path))
    assert analyzer.extract_links(analyzer.get_html_body(msg)) == []
    score, reasons = analyzer.compute_score(msg)
    assert score == 0


def test_mail_without_headers(tmp_path):
    score, reasons = score_of_text(tmp_path, "Subject: x\n\ncorps\n")
    assert score == 0
    assert reasons == []

def test_analyze_returns():
    msg = analyzer.parse_eml(str(DATA / "phishing.eml"))
    result = analyzer.analyse(msg)
    assert result["score"] == 100
    assert result["risk_level"] == "ÉLEVÉ"
    assert result["authentication"]["spf"] == "fail"
    assert any(link["misleading"] for link in result["links"])
