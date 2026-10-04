import sys
import os
import hashlib
from pathlib import Path
import mimetypes
from email import policy
from email.parser import BytesParser
import re
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import json
import argparse

URGENCY_WORDS = ("urgent", "suspendu", "immédiat", "24h", "verify", "action required", "urgent", "urgently", "immediately", "immediate", "suspended", "suspension", "deactivated", "disabled", "locked", "expired", "expiration", "terminate", "termination", "verify", "verification", "validate", "validation", "confirm", "confirmation", "unauthorized", "unusual", "suspicious", "security alert", "security warning", "fraud", "fraudulent", "compromised", "breach", "threat", "warning", "account", "password", "credential", "credentials", "login", "signin", "sign-in", "sign in", "username", "authentication", "authenticate", "access", "payment", "billing", "invoice", "transaction", "refund", "purchase", "order", "bank", "banking", "credit", "debit", "card", "wallet", "money", "transfer", "security", "identity", "personal", "information", "private", "document", "attachment", "notification", "alert", "request", "action", "required", "mandatory", "update", "renew", "renewal", "recover", "restore", "unlock", "click", "link")

HIGH_RISK_EXT = [".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".msix", ".msixbundle", ".appx", ".appxbundle", ".hta", ".cpl", ".lnk", ".scf", ".reg", ".jar", ".apk", ".ipa", ".dmg", ".pkg"]

MEDIUM_RISK_EXT = [".dll", ".ocx", ".sys", ".drv", ".psm1", ".psd1", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".ova", ".ovf", ".bin", ".elf", ".run", ".command", ".desktop", ".application", ".gadget"]

LOW_RISK_EXT = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".csv", ".rtf", ".odt", ".ods", ".odp", ".py", ".pyw", ".pyc", ".pyo", ".sh", ".bash", ".zsh", ".ksh", ".fish", ".pl", ".pm", ".php", ".asp", ".aspx", ".jsp", ".cgi", ".class", ".c", ".h", ".cpp", ".hpp"]

def parse_eml(path):
    with open (path, "rb") as file:
        return BytesParser(policy=policy.default).parse(file)

IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")

def extract_received_ips(msg):

    ips=[]
    for hop in msg.get_all("Received", []):
        for match in IP_RE.findall(hop):
            try:
                ips.append(str(ipaddress.ip_address(match)))
            except ValueError:
                continue
    return ips

def origin_ip(msg):
    ips = extract_received_ips(msg)
    return ips[-1] if ips else None

def classify_ips(msg): #on separe les ips privees et publics
    private_ips = []
    public_ips = []
    for ip in extract_received_ips(msg):
        if ipaddress.ip_address(ip).is_private:
            private_ips.append(ip)
        else:
            public_ips.append(ip)
    return private_ips, public_ips

def get_html_body(msg):
    part = msg.get_body(preferencelist=("html",))
    return part.get_content() if part else ""

def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for x in soup.find_all("a", href=True):
        links.append({"text": x.get_text(strip=True), "href": x["href"]})
    return links 

def is_misleading(link):
    text = link["text"]
    if not text.startswith(("http://", "https://", "www.")):
        return False
    shown = urlparse(text if "//" in text else "//" + text).hostname
    real = urlparse(link["href"]).hostname
    return shown != real

def domain_of(adress):
    match = re.search(r"@([\w.-]+)", adress or "")
    return match.group(1).lower() if match else None

def is_ip(href):
    host = urlparse(href).hostname
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

AUTHENTICATION = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)

def authentication_results(msg):
    results = {}
    for header in msg.get_all("Authentication-Results", []):
        for mech, verdict in AUTHENTICATION.findall(str(header)):
            results.setdefault(mech.lower(), verdict.lower())
    return results

def attachment(msg):
    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        attachments.append({
            "name" : part.get_filename() or "(without name)",
            "sha256" : hashlib.sha256(data).hexdigest(),
            "mime" : part.get_content_type(),
            "size" : len(data),
        })
    return attachments

def get_ext(name):
    return os.path.splitext(name.lower())[1]

def double_extension(name):
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    last, previous = "." + parts[-1], "." + parts[-2]
    return (last in HIGH_RISK_EXT or last in MEDIUM_RISK_EXT) and previous in LOW_RISK_EXT

def same_ext(att):
    guessed, _ = mimetypes.guess_type(att["name"])
    return guessed is not None and guessed != att["mime"]

def compute_score(msg):

    score = 0
    reasons = []
    fromd = domain_of(msg.get("From"))
    replyd = domain_of(msg.get("Reply-To"))
    returnd = domain_of(msg.get("Return-Path"))
    if replyd and fromd and replyd != fromd:
        score += 15
        reasons.append(f"+15 : Reply-To ({replyd}) different de From ({fromd})")
    if returnd and fromd and returnd != fromd:
        score += 15
        reasons.append(f"+15 : Return-Path ({returnd}) different de From ({fromd})")

    for link in extract_links(get_html_body(msg)):
        if is_misleading(link):
            score += 25
            reasons.append(f"+25 : lien trompeur ({link['text']} -> {link['href']})")
        if is_ip(link["href"]):
            score+=20
            reasons.append(f"+20 : lien vers une ip brute ({link['href']}")
    subject = (msg.get("Subject") or "").lower()
    if any(word in subject for word in URGENCY_WORDS):
        score += 10
        reasons.append("+10 : email contenant un ou des mot(s) suspect(s)")

    auth = authentication_results(msg)
    if auth.get("spf") in ("fail", "softfail"):
        score+=20
        reasons.append(f"+20 : SPF erreur ({auth['spf']})")
    if auth.get("dkim") in ("fail", "none"):
        score += 10
        reasons.append(f"+10 : DKIM absent ou en erreur ({auth['dkim']})")
    if auth.get("dmarc") == "fail":
        score += 20
        reasons.append("+20 : DMARC en erreur")
    for att in attachment(msg):
        ext = get_ext(att["name"])
        if double_extension(att["name"]):
            score += 30
            reasons.append(f"+30 : double extension ({att['name']})")
        elif ext in HIGH_RISK_EXT:
            score += 25
            reasons.append(f"+25 : extension à haut risque ({att['name']})")
        elif ext in MEDIUM_RISK_EXT:
            score += 10
            reasons.append(f"+10 : extension à risque moyen ({att['name']})")

        if same_ext(att):
            score += 15
            reasons.append(f"+15 : type MIME incohérent ({att['name']} déclaré {att['mime']})")
    score = min(score, 100) 
    return score, reasons

def risk_level(score):
    if score >= 70:
        return "ÉLEVÉ"
    if score >= 40:
        return "MOYEN"
    return "FAIBLE"

RISK_MESSAGES = {
    "ÉLEVÉ": "Score élevé, mail suspect",
    "MOYEN": "Score moyen, faites attention",
    "FAIBLE": "Score faible, peu d'indices suspects",
}

def analyse(msg):
    private_ips, public_ips = classify_ips(msg)
    score, reasons = compute_score(msg)
    return {
        "headers" : {h: msg.get(h) for h in ("From", "Reply-To", "Return-Path", "Subject", "Date")},
        "received" : [" ".join(hop.split()) for hop in msg.get_all("Received", [])],
        "ips": {
            "all": extract_received_ips(msg),
            "origin": origin_ip(msg),
            "private": private_ips,
            "public": public_ips,
        },
        "links": [
            {**link, "misleading": is_misleading(link), "ip_url": is_ip(link["href"])}
            for link in extract_links(get_html_body(msg))
        ],
        "attachments": attachment(msg),
        "authentication": authentication_results(msg),
        "score": score,
        "risk_level": risk_level(score),
        "reasons": reasons,
    }


def main():

    parser = argparse.ArgumentParser(description="Analyseur d'e-mails de phishing")
    parser.add_argument("file", help="fichier .eml à analyser")
    parser.add_argument("--json", action="store_true", help="sortie au format JSON")
    args = parser.parse_args()

    msg = parse_eml(args.file)

    if args.json:
        print(json.dumps(analyse(msg), indent=2, ensure_ascii=False)) #ces lignes s'executent que si nous utilisons --json, ex de commande : python src/analyzer.py tests/data/mail.eml --json.
        return

    for header in ("From", "Reply-To", "Return-Path", "Subject", "Date"):
        print(f"{header}: {msg.get(header, '(absent)')}")

    print("\nChemin de transit (received) :")

    for i, hop in enumerate(msg.get_all("Received", []), 1):
        print(f" {i}. {' '.join(hop.split())}")

    print("\nIP trouvees :", extract_received_ips(msg))
    print("IP d'origine :", origin_ip(msg)) #seulement received ajoute par le server est fiable, les plus anciens, l'ip d'origine peut etre falsifies par l'attaquant donc c'est un "indice"pas une preuve irrefutable.
    private_ips, public_ips = classify_ips(msg)
    print("IP privees:", private_ips if private_ips else "aucune")
    print("IP public :", public_ips if public_ips else "aucune")
   
    links = extract_links(get_html_body(msg))
    if links:
        print("\nLiens trouvés :")
        for link in links:
            flag = " [Fake]" if is_misleading(link) else ""
            print(f" - affiché : {link['text']}")
            print(f" - réel : {link['href']}{flag}")
    else:
        print("\nLiens trouvés : aucun")
    
    print("\nPièces jointes :")
    attachments = attachment(msg)
    if not attachments:
        print("  aucune")
    for att in attachments:
        print(f"  - {att['name']} ({att['mime']}, {att['size']} octets)")
        print(f"    sha256 : {att['sha256']}")

    score, reasons = compute_score(msg)
    level = risk_level(score)
    print(f"\nScore de suspicion : {score}/100 ({RISK_MESSAGES[level]})")
    for reason in reasons:
        print(f"  {reason}")

if __name__ == "__main__":
    main()
