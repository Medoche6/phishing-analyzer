import sys
from email import policy
from email.parser import BytesParser
import re
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup

URGENCY_WORDS = ("urgent", "suspendu", "immédiat", "24h", "verify", "action required", "urgent", "urgently", "immediately", "immediate", "suspended", "suspension", "deactivated", "disabled", "locked", "expired", "expiration", "terminate", "termination", "verify", "verification", "validate", "validation", "confirm", "confirmation", "unauthorized", "unusual", "suspicious", "security alert", "security warning", "fraud", "fraudulent", "compromised", "breach", "threat", "warning", "account", "password", "credential", "credentials", "login", "signin", "sign-in", "username", "authentication", "authenticate", "access", "payment", "billing", "invoice", "transaction", "refund", "purchase", "order", "bank", "banking", "credit", "debit", "card", "wallet", "money", "transfer", "security", "identity", "personal", "information", "private", "document", "attachment", "notification", "alert", "request", "action", "required", "mandatory", "update", "renew", "renewal", "recover", "restore", "unlock", "click", "link")


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
    score = min(score, 100) 
    return score, reasons

def risk_level(score):

    if score >= 45:
        return "Score élevé, ce mail est surement du phishing"
    if score >= 25:
        return "Score moyen, veuillez faire attention au mail"
    return "Score faible"


def main():

    if len(sys.argv) != 2:
        print("Veuillez entrer le nom du script + un fichier en argument")
        sys.exit(1)
    
    msg = parse_eml(sys.argv[1])

    for header in ("From", "Reply-To", "Return-Path", "Subject", "Date"):
        print(f"{header}: {msg.get(header, '(absent)')}")

    print("\nChemin de transit (received) :")

    for i, hop in enumerate(msg.get_all("Received", []), 1):
        print(f" {i}. {' '.join(hop.split())}")

    print("\nIP trouvees :", extract_received_ips(msg))
    print("IP d'origine :", origin_ip(msg)) #seulement received ajoute par le server est fiable, les plus anciens, l'ip d'origine peut etre falsifies par l'attaquant donc c'est un "indice"pas une preuve irrefutable.

    private_ips, public_ips = classify_ips(msg)
    print("IP privees:", private_ips if private_ips else "Aucune")
    print("IP public :", public_ips if public_ips else "aucune")

    print("\nLiens trouvees : ")
    for link in extract_links(get_html_body(msg)):
        flag = " [Fake]" if is_misleading(link) else ""
        print(f" - affiche : {link['text']}")
        print(f" - real : {link['href']}{flag}")

    score, reasons = compute_score(msg)
    print(f"\nScore de suspicion : {score}/100 ({risk_level(score)})")
    for reason in reasons:
        print(f"  {reason}")


if __name__ == "__main__":
    main()

