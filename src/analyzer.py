import sys
from email import policy
from email.parser import BytesParser
import re
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup

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

def is_misleading(links):
    text = links["text"]
    if not text.startswith(("http://", "https://", "www.")):
        return False
    shown = urlparse(text if "//" in text else "//" + text).hostname
    real = urlparse(links["href"]).hostname
    return shown != real

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
    print("IP d'origine :", origin_ip(msg)) #seulement received ajoute par le server est fiable, les plus anciens, l'ip d'origine peut etre falsifies par l'attaquant donc c un "indice"pas une preuve irrefutable.

    private_ips, public_ips = classify_ips(msg)
    print("IP privees:", private_ips if private_ips else "Aucune")
    print("IP public :", public_ips if public_ips else "aucune")

    print("\nLiens trouvees : ")
    for link in extract_links(get_html_body(msg)):
        flag = " [Fake]" if is_misleading(link) else ""
        print(f" - affiche : {link['text']}")
        print(f" - real : {link['href']}{flag}")


if __name__ == "__main__":
    main()

