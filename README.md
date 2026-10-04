# phishing-analyzer

Static phishing email analyzer with an explainable suspicion score.

Give it a `.eml` file and it extracts the technical indicators an SOC analyst
would check by hand, then explains every point of the final score.

## Features

## Features

- Header parsing (`From`, `Reply-To`, `Return-Path`, `Subject`, `Date`)
- Received chain reconstruction and IP extraction (public / private)
- Link extraction and misleading-link detection (displayed text vs real destination)
- Raw IP URL detection and urgency vocabulary detection in the subject
- SPF / DKIM / DMARC results read from `Authentication-Results`
- Attachment analysis: SHA256, double extensions, risk-tiered extensions, MIME mismatch
- Explainable score capped at 100 with a risk level (low / medium / high)

## Roadmap

- [x] SPF / DKIM / DMARC checks from `Authentication-Results`
- [x] Attachment analysis (double extensions, MIME mismatch, SHA256)
- [x] Score cap and risk levels
- [x] Unit tests with `pytest`
- [x] More test cases (Reply-To only, no HTML, malformed mail)
- [x] JSON output (`--json`) and HTML report
- [ ] Enrichment (domain age, VirusTotal lookup by hash)
- [ ] Own SPF/DMARC verification via DNS

## Installation

```bash
git clone https://github.com/Medoche6/phishing-analyzer.git
cd phishing-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python src/analyzer.py path/to/email.eml
python src/analyzer.py path/to/email.eml --json
```
## Tests

    pip install -r requirements-dev.txt
    pytest -v

Test emails in `tests/data/` are fictional (reserved documentation
domains and IP ranges).

## Example output

By default, the tool prints a human-readable report: headers, `Received` chain, IPs, links, attac     hments and the explained suspicion score.

python src/analyzer.py path/to/email.eml

```
Liens trouvés :
 - affiché : https://www.banque-securite.example/connexion
 - réel : http://192.0.2.99/verification/login.php [Fake]

Pièces jointes :
  aucune

Score de suspicion : 100/100 (Score élevé)
  +15 : Reply-To (gmail.example) different de From (banque-securite.example)
  +15 : Return-Path (mailer-xk92.example.net) different de From (banque-securite.example)
  +25 : lien trompeur (https://www.banque-securite.example/connexion -> http://192.0.2.99/verification/login.php)
  +20 : lien vers une ip brute (http://192.0.2.99/verification/login.php)
  +10 : email contenant un ou des mot(s) suspect(s)
  +20 : SPF erreur (fail)
  +10 : DKIM absent ou en erreur (none)
  +20 : DMARC en erreur
```
## JSON output

Use `--json` to get machine-readable results, for example to feed another script or a SIEM:

    python src/analyzer.py path/to/email.eml --json

Abridged example:
```json
    
    {
  "headers": {
    "From": "Service Securite Banque <alerte@banque-securite.example>",
    "Reply-To": "support-urgent@gmail.example",
    "Return-Path": "<bounce@mailer-xk92.example.net>",
    "Subject": "URGENT : Votre compte sera suspendu sous 24h",
    "Date": "Thu, 01 Oct 2026 09:58:00 +0200"
  },
  "received": [
    "from mail-xk92.example.net (mail-xk92.example.net [203.0.113.45]) by mx.local with ESMTP id abc123 for <victime@exemple.fr>; Thu, 1 Oct 2026 09:58:12 +0200",
    "from localhost (unknown [198.51.100.7]) by mail-xk92.example.net with SMTP id def456; Thu, 1 Oct 2026 09:58:10 +0200"
  ],
  "ips": {
    "all": [
      "203.0.113.45",
      "198.51.100.7"
    ],
    "origin": "198.51.100.7",
    "private": [
      "203.0.113.45",
      "198.51.100.7"
    ],
    "public": []
  },
  "links": [
    {
      "text": "https://www.banque-securite.example/connexion",
      "href": "http://192.0.2.99/verification/login.php",
      "misleading": true,
      "ip_url": true
    },
    {
      "text": "Verifier mon compte",
      "href": "http://bit.example/x7Yz9",
      "misleading": false,
      "ip_url": false
    }
  ],
  "attachments": [],
  "authentication": {
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail"
  },
  "score": 100,
  "risk_level": "ÉLEVÉ",
  "reasons": [
    "+15 : Reply-To (gmail.example) different de From (banque-securite.example)",
    "+15 : Return-Path (mailer-xk92.example.net) different de From (banque-securite.example)",
    "+25 : lien trompeur (https://www.banque-securite.example/connexion -> http://192.0.2.99/verification/login.php)",
    "+20 : lien vers une ip brute (http://192.0.2.99/verification/login.php",
    "+10 : email contenant un ou des mot(s) suspect(s)",
    "+20 : SPF erreur (fail)",
    "+10 : DKIM absent ou en erreur (none)",
    "+20 : DMARC en erreur"
  ]
}
```

## Safety

The analysis is static only: links are never visited and attachments are
never opened or executed. Do not commit real emails or malware samples;
the `samples/` folder is git-ignored.

## Limitations

The score is a decision aid, not a verdict. A legitimate email can fail some
checks (forwarding, misconfiguration), and a malicious one can pass them
(compromised account). `Received` headers other than the one added by your
own server can be forged.

## Liscence

MIT
