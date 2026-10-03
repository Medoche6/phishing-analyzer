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

## Roadmap

- [x] SPF / DKIM / DMARC checks from `Authentication-Results`
- [x] Attachment analysis (double extensions, MIME mismatch, SHA256)
- [x] Score cap and risk levels
- [x] Unit tests with `pytest`
- [ ] More test cases (Reply-To only, no HTML, malformed mail)
- [ ] JSON output (`--json`) and HTML report
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
```
## Tests

    pip install -r requirements-dev.txt
    pytest -v

Test emails in `tests/data/` are fictional (reserved documentation
domains and IP ranges).

## Example output

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
