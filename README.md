# phishing-analyzer

Static phishing email analyzer with an explainable suspicion score.

Give it a `.eml` file and it extracts the technical indicators an SOC analyst
would check by hand, then explains every point of the final score.

## Features

- Header parsing (`From`, `Reply-To`, `Return-Path`, `Subject`, `Date`)
- Received chain reconstruction and IP extraction (public / private)
- Link extraction from the HTML body and misleading-link detection
  (displayed text differs from the real destination)
- Raw IP URL detection
- Urgency vocabulary detection in the subject
- Explainable scoring: each rule adds points and states why

## Roadmap

- [ ] SPF / DKIM / DMARC checks from `Authentication-Results`
- [ ] Attachment analysis (double extensions, MIME mismatch, SHA256 hashes)
- [ ] Score cap and risk levels (low / medium / high)
- [ ] Enrichment (domain age, URLhaus, VirusTotal)
- [ ] Unit tests with `pytest`

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

## Example output

```
Score de suspicion : 85
  +15 : Reply-To (gmail.example) different de From (banque-securite.example)
  +15 : Return-Path (mailer-xk92.example.net) different de From (banque-securite.example)
  +25 : lien trompeur (https://www.banque-securite.example/connexion -> http://192.0.2.99/verification/login.php)
  +20 : lien vers une IP brute (http://192.0.2.99/verification/login.php)
  +10 : sujet avec vocabulaire d'urgence
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
