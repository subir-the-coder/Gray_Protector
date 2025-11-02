# Gray_Protector
A powerful Domain Investigation &amp; Fraud Detection Tool — built for cybersecurity analysts, researchers, and ethical hackers who take web safety seriously.
# 🛡️ Gray Protector v2.0  
**Advanced Domain Investigation & Fraud Detection Tool**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-Apache%202.0-green)
![Version](https://img.shields.io/badge/Version-2.0-orange)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 🚀 Overview

**Gray Protector** is a cybersecurity tool designed to perform in-depth analysis of domains and detect potential fraud, phishing, or malicious intent.  
It combines WHOIS intelligence, SSL data, DNS information, and threat intelligence sources to evaluate the **trustworthiness of a domain**.

This tool is crafted for **ethical hackers**, **security researchers**, and **SOC analysts** who want quick and accurate insight into any domain.

---

## ⚙️ Features

✅ **WHOIS Lookup** — Fetch registrar, owner, and domain age information  
✅ **SSL Certificate Check** — Inspect validity, issuer, and expiry  
✅ **IP & Geo Tracking** — Extract IP address and location of the server  
✅ **Threat Intel Check** — Compare against VirusTotal, PhishTank, and blocklists  
✅ **Domain Risk Scoring** — Automated confidence level for fraud suspicion  
✅ **Scam Phrase Detection** — Analyzes page content for scam indicators  
✅ **Colorful CLI Output** — Interactive terminal with `colorama` and ASCII banners  
✅ **Detailed Report** — Save investigation results in structured text or JSON format  

---

## 🧠 Tech Stack

- **Language:** Python 3.8+
- **Libraries Used:**
  - `requests`
  - `whois`
  - `socket`
  - `ssl`
  - `json`
  - `colorama`
  - `pyfiglet`
  - `datetime`

---

## 🖥️ Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/subir-the-coder/GrayProtector.git
   cd GrayProtector
