import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import re
from urllib.parse import urlparse

CONFIG_FILE = "config.json"

class URLAnalyzer:
    def __init__(self, max_length=200, suspicious_keywords=None):
        self.max_length = self._load_max_length() if max_length is None else max_length
        self.suspicious_keywords = self._load_keywords() if suspicious_keywords is None else suspicious_keywords

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                import json
                return json.load(f)
        else:
            return {
                "max_url_length": 200,
                "suspicious_keywords": [
                    "malware",
                    "virus",
                    "phishing",
                    "scam",
                    "login",
                    "bank",
                    "account",
                    "free",
                    "gift"
                ],
                "default_blacklist_url": "https://raw.githubusercontent.com/firehol/blocklist-ipdb/master/urlhaus-domains.txt"
            }

    def _load_max_length(self):
        config = self._load_config()
        return config.get("max_url_length", 200)

    def _load_keywords(self):
        config = self._load_config()
        return config.get("suspicious_keywords", [])

    def analyze_url(self, url):
        issues = []
        if len(url) > self.max_length:
            issues.append(f"URL melebihi batas panjang ({self.max_length} karakter)")
        for keyword in self.suspicious_keywords:
            if keyword in url.lower():
                issues.append(f"URL mengandung kata kunci mencurigakan: '{keyword}'")
        return {"issues": issues}

if __name__ == "__main__":
    analyzer = URLAnalyzer()

    while True:
        url_to_analyze = input("Masukkan URL yang ingin Anda analisis (atau ketik 'keluar' untuk berhenti): ")
        if url_to_analyze.lower() == 'keluar':
            break

        analysis_result = analyzer.analyze_url(url_to_analyze)
        print(f"\nAnalisis URL: {analysis_result['url']}")
        if analysis_result["issues"]:
            for issue in analysis_result["issues"]:
                print(f"- {issue}")
        else:
            print("- Tidak ada isu mencurigakan terdeteksi (berdasarkan analisis)")
        print("-" * 30)
        analysis_result = analyzer.analyze_url(url_to_analyze)
        print(f"Analisis URL: {analysis_result['url']}")
        if analysis_result["issues"]:
            for issue in analysis_result["issues"]:
                print(f"- {issue}")
        else:
            print("- Tidak ada isu mencurigakan terdeteksi (berdasarkan analisis)")
        print("-" * 30)