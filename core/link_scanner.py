import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import requests
import json
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from core.blacklist import Blacklist
from core.url_analyzer import URLAnalyzer
import logging
from utils.longger import logger
from core.phishing_detector import analyze_url_for_phishing


CONFIG_FILE = "config.json"

class LinkScanner:
    def __init__(self, blacklist_file="blacklist.txt"):
        self.settings = self._load_config()
        self.blacklist = Blacklist(blacklist_file)
        self.url_analyzer = URLAnalyzer(self.settings.get("max_url_length", 200),
                                        self.settings.get("suspicious_keywords", []))
        logger.info("LinkScanner diinisialisasi.")

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
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

    def extract_and_scan_links(self, url, gui_instance=None):
        logger.info(f"Memulai pemindaian URL: {url}")
        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            results = []
            link_count = 0
            suspicious_count = 0
            phishing_count = 0

            for a_tag in soup.find_all('a', href=True):
                if gui_instance and gui_instance.cancel_scan:
                    logger.info(f"Pemindaian URL '{url}' dibatalkan oleh pengguna.")
                    break

                link = a_tag['href']
                absolute_link = urljoin(url, link)
                link_count += 1
                is_suspicious = False
                reasons = []
                is_phishing = False
                phishing_reasons, final_url = analyze_url_for_phishing(absolute_link) # Dapatkan URL akhir

                if phishing_reasons:
                    is_phishing = True
                    phishing_count += 1
                    reasons.extend(["Potensi phishing (analisis URL/konten):"] + phishing_reasons)
                    logger.warning(f"Potensi phishing terdeteksi pada tautan (setelah redirect dari '{absolute_link}'): {final_url} (Alasan: {', '.join(phishing_reasons)})")

                if self.blacklist.check_blacklist(final_url): # Periksa blacklist terhadap URL akhir
                    is_suspicious = True
                    reasons.append(f"Ditemukan dalam blacklist (URL akhir: {final_url})")

                analysis_report = self.url_analyzer.analyze_url(final_url) # Analisis URL terhadap URL akhir
                if analysis_report["issues"]:
                    is_suspicious = True
                    reasons.extend([f"Masalah analisis URL (URL akhir: {final_url}):"] + analysis_report["issues"])

                if is_suspicious or is_phishing:
                    suspicious_count += 1
                    logger.warning(f"Tautan mencurigakan ditemukan (setelah redirect dari '{absolute_link}'): {final_url} (Alasan: {', '.join(reasons)})")
                else:
                    logger.info(f"Tautan aman (setelah redirect dari '{absolute_link}'): {final_url}")

                results.append({"url": absolute_link, "final_url": final_url, "suspicious": is_suspicious, "reasons": reasons, "phishing": is_phishing, "phishing_reasons": phishing_reasons})

            logger.info(f"Pemindaian URL '{url}' selesai. Total {link_count} tautan dipindai, {suspicious_count} mencurigakan ({phishing_count} potensi phishing).")
            return results

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching URL {url}: {e}")
            return []

if __name__ == "__main__":
    scanner = LinkScanner()
    target_url = input("Masukkan URL situs web yang ingin Anda pindai: ")
    scan_results = scanner.extract_and_scan_links(target_url)

    if scan_results:
        print(f"\nHasil Pemindaian Tautan dari {target_url}:")
        for result in scan_results:
            print(f"- URL: {result['url']}")
            if result['suspicious']:
                print("  Status: Mencurigakan")
                for reason in result['reasons']:
                    print(f"    - {reason}")
            else:
                print("  Status: Aman")
        print("-" * 30)
    else:
        print(f"\nTidak ada tautan yang ditemukan atau terjadi kesalahan saat memproses {target_url}.")