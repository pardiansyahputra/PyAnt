import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import re
from urllib.parse import urlparse,urljoin
import logging
from utils.longger import logger  # Pastikan logger sudah dikonfigurasi
import requests
from bs4 import BeautifulSoup


def fetch_url_content(url, timeout=5, max_redirects=5):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        if len(response.history) >= max_redirects:
            logger.warning(f"Jumlah pengalihan melebihi batas ({max_redirects}) untuk URL: {url}")
            return response.text, response.url
        return response.text, response.url # Kembalikan konten dan URL akhir
    except requests.exceptions.RequestException as e:
        logger.error(f"Gagal mengambil konten dari {url} (atau mengikuti redirect): {e}")
        return None, url # Jika gagal, kembalikan None untuk konten dan URL awal

def detect_typosquatting(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.lower()
    common_domains = ["google.com", "facebook.com", "twitter.com", "instagram.com", "amazon.com", "netflix.com", "paypal.com", "microsoft.com", "apple.com"]
    suspicious_reasons = []

    for domain in common_domains:
        # Hapus satu karakter
        for i in range(len(domain)):
            typo = domain[:i] + domain[i+1:]
            if typo in hostname:
                suspicious_reasons.append(f"Kemiripan typosquatting dengan domain populer: {domain} (typo: {typo})")

        # Tukar dua karakter bersebelahan
        for i in range(len(domain) - 1):
            typo = domain[:i] + domain[i+1] + domain[i] + domain[i+2:]
            if typo in hostname:
                suspicious_reasons.append(f"Kemiripan typosquatting dengan domain populer: {domain} (swap: {typo})")

        # Sisipkan karakter di antara
        for i in range(len(domain) + 1):
            for char in "abcdefghijklmnopqrstuvwxyz0123456789":
                typo = domain[:i] + char + domain[i:]
                if typo in hostname:
                    suspicious_reasons.append(f"Kemiripan typosquatting dengan domain populer: {domain} (insert: {typo})")

    return suspicious_reasons

def detect_suspicious_path(url):
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    suspicious_patterns = [
        r"/login",
        r"/signin",
        r"/account",
        r"/update",
        r"/confirm",
        r"/verify",
        r"/secure",
        r"/bank",
        r"/password",
        r"/creditcard"
    ]
    suspicious_reasons = []
    for pattern in suspicious_patterns:
        if re.search(pattern, path):
            suspicious_reasons.append(f"Path URL mengandung pola yang mencurigakan: {pattern}")
    return suspicious_reasons

def detect_phishing_keywords(html_content):
    if not html_content:
        return []
    keywords = ["verifikasi akun", "informasi penting", "tindakan segera", "keamanan akun", "masalah keamanan",
                "login aman", "detail kartu kredit", "nomor rekening bank", "kata sandi anda", "klik di sini untuk",
                "hadiah gratis", "transfer dana", "konfirmasi identitas"]
    found_keywords = []
    for keyword in keywords:
        if keyword.lower() in html_content.lower():
            found_keywords.append(f"Konten mengandung kata kunci phishing: '{keyword}'")
    return found_keywords

def analyze_forms(html_content, url):
    if not html_content:
        return []
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')
    suspicious_forms = []
    parsed_url = urlparse(url)
    current_domain = parsed_url.netloc

    for form in forms:
        method = form.get('method', 'get').lower()
        action = form.get('action')

        inputs = form.find_all('input', {'type': ['password', 'email', 'text', 'number']})
        sensitive_inputs = any(input.get('type') in ['password', 'email'] or 'card' in input.get('name', '').lower() or 'account' in input.get('name', '').lower() for input in inputs)

        if sensitive_inputs:
            if action:
                form_url = urljoin(url, action)
                parsed_form_url = urlparse(form_url)
                form_domain = parsed_form_url.netloc
                if form_domain != current_domain and not form_domain.endswith(current_domain):
                    suspicious_forms.append(f"Formulir mengirimkan data sensitif ke domain yang berbeda: {form_domain}")
            else:
                suspicious_forms.append("Formulir mengirimkan data sensitif tanpa atribut 'action' yang jelas")
    return suspicious_forms

def analyze_url_for_phishing(url):
    phishing_indicators = []
    original_url = url # Simpan URL awal
    html_content, final_url = fetch_url_content(url)

    if final_url != original_url:
        logger.info(f"URL '{original_url}' dialihkan ke '{final_url}'")
        url = final_url # Gunakan URL akhir untuk analisis selanjutnya

    phishing_indicators.extend(detect_typosquatting(url))
    phishing_indicators.extend(detect_suspicious_path(url))

    if html_content:
        phishing_indicators.extend(detect_phishing_keywords(html_content))
        phishing_indicators.extend(analyze_forms(html_content, url))

    if phishing_indicators:
        logger.warning(f"Potensi phishing terdeteksi pada URL (setelah redirect dari '{original_url}'): {url} (Alasan: {', '.join(phishing_indicators)})")
    else:
        logger.info(f"Tidak ada indikasi phishing (berdasarkan analisis URL dan konten setelah redirect dari '{original_url}') pada: {url}")

    return phishing_indicators, final_url # Kembalikan juga URL akhir

if __name__ == "__main__":
    test_urls = [
        "http://faceboook.com/login.php",
        "https://paypaal.com/signin",
        "http://www.google.cm/account/update",
        "https://secure-bankofamerica.com/",
        "http://amazonn.com/",
        "http://legitsite.com/info",
        "https://fake-bank.com/login",
        "https://another-fake.com/verify?token=...",
        "https://phishing-site.ru/transfer.html",
        "http://bit.ly/3C5vL5n" # Contoh pemendek URL (mungkin perlu diganti dengan yang aktif)
    ]
    for url in test_urls:
        print(f"Menganalisis URL: {url}")
        indicators, final_url = analyze_url_for_phishing(url)
        print(f"  URL Akhir: {final_url}")
        if indicators:
            print(f"  Indikator Phishing: {indicators}")
        else:
            print("  Tidak ada indikator phishing terdeteksi.")
        print("-" * 20)