import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import tkinter as tk
from tkinter import ttk, messagebox
from core.link_scanner import LinkScanner
import threading
from gui.setting_window import SettingsWindow
import json
import logging
from utils.longger import logger
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse,urljoin
from core.phishing_detector import analyze_url_for_phishing


CONFIG_FILE = "config.json"

class MainWindow:
    def __init__(self, master):
        self.master = master
        master.title("PyAntiVirus - Pemindai Tautan")

        self.link_scanner = LinkScanner()
        self.is_scanning = False
        self.cancel_scan = False
        self.default_config = self._load_default_config()

        # --- Frame untuk Input URL dan Tombol Pemindaian ---
        input_frame = ttk.Frame(master)
        input_frame.grid(row=0, column=0, columnspan=2, padx=5, pady=(5, 2), sticky="ew")

        self.url_label = ttk.Label(input_frame, text="Masukkan URL Situs:")
        self.url_label.pack(side=tk.LEFT, padx=5)
        self.url_entry = ttk.Entry(input_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, fill="x", expand=True, padx=5)
        self.scan_button = ttk.Button(input_frame, text="Mulai Pemindaian", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # --- Frame untuk Blacklist URL dan Tombol Perbarui ---
        blacklist_frame = ttk.Frame(master)
        blacklist_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=(2, 5), sticky="ew")

        self.blacklist_url_label = ttk.Label(blacklist_frame, text="URL Sumber Blacklist:")
        self.blacklist_url_label.pack(side=tk.LEFT, padx=5)
        self.blacklist_url_entry = ttk.Entry(blacklist_frame, width=50)
        self.blacklist_url_entry.pack(side=tk.LEFT, fill="x", expand=True, padx=5)
        self.blacklist_url_entry.insert(0, self.default_config.get("default_blacklist_url", "https://raw.githubusercontent.com/firehol/blocklist-ipdb/master/urlhaus-domains.txt"))
        self.update_bl_button = ttk.Button(blacklist_frame, text="Perbarui Blacklist", command=self.update_blacklist)
        self.update_bl_button.pack(side=tk.LEFT, padx=5)

        # --- Tombol Pengaturan dan Batalkan ---
        button_frame = ttk.Frame(master)
        button_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=(5, 5), sticky="ew")

        self.settings_button = ttk.Button(button_frame, text="Pengaturan", command=self.open_settings)
        self.settings_button.pack(side=tk.LEFT, padx=5)
        self.cancel_button = ttk.Button(button_frame, text="Batalkan Pemindaian", command=self.cancel_scan_process, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.LEFT, padx=5)

        # --- Label untuk area hasil ---
        self.result_label = ttk.Label(master, text="Hasil Pemindaian:")
        self.result_label.grid(row=3, column=0, padx=5, pady=(10, 2), sticky="w")

        # --- Area hasil (Text widget) ---
        self.result_text = tk.Text(master, height=15, width=70)
        self.result_text.grid(row=4, column=0, columnspan=2, padx=5, pady=(2, 5), sticky="ew")
        self.result_text.config(state=tk.DISABLED)

        # --- Progress Bar ---
        self.progress_bar = ttk.Progressbar(master, orient=tk.HORIZONTAL, length=300, mode='indeterminate')
        self.progress_bar.grid(row=5, column=0, columnspan=2, padx=5, pady=(5, 2), sticky="ew")
        self.progress_bar.stop()

        # --- Label Status Pemindaian ---
        self.scan_status_label = ttk.Label(master, text="")
        self.scan_status_label.grid(row=6, column=0, columnspan=2, padx=5, pady=(2, 10), sticky="w")


        # Konfigurasi grid agar kolom bisa diresize
        master.grid_columnconfigure(1, weight=1)
        master.grid_rowconfigure(4, weight=1) # Biarkan area hasil yang resizable

        logger.info("MainWindow diinisialisasi.")

    def _load_default_config(self):
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

    def open_settings(self):
        logger.info("Jendela pengaturan dibuka.")
        SettingsWindow(self.master, self)

    def start_scan(self):
        url = self.url_entry.get()
        if url and not self.is_scanning:
            logger.info(f"Pemindaian dimulai untuk URL: {url}")
            self.is_scanning = True
            self.cancel_scan = False
            self.scan_button.config(state=tk.DISABLED)
            self.cancel_button.config(state=tk.NORMAL)

            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, f"Memulai pemindaian untuk: {url}\n")
            self.result_text.config(state=tk.DISABLED)

            self.progress_bar.start()
            threading.Thread(target=self._perform_scan, args=(url,)).start()
        elif self.is_scanning:
            messagebox.showinfo("Info", "Pemindaian sedang berlangsung. Silakan batalkan terlebih dahulu.")
        else:
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, "Harap masukkan URL terlebih dahulu.\n")
            self.result_text.config(state=tk.DISABLED)

    def _perform_scan(self, url):
        self.total_links = 0
        self.processed_links = 0
        self.suspicious_links_count = 0
        self.phishing_links_count = 0
        results = []

        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            all_links = soup.find_all('a', href=True)
            self.total_links = len(all_links)

            for a_tag in all_links:
                if self.cancel_scan:
                    logger.info(f"Pemindaian URL '{url}' dibatalkan oleh pengguna.")
                    break

                link = a_tag['href']
                absolute_link = urljoin(url, link)
                self.processed_links += 1
                self.master.after(0, self._update_scan_status) # Update status label

                is_suspicious = False
                reasons = []
                is_phishing = False
                phishing_reasons, final_url = analyze_url_for_phishing(absolute_link)
                if phishing_reasons:
                    is_phishing = True
                    self.phishing_links_count += 1
                    reasons.extend(["Potensi phishing (analisis URL/konten):"] + phishing_reasons)
                    logger.warning(f"Potensi phishing terdeteksi pada tautan (setelah redirect dari '{absolute_link}'): {final_url} (Alasan: {', '.join(phishing_reasons)})")
                if self.link_scanner.blacklist.check_blacklist(absolute_link):
                    is_suspicious = True
                    reasons.append("Ditemukan dalam blacklist")

                analysis_report = self.link_scanner.url_analyzer.analyze_url(absolute_link)
                if analysis_report["issues"]:
                    is_suspicious = True
                    reasons.extend(analysis_report["issues"])

                if is_suspicious or is_phishing:
                    self.suspicious_links_count += 1
                    logger.warning(f"Tautan mencurigakan ditemukan: {absolute_link} (Alasan: {', '.join(reasons)})")
                else:
                    logger.info(f"Tautan aman: {absolute_link}")

                results.append({"url": absolute_link, "suspicious": is_suspicious, "reasons": reasons, "phishing": is_phishing, "phishing_reasons": phishing_reasons})

            self.master.after(0, self._finish_scan, results)

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching URL {url}: {e}")
            self.master.after(0, self._finish_scan, [])

    def _update_scan_status(self):
        if self.total_links > 0:
            status_text = f"Memproses tautan ke-{self.processed_links} dari {self.total_links}"
        else:
            status_text = f"Memproses tautan ke-{self.processed_links}"
        self.scan_status_label.config(text=status_text)

    def _finish_scan(self, results):
        logger.info(f"Pemindaian selesai. Total {len(results)} tautan dipindai, {self.suspicious_links_count} mencurigakan ({self.phishing_links_count} potensi phishing).")
        self.is_scanning = False
        self.cancel_scan = False
        self.scan_button.config(state=tk.NORMAL)
        self.cancel_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.scan_status_label.config(text="") # Bersihkan label status

        summary_text = f"Ringkasan Pemindaian:\n"
        summary_text += f"  Total Tautan Dipindai: {len(results)}\n"
        summary_text += f"  Tautan Mencurigakan: {self.suspicious_links_count}\n"
        summary_text += f"  Potensi Phishing: {self.phishing_links_count}\n\n"

        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, summary_text) # Tampilkan ringkasan terlebih dahulu
        self.result_text.tag_config("aman", foreground="green")
        self.result_text.tag_config("mencurigakan", foreground="red")
        self.result_text.tag_config("phishing", foreground="orange")

        if results:
            for result in results:
                self.result_text.insert(tk.END, f"- URL: {result['url']}\n")
                if result['phishing']:
                    self.result_text.insert(tk.END, "  Status: Potensi Phishing\n", "phishing")
                    for reason in result['phishing_reasons']:
                        self.result_text.insert(tk.END, f"    - {reason}\n")
                elif result['suspicious']:
                    self.result_text.insert(tk.END, "  Status: Mencurigakan\n", "mencurigakan")
                    for reason in result['reasons']:
                        self.result_text.insert(tk.END, f"    - {reason}\n")
                else:
                    self.result_text.insert(tk.END, "  Status: Aman\n", "aman")
            self.result_text.insert(tk.END, "-" * 30 + "\n")
        else:
            self.result_text.insert(tk.END, "Tidak ada tautan yang ditemukan atau terjadi kesalahan.\n")
        self.result_text.config(state=tk.DISABLED)

    def cancel_scan_process(self):
        if self.is_scanning:
            logger.info("Pemindaian dibatalkan oleh pengguna.")
            self.cancel_scan = True
            self.result_text.config(state=tk.NORMAL)
            self.result_text.insert(tk.END, "\nPemindaian dibatalkan oleh pengguna.\n")
            self.result_text.config(state=tk.DISABLED)
            self.progress_bar.stop()
            self.is_scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.cancel_button.config(state=tk.DISABLED)

    def display_results(self, results):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.tag_config("aman", foreground="green")
        self.result_text.tag_config("mencurigakan", foreground="red")
        self.result_text.tag_config("phishing", foreground="orange")

        if results:
            for result in results:
                self.result_text.insert(tk.END, f"- URL Awal: {result['url']}\n")
                if 'final_url' in result and result['final_url'] != result['url']:
                    self.result_text.insert(tk.END, f"  Dialihkan ke: {result['final_url']}\n")
                    url_to_display = result['final_url']
                else:
                    url_to_display = result['url']

                if result['phishing']:
                    self.result_text.insert(tk.END, "  Status: Potensi Phishing\n", "phishing")
                    for reason in result['phishing_reasons']:
                        self.result_text.insert(tk.END, f"    - {reason}\n")
                elif result['suspicious']:
                    self.result_text.insert(tk.END, "  Status: Mencurigakan\n", "mencurigakan")
                    for reason in result['reasons']:
                        self.result_text.insert(tk.END, f"    - {reason}\n")
                else:
                    self.result_text.insert(tk.END, "  Status: Aman\n", "aman")
            self.result_text.insert(tk.END, "-" * 30 + "\n")
        else:
            self.result_text.insert(tk.END, "Tidak ada tautan yang ditemukan atau terjadi kesalahan.\n")
        self.result_text.config(state=tk.DISABLED)

    def update_blacklist(self):
        remote_url = self.blacklist_url_entry.get()
        logger.info(f"Memulai pembaruan blacklist dari GUI dengan URL: {remote_url}")
        if remote_url:
            message = self.link_scanner.blacklist.update_blacklist_from_url(remote_url)
            messagebox.showinfo("Pembaruan Blacklist", message)
            logger.info(f"Pembaruan blacklist dari GUI selesai. Hasil: {message}")
        else:
            messagebox.showerror("Kesalahan", "Harap masukkan URL sumber blacklist.")
            logger.warning("Gagal memperbarui blacklist dari GUI: URL sumber tidak dimasukkan.")

def main():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()