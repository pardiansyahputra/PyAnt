import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import tkinter as tk
from tkinter import ttk,messagebox
import json
import logging
from utils.longger import logger

CONFIG_FILE = "config.json"

class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, main_window): # Terima instance MainWindow
        super().__init__(parent)
        self.title("Pengaturan PyAntiVirus")
        self.geometry("400x300")
        self.parent = parent
        self.main_window = main_window # Simpan instance MainWindow
        self.settings = self.load_settings()

        self.init_widgets()
        self.populate_widgets()
        logger.info("Jendela pengaturan dibuka.")

    def load_settings(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                settings = json.load(f)
                logger.info("Pengaturan dimuat dari config.json.")
                return settings
        else:
            default_settings = {
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
            logger.info("Menggunakan pengaturan default karena config.json tidak ditemukan.")
            return default_settings

    def save_settings(self):
        url_length = self.url_length_entry.get()
        keywords = self.keyword_text.get("1.0", tk.END).strip().splitlines()
        default_blacklist_url = self.default_blacklist_url_entry.get()

        try:
            self.settings["max_url_length"] = int(url_length)
        except ValueError:
            messagebox.showerror("Kesalahan", "Batas Panjang URL harus berupa angka.")
            logger.warning("Gagal menyimpan pengaturan: Batas Panjang URL bukan angka.")
            return

        self.settings["suspicious_keywords"] = keywords
        self.settings["default_blacklist_url"] = default_blacklist_url

        with open(CONFIG_FILE, "w") as f:
            json.dump(self.settings, f, indent=2)
            logger.info("Pengaturan berhasil disimpan ke config.json.")

        messagebox.showinfo("Info", "Pengaturan berhasil disimpan.")
        self.main_window.apply_settings() # Panggil metode apply_settings di MainWindow
        self.destroy()
        logger.info("Jendela pengaturan ditutup setelah menyimpan.")

    def init_widgets(self):
        # --- Batas Panjang URL ---
        ttk.Label(self, text="Batas Panjang URL untuk Analisis:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_length_entry = ttk.Entry(self, width=10)
        self.url_length_entry.grid(row=0, column=1, padx=5, pady=5, sticky="e")

        # --- Kata Kunci Mencurigakan ---
        ttk.Label(self, text="Kata Kunci Mencurigakan (per baris):").grid(row=1, column=0, padx=5, pady=5, sticky="nw")
        self.keyword_text = tk.Text(self, height=5, width=30)
        self.keyword_text.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        # --- URL Sumber Blacklist Default ---
        ttk.Label(self, text="URL Sumber Blacklist Default:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.default_blacklist_url_entry = ttk.Entry(self, width=40)
        self.default_blacklist_url_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        # --- Tombol Aksi ---
        button_frame = ttk.Frame(self)
        button_frame.grid(row=3, column=0, columnspan=2, padx=5, pady=10, sticky="e")

        ttk.Button(button_frame, text="Simpan", command=self.save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Batal", command=self.destroy).pack(side=tk.RIGHT, padx=5)

        # Konfigurasi agar Text widget bisa diresize saat jendela diresize
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def populate_widgets(self):
        self.url_length_entry.insert(0, self.settings["max_url_length"])
        self.keyword_text.insert(tk.END, "\n".join(self.settings["suspicious_keywords"]))
        self.default_blacklist_url_entry.insert(0, self.settings["default_blacklist_url"])

if __name__ == "__main__":
    root = tk.Tk()
    # Untuk testing SettingsWindow secara mandiri, kita perlu mock MainWindow
    class MockMainWindow:
        def apply_settings(self):
            print("Pengaturan diterapkan (mock).")
    app = SettingsWindow(root, MockMainWindow())
    root.mainloop()