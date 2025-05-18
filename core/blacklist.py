import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import os
import re
import requests
from utils.longger import logger


class Blacklist:
    def __init__(self, blacklist_file="blacklist.txt"):
        self.blacklist_file = blacklist_file
        self.blacklist = self._load_blacklist()
        logger.info(f"Blacklist diinisialisasi dari file: {self.blacklist_file} dengan {len(self.blacklist)} entri.")

    def _load_blacklist(self):
        blacklist = set()
        if os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, "r") as f:
                for line in f:
                    entry = line.strip()
                    if entry:
                        blacklist.add(entry)
        logger.info(f"Blacklist dimuat dengan {len(blacklist)} entri dari {self.blacklist_file}.")
        return blacklist

    def add_to_blacklist(self, entry):
        if entry not in self.blacklist:
            self.blacklist.add(entry)
            self._save_blacklist()
            logger.info(f"Entri '{entry}' ditambahkan ke blacklist.")
        else:
            logger.warning(f"Entri '{entry}' sudah ada di blacklist.")

    def remove_from_blacklist(self, entry):
        if entry in self.blacklist:
            self.blacklist.remove(entry)
            self._save_blacklist()
            logger.info(f"Entri '{entry}' dihapus dari blacklist.")
        else:
            logger.warning(f"Entri '{entry}' tidak ditemukan di blacklist.")

    def check_blacklist(self, url):
        for entry in self.blacklist:
            if entry in url:
                logger.warning(f"URL '{url}' terdeteksi di blacklist karena mengandung '{entry}'.")
                return True
        return False

    def _save_blacklist(self):
        with open(self.blacklist_file, "w") as f:
            for item in self.blacklist:
                f.write(item + "\n")
        logger.info(f"Blacklist disimpan ke file: {self.blacklist_file} dengan {len(self.blacklist)} entri.")

    def update_blacklist_from_url(self, remote_url):
        try:
            logger.info(f"Memulai pembaruan blacklist dari URL: {remote_url}")
            response = requests.get(remote_url)
            response.raise_for_status()  # Raise an exception for bad status codes
            new_entries = set(line.strip() for line in response.text.splitlines() if line.strip())
            added_count = len(new_entries - self.blacklist)
            self.blacklist.update(new_entries)
            self._save_blacklist()
            logger.info(f"Blacklist berhasil diperbarui dari {remote_url}. {added_count} entri baru ditambahkan.")
            return f"Blacklist berhasil diperbarui dengan {added_count} entri baru dari {remote_url}"
        except requests.exceptions.RequestException as e:
            logger.error(f"Gagal memperbarui blacklist dari {remote_url}: {e}")
            return f"Gagal memperbarui blacklist dari {remote_url}: {e}"

if __name__ == "__main__":
    bl = Blacklist()

    while True:
        print("\nPilih tindakan:")
        print("1. Lihat daftar hitam")
        print("2. Tambah ke daftar hitam")
        print("3. Hapus dari daftar hitam")
        print("4. Periksa URL terhadap daftar hitam")
        print("5. Perbarui blacklist dari URL")
        print("6. Keluar")

        choice = input("Masukkan pilihan Anda: ")

        if choice == '1':
            print("Daftar hitam saat ini:", bl.blacklist)
        elif choice == '2':
            entry_to_add = input("Masukkan URL atau pola yang ingin ditambahkan ke daftar hitam: ")
            bl.add_to_blacklist(entry_to_add)
            print(f"'{entry_to_add}' telah ditambahkan ke daftar hitam.")
        elif choice == '3':
            entry_to_remove = input("Masukkan URL atau pola yang ingin dihapus dari daftar hitam: ")
            bl.remove_from_blacklist(entry_to_remove)
            print(f"'{entry_to_remove}' telah dihapus dari daftar hitam (jika ada).")
        elif choice == '4':
            url_to_check = input("Masukkan URL yang ingin diperiksa terhadap daftar hitam: ")
            if bl.check_blacklist(url_to_check):
                print(f"'{url_to_check}' ditemukan dalam daftar hitam.")
            else:
                print(f"'{url_to_check}' tidak ditemukan dalam daftar hitam.")
        elif choice == '5':
            remote_url = input("Masukkan URL sumber blacklist jarak jauh: ")
            message = bl.update_blacklist_from_url(remote_url)
            print(message)
        elif choice == '6':
            print("Keluar dari program.")
            break
        else:
            print("Pilihan tidak valid. Silakan coba lagi.")