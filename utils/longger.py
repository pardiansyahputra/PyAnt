import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import logging


# Tentukan path ke file log
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.log')

# Buat direktori log jika belum ada
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Konfigurasi logger dasar
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename=LOG_FILE,
    encoding='utf-8'
)

# Buat logger khusus untuk aplikasi kita
logger = logging.getLogger(__name__)

# Tambahkan handler untuk menampilkan log di konsol (opsional)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)  # Hanya tampilkan WARNING dan yang lebih tinggi di konsol
formatter = logging.Formatter('%(levelname)s - %(module)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

if __name__ == "__main__":
    logger.info("Ini adalah pesan informasi.")
    logger.warning("Ini adalah pesan peringatan.")
    logger.error("Ini adalah pesan kesalahan.")