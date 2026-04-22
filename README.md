# 🛡️ NIDS AI Engine (SOM) - Docker Environment

Repositori ini berisi komponen **AI Engine** untuk Sistem Deteksi Intrusi Jaringan (NIDS) berbasis arsitektur *Event-Driven* (Kafka) dan *Machine Learning* (SOM).

Komponen ini berjalan secara terisolasi di dalam **Docker Container**, bertugas untuk mengonsumsi data trafik mentah dari Kafka, melakukan prediksi anomali, dan menyimpan hasil deteksi ke dalam PostgreSQL yang dapat dipantau melalui UI pgAdmin.

---

## 🏛️ Konsep Arsitektur Sistem

Proyek ini dibangun menggunakan standar industri modern dengan menerapkan dua pola arsitektur utama:

### 1. Arsitektur Microservices
Berbeda dengan sistem *Monolithic* (di mana semua kode ditumpuk dalam satu aplikasi besar), sistem ini dipecah menjadi layanan-layanan kecil (*microservices*) yang saling mandiri:
* **Service Penyadapan (Producer):** Berjalan secara *native* di laptop pengguna untuk menangkap trafik jaringan.
* **Service Pesan (Kafka):** Berjalan di Docker sebagai terminal lalu lintas data.
* **Service AI (Consumer):** Berjalan di Docker khusus untuk menganalisis data menggunakan model SOM.
* **Service Penyimpanan & UI (PostgreSQL & pgAdmin):** Tempat penyimpanan data dan *dashboard* pemantauan visual.

*Keuntungan:* Jika salah satu layanan mati (misalnya Streamlit UI atau AI Engine sedang diperbarui), komponen lain (seperti Kafka yang sedang menerima data trafik) tidak akan ikut *crash*.

### 2. Pola Publish-Subscribe (Pub/Sub)
Sistem NIDS ini tidak saling terhubung secara langsung (seperti Producer menembak langsung ke Database). Ia menggunakan konsep **Publish-Subscribe** melalui **Apache Kafka**.
* **Publisher (Producer):** Aplikasi penyadap jaringan mem-*publish* (mengirim) data mentah paket ke sebuah "Topic" Kafka bernama `nids.raw.packets`.
* **Subscriber (Consumer):** AI Engine men-*subscribe* (berlangganan) ke Topic tersebut. Kapan pun ada data baru yang masuk, AI akan otomatis menariknya untuk diproses secara asinkron (berjalan di latar belakang tanpa mengganggu aliran trafik).

*Keuntungan:* Komponen saling *decoupled* (terpisah). Kamu bisa menambahkan 5 AI berbeda untuk men-*subscribe* topik yang sama tanpa mengubah kode Producer sama sekali!

---

## ⚙️ Persyaratan Sistem (Prerequisites)

Sebelum menjalankan komponen ini, pastikan sistem kamu sudah memenuhi syarat berikut:

1. **Docker Engine / Desktop:** Untuk menjalankan *container* layanan *backend*. [Download di sini](https://www.docker.com/products/docker-desktop/).
2. **Npcap (Khusus Pengguna Windows):** Syarat WAJIB agar *Live Producer* (`nfstream`) bisa mem-*bypass* perlindungan OS Windows dan menyadap trafik langsung dari kartu jaringan (Wi-Fi/Ethernet) dengan mode *Promiscuous*. 
   * [Download Npcap](https://npcap.com/) dan pastikan mencentang opsi *"Install Npcap in WinPcap API-compatible Mode"* saat proses instalasi.

---

## 🚀 Cara Menjalankan (Deployment Docker)

Sangat disarankan untuk menjalankan layanan infrastrukturnya menggunakan **Docker Compose**.

### 1. Persiapan File Environment
```env
# Konfigurasi Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:29092
KAFKA_RAW_TOPIC=nids.raw.packets
KAFKA_GROUP_ID=nids-ai-engine
KAFKA_CLIENT_ID=nids-client

# Konfigurasi PostgreSQL
PGHOST=localhost
PGPORT=5432
PGDATABASE=nids
PGUSER=postgres
PGPASSWORD=postgres
```

### 2. Build dan Run dengan Docker Compose
Jalankan perintah berikut di terminal:
```bash
docker-compose up -d --build
```
Perintah ini akan membangun dan menjalankan 4 layanan sekaligus: Kafka, PostgreSQL, pgAdmin, dan AI Engine.

### 3. Mengakses Database UI (pgAdmin 4)
Kamu tidak perlu lagi menginstal *tools* database di laptop. Buka browser dan ikuti langkah ini:
1. Kunjungi: `http://localhost:8080/`
2. Login dengan kredensial bawaan (sesuaikan dengan docker-compose jika diubah):
   * **Email:** `admin@admin.com`
   * **Password:** `admin`
3. Klik kanan di tab **Servers** > **Register** > **Server...**
4. Di tab **General**, beri nama (misal: `NIDS DB`).
5. Di tab **Connection**, isi konfigurasinya:
   * **Host name/address:** `db`
   * **Port:** `5432`
   * **Username:** `postgres`
   * **Password:** `postgres`
6. Klik **Save**. Kamu sekarang bisa mengeksplorasi tabel `nids_alerts` secara visual!

### 4. Memantau Log AI Engine
Untuk melihat hasil deteksi (seperti jarak BMU dan tingkat akurasi) secara *real-time* di terminal:
```bash
docker logs -f nids-ai-engine
```

---

## 💻 Menjalankan Layanan Lokal (Producer & Streamlit UI)

Karena skrip penyadap jaringan dan antarmuka UI membutuhkan akses langsung ke jaringan dan sistem operasi pengguna, keduanya **harus dijalankan di luar Docker** menggunakan *Virtual Environment* Python.

### 1. Buat Virtual Environment
Buka terminal (Command Prompt/PowerShell) di folder proyek ini, lalu jalankan:
```bash
python -m venv env
```

### 2. Aktifkan Virtual Environment
```powershell
.\env\Scripts\activate
```

### 3. Instal Dependensi
Instal semua pustaka yang dibutuhkan ke dalam lingkungan lokal yang bersih ini:
```bash
pip install -r requirements.txt
```

### 4. Eksekusi Program
Buka dua terminal terpisah (pastikan `env` sudah aktif di kedua terminal tersebut):

* **Terminal 1 (Jalankan Penyadap Jaringan):**
  ```bash
  python -m src.kafka_producer_live
  ```

* **Terminal 2 (Jalankan Streamlit UI):**
  ```bash
  streamlit run app.py
  ```
  *(Sesuaikan `app.py` dengan nama file Streamlit).*

---

## ⚠️ Catatan Penting

* **Penyadap Jaringan (Producer):** Skrip `kafka_producer_live.py` (yang menggunakan NFStream) **TIDAK** berjalan di dalam Docker ini. Producer harus dijalankan secara *native* di *Host OS* (Windows/Linux/Mac) dengan hak akses Administrator/Root.
* **Graceful Shutdown:** Karena Dockerfile menggunakan *Exec Form* (`CMD ["python", "-m", ...]`), kontainer AI dapat menerima sinyal berhenti dengan baik, sehingga koneksi Kafka dan Database akan ditutup dengan aman saat perintah `docker stop` dijalankan.
