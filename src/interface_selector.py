from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)

def select_interface(provided_iface: str | None = None) -> str:
    if provided_iface:
        log.info("Menggunakan interface manual dari argumen: %s", provided_iface)
        return provided_iface

    try:
        # Menggunakan Scapy untuk mengambil detail adapter jaringan
        from scapy.interfaces import get_working_ifaces
        from scapy.all import conf
        
        ifaces = get_working_ifaces()
        
        print("\n" + "="*80)
        print("DAFTAR INTERFACE JARINGAN TERSEDIA")
        print("="*80)
        print("0. [Auto-Detect] Gunakan Default Route")
        
        for idx, iface in enumerate(ifaces, start=1):
            # Menampilkan nama logical (Wi-Fi) dan description (Intel(R) Wireless...)
            print(f"{idx}. {iface.name:<25} | Hardware: {iface.description}")
            print(f"   (IP: {iface.ip})")
            print("-" * 80)
            
        choice = input(f"Pilih nomor interface (0-{len(ifaces)}): ")
        
        try:
            choice_idx = int(choice.strip())
            if choice_idx == 0:
                iface_to_use = conf.iface.description
                log.info("Auto-Detect memilih: %s", iface_to_use)
                return iface_to_use
            elif 1 <= choice_idx <= len(ifaces):
                iface_to_use = ifaces[choice_idx - 1].description
                log.info("Menggunakan interface: %s", iface_to_use)
                return iface_to_use
            else:
                log.error("Pilihan tidak valid. Silakan jalankan ulang script.")
                sys.exit(1)
        except ValueError:
            log.error("Harap masukkan angka yang valid.")
            sys.exit(1)
            
    except Exception as e:
        log.error("Gagal memuat daftar interface otomatis: %s", e)
        log.info("Silakan masukkan interface manual menggunakan argumen --iface")
        sys.exit(1)