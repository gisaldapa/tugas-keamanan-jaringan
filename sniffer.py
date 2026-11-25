"""
Otomatisasi Packet Sniffer & Analyzer PCAP (Scapy / Npcap Loopback).

Kompatibel dengan Wireshark/tshark:
- Mode Capture: Menangkap paket TCP pada interface loopback (lo / \\Device\\NPF_Loopback)
  dengan filter port aplikasi (default: tcp port 8000) dan menyimpannya ke file .pcap.
- Mode Analyze: Membaca file .pcap dan mengekstrak header IP/TCP serta payload HTTP
  secara detail ke terminal (ekuivalen dengan `tshark -r bukti_sniffing.pcap -Y "http" -V`).
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from scapy.all import IP, IPv6, TCP, Raw, conf, get_if_list, rdpcap, sniff, wrpcap


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ", b"HTTP/")


def resolve_loopback_interface(requested_iface: str | None) -> str:
    """Menentukan interface loopback aktif untuk Windows (Npcap) maupun Linux (lo)."""
    if requested_iface:
        return requested_iface

    available = get_if_list()
    if conf.loopback_name and conf.loopback_name in available:
        return conf.loopback_name

    for candidate in ("lo", "lo0", r"\Device\NPF_Loopback"):
        if candidate in available:
            return candidate

    raise RuntimeError(
        f"Interface loopback tidak ditemukan. Interface tersedia: {available}"
    )


def format_tcp_flags(tcp_layer: TCP) -> str:
    """Mengubah bitmask TCP flags menjadi string yang mudah dibaca."""
    return str(tcp_layer.flags)


def capture_packets(
    output_path: str,
    port: int = 8000,
    iface: str | None = None,
    duration: float | None = None,
    ready_file: str | None = None,
    stop_file: str | None = None,
) -> int:
    """Menangkap paket pada interface loopback dan menulisnya ke file PCAP."""
    target_iface = resolve_loopback_interface(iface)
    bpf_filter = f"tcp port {port}"
    captured = []
    stop_requested = False

    def _handle_signal(signum, frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    print(f"[SNIFFER] Interface   : {target_iface}")
    print(f"[SNIFFER] BPF Filter  : {bpf_filter}")
    print(f"[SNIFFER] Output PCAP : {output_path}")
    print("[SNIFFER] Memulai perekaman paket...")

    if ready_file:
        Path(ready_file).write_text("READY", encoding="utf-8")

    start_time = time.monotonic()

    def _should_stop(_pkt) -> bool:
        if stop_requested:
            return True
        if stop_file and os.path.exists(stop_file):
            return True
        if duration is not None and (time.monotonic() - start_time) >= duration:
            return True
        return False

    def _on_packet(pkt):
        captured.append(pkt)

    while not _should_stop(None):
        remaining = 0.5
        if duration is not None:
            left = duration - (time.monotonic() - start_time)
            if left <= 0:
                break
            remaining = min(0.5, left)

        sniff(
            iface=target_iface,
            filter=bpf_filter,
            prn=_on_packet,
            store=False,
            timeout=remaining,
            stop_filter=_should_stop,
        )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, captured)
    print(f"[SNIFFER] Perekaman selesai. Total paket tersimpan: {len(captured)} -> {output_path}")
    return len(captured)


def analyze_pcap(pcap_path: str, port: int = 8000, http_only: bool = True) -> None:
    """Membaca file PCAP dan menampilkan detail paket TCP + payload HTTP di terminal."""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"File PCAP tidak ditemukan: {pcap_path}")

    packets = rdpcap(pcap_path)
    print("=" * 80)
    print(f"ANALISIS FILE PCAP : {pcap_path}")
    print(f"Total Paket        : {len(packets)}")
    print(f"Filter Tampilan    : TCP port {port}" + (" (HTTP Payload Only)" if http_only else " (All TCP)"))
    print("=" * 80)

    shown = 0
    for idx, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(TCP):
            continue

        tcp = pkt[TCP]
        if tcp.sport != port and tcp.dport != port:
            continue

        raw_bytes = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

        if http_only and not raw_bytes:
            continue

        shown += 1
        src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "loopback")
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "loopback")
        ts = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        print(f"\n--- Frame #{idx} | Timestamp: {ts} | Length: {len(pkt)} bytes ---")
        print(f"Network Layer   : {src_ip} -> {dst_ip}")
        print(
            f"Transport (TCP) : {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport} "
            f"[Flags: {format_tcp_flags(tcp)}, Seq={tcp.seq}, Ack={tcp.ack}, Payload={len(raw_bytes)}B]"
        )

        if raw_bytes:
            decoded = raw_bytes.decode("utf-8", errors="replace")
            print("HTTP Payload    :")
            for line in decoded.splitlines():
                print(f"    {line}")
            if not decoded.endswith("\n"):
                print()

    print("=" * 80)
    print(f"Total paket yang ditampilkan: {shown}")
    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Packet Sniffer & PCAP Analyzer untuk simulasi jaringan lokal."
    )
    parser.add_argument(
        "--capture",
        action="store_true",
        help="Menjalankan mode perekaman paket ke file PCAP.",
    )
    parser.add_argument(
        "--analyze",
        metavar="PCAP_FILE",
        help="Menganalisis file PCAP dan menampilkan header TCP/HTTP + payload.",
    )
    parser.add_argument(
        "--output",
        default="bukti_sniffing.pcap",
        help="Nama file output PCAP (default: bukti_sniffing.pcap).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port TCP target untuk filter (default: 8000).",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Nama interface jaringan (otomatis mendeteksi loopback jika kosong).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Durasi perekaman maksimum dalam detik.",
    )
    parser.add_argument(
        "--ready-file",
        default=None,
        help="File penanda yang dibuat saat sniffer siap merekam.",
    )
    parser.add_argument(
        "--stop-file",
        default=None,
        help="File pemicu untuk menghentikan perekaman dengan bersih.",
    )
    parser.add_argument(
        "--all-tcp",
        action="store_true",
        help="Saat --analyze, tampilkan semua paket TCP (termasuk SYN/ACK tanpa payload).",
    )

    args = parser.parse_args()

    if args.analyze:
        analyze_pcap(args.analyze, port=args.port, http_only=not args.all_tcp)
        return

    if args.capture:
        capture_packets(
            output_path=args.output,
            port=args.port,
            iface=args.iface,
            duration=args.duration,
            ready_file=args.ready_file,
            stop_file=args.stop_file,
        )
        return

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
