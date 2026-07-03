#!/usr/bin/env python3
"""
clipsync.py -- Dependency-Free Cross-Platform Clipboard Sync
============================================================
Syncs clipboard text bidirectionally between Windows (Host) and Linux (VM).
Works via raw TCP sockets. No python dependencies needed.

Usage:
  Windows Host (Server):
    python clipsync.py --bind 0.0.0.0 --port 9999

  Linux VM Guest (Client):
    python3 clipsync.py --connect <Windows_Host_IP> --port 9999
"""

import sys
import time
import socket
import struct
import threading
import subprocess

# -----------------------------------------------------------------------------
# Clipboard Utilities (Windows Native Ctypes & Linux Command-Line Fallbacks)
# -----------------------------------------------------------------------------

def setup_clipboard_functions():
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        # Win32 Constants
        CF_UNICODETEXT = 13
        GHND = 0x0042

        def get_clipboard() -> str:
            if not user32.OpenClipboard(None):
                return ""
            try:
                handle = user32.GetClipboardData(CF_UNICODETEXT)
                if not handle:
                    return ""
                ptr = kernel32.GlobalLock(handle)
                if not ptr:
                    return ""
                text = ctypes.c_wchar_p(ptr).value
                kernel32.GlobalUnlock(handle)
                return text or ""
            except Exception:
                return ""
            finally:
                user32.CloseClipboard()

        def set_clipboard(text: str) -> bool:
            if not user32.OpenClipboard(None):
                return False
            try:
                user32.EmptyClipboard()
                bytes_needed = (len(text) + 1) * ctypes.sizeof(ctypes.c_wchar)
                h_mem = kernel32.GlobalAlloc(GHND, bytes_needed)
                if not h_mem:
                    return False
                ptr = kernel32.GlobalLock(h_mem)
                if not ptr:
                    return False
                ctypes.memmove(ptr, text, bytes_needed)
                kernel32.GlobalUnlock(h_mem)
                if not user32.SetClipboardData(CF_UNICODETEXT, h_mem):
                    kernel32.GlobalFree(h_mem)
                    return False
                return True
            except Exception:
                return False
            finally:
                user32.CloseClipboard()

        return get_clipboard, set_clipboard

    else:
        # Linux / Unix Platform
        def get_clipboard() -> str:
            for cmd in [["xclip", "-selection", "clipboard", "-o"], ["xsel", "-ob"]]:
                try:
                    res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=2)
                    return res.stdout
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            return ""

        def set_clipboard(text: str) -> bool:
            for cmd in [["xclip", "-selection", "clipboard"], ["xsel", "-ib"]]:
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
                    p.communicate(input=text, timeout=2)
                    return p.returncode == 0
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            return False

        return get_clipboard, set_clipboard

# Initialize clipboard adapters
get_clip, set_clip = setup_clipboard_functions()

# -----------------------------------------------------------------------------
# Networking Protocol (Length-Prefixed UTF-8 Messages)
# -----------------------------------------------------------------------------

def send_msg(sock: socket.socket, text: str):
    data = text.encode("utf-8")
    # Send 4-byte big-endian length prefix, then the payload
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed prematurely")
        data += packet
    return data

def recv_msg(sock: socket.socket) -> str:
    header = recv_exact(sock, 4)
    length = struct.unpack(">I", header)[0]
    payload = recv_exact(sock, length)
    return payload.decode("utf-8")

# -----------------------------------------------------------------------------
# Bidirectional Sync Loops
# -----------------------------------------------------------------------------

# Shared state to prevent echo loops
last_synced_value = ""
state_lock = threading.Lock()

def socket_reader_thread(sock: socket.socket):
    """Listens for clipboard updates from the network and writes them locally."""
    global last_synced_value
    try:
        while True:
            incoming_text = recv_msg(sock)
            with state_lock:
                last_synced_value = incoming_text
                set_clip(incoming_text)
            print(f"[+] Synced from peer: {len(incoming_text)} chars")
    except (ConnectionError, socket.error) as e:
        print(f"[-] Connection lost in reader: {e}")

def run_sync(sock: socket.socket):
    global last_synced_value
    
    # Initialize the local value to current clipboard to prevent immediately sending on startup
    with state_lock:
        last_synced_value = get_clip()

    # Start network reader thread
    t = threading.Thread(target=socket_reader_thread, args=(sock,), daemon=True)
    t.start()

    print("[*] Clipboard sync active. Start copying!")
    try:
        while True:
            time.sleep(0.5)
            current_clip = get_clip()
            
            with state_lock:
                if current_clip != last_synced_value:
                    last_synced_value = current_clip
                    try:
                        send_msg(sock, current_clip)
                        print(f"[+] Sent to peer: {len(current_clip)} chars")
                    except socket.error as e:
                        print(f"[-] Failed to send: {e}")
                        break
    except KeyboardInterrupt:
        print("[*] Stopping sync loop...")

# -----------------------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------------------

def print_usage():
    print(__doc__)
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print_usage()

    mode = sys.argv[1]
    
    # Simple CLI parsing
    port = 9999
    host = "0.0.0.0"

    try:
        if "--port" in sys.argv:
            idx = sys.argv.index("--port")
            port = int(sys.argv[idx + 1])
    except Exception:
        print("[-] Invalid port number")
        sys.exit(1)

    if mode in ("--bind", "-b"):
        # Server Mode
        try:
            if idx := sys.argv.index(mode) if mode in sys.argv else None:
                if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("-"):
                    host = sys.argv[idx + 1]
        except Exception:
            pass

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((host, port))
            server.listen(1)
            print(f"[*] Server listening on {host}:{port}...")
        except Exception as e:
            print(f"[-] Bind failed: {e}")
            sys.exit(1)

        try:
            while True:
                sock, addr = server.accept()
                print(f"[+] Connected to guest VM at {addr}")
                try:
                    run_sync(sock)
                finally:
                    sock.close()
                    print("[*] Waiting for new connection...")
        except KeyboardInterrupt:
            print("\n[*] Exiting server.")
            server.close()

    elif mode in ("--connect", "-c"):
        # Client Mode
        target_ip = None
        try:
            idx = sys.argv.index(mode)
            if idx + 1 < len(sys.argv):
                target_ip = sys.argv[idx + 1]
        except Exception:
            pass

        if not target_ip:
            print("[-] Please specify host IP to connect to.")
            print("Usage: clipsync.py --connect <IP>")
            sys.exit(1)

        while True:
            print(f"[*] Attempting to connect to {target_ip}:{port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((target_ip, port))
                print("[+] Connected to host successfully!")
                run_sync(sock)
            except (ConnectionRefusedError, socket.error) as e:
                print(f"[-] Connection failed ({e}). Reconnecting in 3s...")
                time.sleep(3)
            finally:
                sock.close()
    else:
        print_usage()

if __name__ == "__main__":
    main()
