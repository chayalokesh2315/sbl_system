"""Check your Gemini key and connection, and time it.

Run from the sbl_system folder, in the same terminal where you set the key:
    set SBL_AI_KEY=your-key        (Windows)
    python test_gemini.py
"""
import socket
import time
import urllib.error

from app import ai_assist

HOST = "generativelanguage.googleapis.com"

key = ai_assist.get_key()
print(f"Models to try: {ai_assist.get_models()} | key set: {bool(key)} | timeout: {ai_assist.get_timeout()}s")
if not key:
    raise SystemExit("No key found. Set SBL_AI_KEY in this terminal first.")

print("\n1) Connection test (3s limit each)")
for label, fam in (("IPv4", socket.AF_INET), ("IPv6", socket.AF_INET6)):
    t = time.time()
    try:
        infos = socket.getaddrinfo(HOST, 443, fam, socket.SOCK_STREAM)
        socket.create_connection(infos[0][4][:2], timeout=3).close()
        print(f"   {label}: OK in {time.time() - t:.1f}s")
    except OSError as e:
        print(f"   {label}: FAILED after {time.time() - t:.1f}s ({e})")
print("   (The app uses IPv4 only, so an IPv6 failure is fine.)")

print("\n2) Asking Gemini for a one-line reply")
t = time.time()
try:
    text, model = ai_assist._generate('Reply with JSON {"ok": true}', key, ai_assist.get_models(),
                                      ai_assist.get_timeout())
    print(f"   {model} answered in {time.time() - t:.1f}s: {text.strip()[:120]}")
except urllib.error.HTTPError as e:
    detail = e.read().decode("utf-8", "ignore")[:400]
    print(f"   HTTP {e.code} after {time.time() - t:.1f}s: {detail}")
except Exception as e:
    print(f"   Failed after {time.time() - t:.1f}s: {type(e).__name__}: {e}")
