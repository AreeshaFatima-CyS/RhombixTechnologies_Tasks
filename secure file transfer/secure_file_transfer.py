import socket, os, hashlib, logging, json, threading
from cryptography.fernet import Fernet
 
# ---------- CONFIG ----------
HOST, PORT, BUFFER = "127.0.0.1", 5001, 4096
KEY_FILE = "secret.key"
USERS = {
    "admin":  hashlib.sha256(b"admin123").hexdigest(),
    "intern": hashlib.sha256(b"intern123").hexdigest(),
}
 
# ---------- LOGGING ----------
logging.basicConfig(filename="audit_log.txt", level=logging.INFO,
                    format="%(asctime)s | %(message)s")
def log(msg): print(msg); logging.info(msg)
 
# ---------- KEY ----------
def get_key():
    if not os.path.exists(KEY_FILE):
        open(KEY_FILE, "wb").write(Fernet.generate_key())
    return open(KEY_FILE, "rb").read()
 
# ---------- ENCRYPT / DECRYPT ----------
def encrypt(data): return Fernet(get_key()).encrypt(data)
def decrypt(data): return Fernet(get_key()).decrypt(data)
 
# ---------- HASH ----------
def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): h.update(chunk)
    return h.hexdigest()
 
# ---------- AUTH ----------
def authenticate(user, pwd):
    return USERS.get(user) == hashlib.sha256(pwd.encode()).hexdigest()
 
# ---------- SEND HELPER ----------
def send_msg(sock, data: bytes):
    size = len(data)
    sock.sendall(size.to_bytes(4, 'big') + data)
 
def recv_msg(sock) -> bytes:
    raw = sock.recv(4)
    size = int.from_bytes(raw, 'big')
    data = b""
    while len(data) < size:
        data += sock.recv(min(BUFFER, size - len(data)))
    return data
 
# ---------- SERVER ----------
def handle_client(conn, addr):
    log(f"[SERVER] Connection: {addr}")
    try:
        creds = recv_msg(conn).decode()
        user, pwd = creds.split(":")
        if not authenticate(user, pwd):
            send_msg(conn, b"AUTH_FAIL")
            log(f"[AUTH] Failed: {user}"); return
        send_msg(conn, b"AUTH_OK")
        log(f"[AUTH] Login: {user}")
 
        meta = json.loads(recv_msg(conn).decode())
        fname, sent_hash = meta["filename"], meta["hash"]
 
        enc_data = recv_msg(conn)
 
        os.makedirs("received_files", exist_ok=True)
        out_path = f"received_files/{fname}"
        with open(out_path, "wb") as f:
            f.write(decrypt(enc_data))
 
        if file_hash(out_path) == sent_hash:
            send_msg(conn, b"OK")
            log(f"[OK] '{fname}' from '{user}' - Integrity VERIFIED")
        else:
            send_msg(conn, b"FAIL")
            log(f"[ERROR] Hash mismatch for '{fname}'")
    except Exception as e:
        log(f"[ERROR] {e}")
    finally:
        conn.close()
 
def start_server():
    get_key()
    s = socket.socket(); s.bind((HOST, PORT)); s.listen(5)
    log(f"[SERVER] Running on {HOST}:{PORT} ...")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()
 
# ---------- CLIENT ----------
def send_file(filepath, user, pwd):
    if not os.path.exists(filepath):
        print("[ERROR] File not found."); return
 
    with open(filepath, "rb") as f: raw = f.read()
    orig_hash = file_hash(filepath)
    enc_data = encrypt(raw)
 
    c = socket.socket(); c.connect((HOST, PORT))
 
    send_msg(c, f"{user}:{pwd}".encode())
    resp = recv_msg(c)
    if resp != b"AUTH_OK":
        print("[!] Auth failed."); c.close(); return
    print("[OK] Authenticated.")
 
    meta = json.dumps({"filename": os.path.basename(filepath), "hash": orig_hash})
    send_msg(c, meta.encode())
    send_msg(c, enc_data)
 
    result = recv_msg(c)
    if result == b"OK":
        print("[OK] Transfer successful & verified!")
        log(f"[CLIENT] '{filepath}' sent by '{user}'. Result: OK")
    else:
        print("[!] Transfer failed.")
    c.close()
 
# ---------- MAIN ----------
if __name__ == "__main__":
    print("\n=== Secure File Transfer | Rhombix Technologies ===")
    print("1. Start Server\n2. Send File")
    choice = input("Choice: ").strip()
 
    if choice == "1":
        start_server()
    elif choice == "2":
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        f = input("File path (e.g. test.txt): ").strip()
        send_file(f, u, p)
    else:
        print("Invalid choice.")
 
