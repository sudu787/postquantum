"""Live demo for the presentation: one honest handshake, then four attacks.

  python demo.py              # pauses between steps (press Enter)
  python demo.py --no-pause   # runs straight through

Everything runs on this machine. An "attacker" sits between the client and
the server and can read, change or replay every message.
"""
import argparse
import socket
import struct
import threading

import auth
import kex
import messages
from client import run_client
from messages import APP_DATA, CLIENT_HELLO, FINISHED, SERVER_HELLO, HandshakeError
from server import run_server

NAMES = {CLIENT_HELLO: "ClientHello", SERVER_HELLO: "ServerHello", FINISHED: "Finished", APP_DATA: "AppData"}
PAUSE = True


def step(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def pause():
    if PAUSE:
        input("\n  [press Enter to continue]")


class Attacker:
    """Sits on the wire between client and server; sees and can change every frame."""

    def __init__(self, tamper=None, show=False):
        self.tamper = tamper
        self.show = show
        self.log = []

    def _relay(self, src, dst, direction):
        try:
            while True:
                t, payload = messages.recv_frame(src)
                self.log.append((direction, t, payload))
                if self.show:
                    arrow = "client -> server" if direction == "c2s" else "server -> client"
                    print(f"  {arrow}  {NAMES.get(t, t):<12} {len(payload):>6,} bytes")
                if self.tamper:
                    t, payload = self.tamper(direction, t, payload)
                messages.send_frame(dst, t, payload)
        except (HandshakeError, OSError):
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def connect(identity, pinned_pk, attacker):
    """Run client and server with `attacker` in the middle. Returns (client, server) results."""
    c_sock, a1 = socket.socketpair()
    a2, s_sock = socket.socketpair()
    for s in (c_sock, a1, a2, s_sock):
        s.settimeout(30)
    threading.Thread(target=attacker._relay, args=(a1, a2, "c2s"), daemon=True).start()
    threading.Thread(target=attacker._relay, args=(a2, a1, "s2c"), daemon=True).start()

    out = {}

    def server_side():
        try:
            out["server"] = run_server(s_sock, identity)
        except Exception as e:
            out["server"] = e

    st = threading.Thread(target=server_side, daemon=True)
    st.start()
    try:
        out["client"] = run_client(c_sock, pinned_pk)
    except Exception as e:
        out["client"] = e
    st.join(30)
    return out["client"], out.get("server")


def verdict(client, server):
    for side, r in (("client", client), ("server", server)):
        if isinstance(r, Exception):
            print(f"  {side}: REJECTED -> {r}")
        else:
            print(f"  {side}: handshake completed")
    blocked = isinstance(client, Exception) or isinstance(server, Exception)
    print("\n  RESULT: " + ("attack BLOCKED" if blocked else "attack SUCCEEDED (bad!)"))
    return blocked


def flip_bit(payload, index):
    b = bytearray(payload)
    b[index] ^= 0x01
    return bytes(b)


def main():
    global PAUSE
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-pause", action="store_true")
    PAUSE = not ap.parse_args().no_pause

    step("0. Setup")
    print(f"  Key exchange : {kex.ALG}  ({kex.BACKEND})")
    print(f"  Signatures   : {auth.ALG}  ({auth.BACKEND})")
    print("  KDF / hash   : HKDF-SHA384 / SHA-384     Records: AES-256-GCM")
    identity = auth.keygen()
    print(f"  Server identity: ML-DSA-87 public key, {len(identity.pk):,} bytes (the client pins it)")
    pause()

    results = []

    # ---- 1. honest handshake ----------------------------------------------
    step("1. Honest handshake (an eavesdropper records everything)")
    spy = Attacker(show=True)
    client, server = connect(identity, identity.pk, spy)
    secret = b"Exam answers: ML-KEM-1024 resists Shor"
    client.send(secret)
    received = server.recv()
    server.send(b"ack")
    client.recv()
    record = [p for d, t, p in spy.log if t == APP_DATA][0]
    print(f"\n  client sent    : {secret.decode()}")
    print(f"  server got     : {received.decode()}")
    print(f"  eavesdropper saw: {record[:24].hex()}...  ({len(record)} bytes of ciphertext)")
    print(f"  plaintext visible on the wire? {secret in b''.join(p for _, _, p in spy.log)}")
    print(f"  both sides agree on transcript: {client.transcript_hash == server.transcript_hash}")
    pause()

    # ---- 2. man in the middle ---------------------------------------------
    step("2. Man-in-the-middle: attacker answers with its OWN server key")
    impostor = auth.keygen()
    print("  The attacker runs its own ML-DSA-87 key pair and pretends to be the server.")
    results.append(("Man-in-the-middle", verdict(*connect(impostor, identity.pk, Attacker()))))
    pause()

    # ---- 3. tampering -----------------------------------------------------
    step("3. Tampering: flip ONE bit of the ML-KEM-1024 ciphertext in transit")

    def tamper_ct(d, t, p):
        if d == "s2c" and t == SERVER_HELLO:
            print("  attacker: flipping 1 bit inside the ciphertext...")
            p = flip_bit(p, 3 + 2 + 100)
        return t, p

    results.append(("Tampering", verdict(*connect(identity, identity.pk, Attacker(tamper_ct)))))
    pause()

    # ---- 4. downgrade -----------------------------------------------------
    step("4. Downgrade: rewrite the ClientHello to ask for a weaker suite")

    def downgrade(d, t, p):
        if d == "c2s" and t == CLIENT_HELLO:
            print("  attacker: changing suite 0x1024 (ML-KEM-1024) -> 0x0512 (ML-KEM-512)...")
            p = p[:1] + struct.pack(">H", 0x0512) + p[3:]
        return t, p

    results.append(("Downgrade", verdict(*connect(identity, identity.pk, Attacker(downgrade)))))
    pause()

    # ---- 5. replay --------------------------------------------------------
    step("5. Replay: record an honest session, then resend the client's messages")
    rec = Attacker()
    c, s = connect(identity, identity.pk, rec)
    c.send(b"pay 100 rupees")
    print(f"  honest session: server received '{s.recv().decode()}'")
    flight = [(t, p) for d, t, p in rec.log if d == "c2s"]

    a_sock, s_sock = socket.socketpair()
    a_sock.settimeout(30)
    s_sock.settimeout(30)
    out = {}
    st = threading.Thread(target=lambda: out.update(r=_try(run_server, s_sock, identity)), daemon=True)
    st.start()
    print("  attacker: replaying the recorded ClientHello, Finished and payment...")
    try:
        messages.send_frame(a_sock, *flight[0])
        messages.recv_frame(a_sock, SERVER_HELLO)
        messages.recv_frame(a_sock, FINISHED)
        messages.send_frame(a_sock, *flight[1])
        messages.send_frame(a_sock, *flight[2])
    except (HandshakeError, OSError):
        pass
    st.join(30)
    r = out.get("r")
    if isinstance(r, Exception):
        print(f"  server: REJECTED -> {r}")
        print("\n  RESULT: attack BLOCKED (the server used a fresh nonce and ciphertext,"
              " so the old Finished MAC no longer matches)")
    results.append(("Replay", isinstance(r, Exception)))
    pause()

    # ---- summary ----------------------------------------------------------
    step("Summary")
    for name, blocked in results:
        print(f"  {name:<20} {'BLOCKED' if blocked else 'NOT BLOCKED'}")
    print("\n  Message sizes on the wire (payload bytes):")
    for d, t, p in spy.log:
        if t != APP_DATA:
            print(f"    {NAMES[t]:<12} {len(p):>6,}")
    print()


def _try(fn, *args):
    try:
        return fn(*args)
    except Exception as e:
        return e


if __name__ == "__main__":
    main()
