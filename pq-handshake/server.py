"""Handshake server.

  python server.py [--host 127.0.0.1] [--port 4433] [--pk-out server_pk.bin] [--once]

Writes its ML-DSA-87 public key to --pk-out; the client pins that key
(a stand-in for a certificate chain).
"""
import argparse
import hmac
import os
import socket
import threading

import auth
import kdf
import kex
import messages
from messages import CLIENT_HELLO, FINISHED, SERVER_HELLO, SIG_CONTEXT, ClientHello, HandshakeError, ServerHello
from record import RecordLayer, SecureChannel
from transcript import Transcript


def run_server(sock, identity):
    """Run the server side of the handshake. Returns a SecureChannel or raises HandshakeError."""
    try:
        t = Transcript()

        # 1. ClientHello: ML-KEM-1024 public key + nonce
        _, payload = messages.recv_frame(sock, CLIENT_HELLO)
        ch = ClientHello.decode(payload)
        t.add(CLIENT_HELLO, payload)

        # 2. Encapsulate to the client's key
        ct, ss = kex.encaps(ch.pk)

        # 3. Sign the transcript (ClientHello + ServerHello without the signature)
        sh = ServerHello(ct=ct, nonce=os.urandom(messages.NONCE_LEN), cert=identity.pk)
        signed = t.fork()
        signed.add(SERVER_HELLO, sh.core())
        sh.sig = auth.sign(identity.sk, SIG_CONTEXT + signed.digest())

        payload = sh.encode()
        messages.send_frame(sock, SERVER_HELLO, payload)
        t.add(SERVER_HELLO, payload)

        # 4. Key schedule, bound to the transcript
        th = t.digest()
        keys = kdf.derive(ss, th)

        # 5. Server Finished
        server_fin = kdf.finished_mac(keys.server_finished, th)
        messages.send_frame(sock, FINISHED, server_fin)
        t.add(FINISHED, server_fin)

        # 6. Verify the client's Finished
        _, client_fin = messages.recv_frame(sock, FINISHED)
        expected = kdf.finished_mac(keys.client_finished, t.digest())
        if not hmac.compare_digest(client_fin, expected):
            raise HandshakeError("client Finished MAC is wrong")
        t.add(FINISHED, client_fin)

        return SecureChannel(
            sock,
            sender=RecordLayer(keys.server_key, keys.server_iv),
            receiver=RecordLayer(keys.client_key, keys.client_iv),
            transcript_hash=t.digest(),
        )
    except Exception as e:
        _abort(sock)
        if isinstance(e, HandshakeError):
            raise
        raise HandshakeError(f"server handshake failed: {e}") from e


def _abort(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def handle(conn, addr, identity, timeout):
    """Serve one connection. Always closes it, whatever goes wrong."""
    with conn:
        # A peer that stalls (or never speaks) is dropped instead of holding the socket.
        conn.settimeout(timeout)
        try:
            channel = run_server(conn, identity)
            print(f"[server] handshake OK with {addr[0]}:{addr[1]}")
            msg = channel.recv()
            print(f"[server] received: {msg.decode(errors='replace')}")
            channel.send(b"server got: " + msg)
        except Exception as e:
            print(f"[server] connection aborted: {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--pk-out", default="server_pk.bin")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds before an idle peer is dropped")
    ap.add_argument("--once", action="store_true", help="exit after one connection")
    args = ap.parse_args()

    identity = auth.keygen()
    with open(args.pk_out, "wb") as f:
        f.write(identity.pk)
    print(f"[server] {kex.ALG} via {kex.BACKEND}; {auth.ALG} via {auth.BACKEND}")
    print(f"[server] wrote ML-DSA-87 public key to {args.pk_out}")

    with socket.create_server((args.host, args.port)) as srv:
        print(f"[server] listening on {args.host}:{args.port}")
        while True:
            conn, addr = srv.accept()
            # One thread per connection, so a slow client can't block everyone else.
            t = threading.Thread(target=handle, args=(conn, addr, identity, args.timeout), daemon=True)
            t.start()
            if args.once:
                t.join()
                break


if __name__ == "__main__":
    main()
