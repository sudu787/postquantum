"""Handshake client.

  python client.py [--host 127.0.0.1] [--port 4433] [--server-pk server_pk.bin] [--message "hi"]
"""
import argparse
import hmac
import os
import socket

import auth
import kdf
import kex
import messages
from messages import CLIENT_HELLO, FINISHED, SERVER_HELLO, SIG_CONTEXT, ClientHello, HandshakeError, ServerHello
from record import RecordLayer, SecureChannel
from transcript import Transcript


def run_client(sock, server_pk):
    """Run the client side of the handshake against a server whose ML-DSA-87
    public key is `server_pk`. Returns a SecureChannel or raises HandshakeError."""
    try:
        t = Transcript()

        # 1. Fresh ML-KEM-1024 key pair for this connection
        pk, sk = kex.keygen()
        payload = ClientHello(pk=pk, nonce=os.urandom(messages.NONCE_LEN)).encode()
        messages.send_frame(sock, CLIENT_HELLO, payload)
        t.add(CLIENT_HELLO, payload)

        # 2. ServerHello: authenticate the server before trusting the ciphertext
        _, payload = messages.recv_frame(sock, SERVER_HELLO)
        sh = ServerHello.decode(payload)
        if not hmac.compare_digest(sh.cert, server_pk):
            raise HandshakeError("unknown server identity (public key not pinned)")
        signed = t.fork()
        signed.add(SERVER_HELLO, sh.core())
        if not auth.verify(sh.cert, SIG_CONTEXT + signed.digest(), sh.sig):
            raise HandshakeError("server signature does not verify")
        t.add(SERVER_HELLO, payload)

        # 3. Decapsulate and run the key schedule
        ss = kex.decaps(sk, sh.ct)
        th = t.digest()
        keys = kdf.derive(ss, th)

        # 4. Verify the server's Finished
        _, server_fin = messages.recv_frame(sock, FINISHED)
        if not hmac.compare_digest(server_fin, kdf.finished_mac(keys.server_finished, th)):
            raise HandshakeError("server Finished MAC is wrong")
        t.add(FINISHED, server_fin)

        # 5. Client Finished
        client_fin = kdf.finished_mac(keys.client_finished, t.digest())
        messages.send_frame(sock, FINISHED, client_fin)
        t.add(FINISHED, client_fin)

        return SecureChannel(
            sock,
            sender=RecordLayer(keys.client_key, keys.client_iv),
            receiver=RecordLayer(keys.server_key, keys.server_iv),
            transcript_hash=t.digest(),
        )
    except Exception as e:
        _abort(sock)
        if isinstance(e, HandshakeError):
            raise
        raise HandshakeError(f"client handshake failed: {e}") from e


def _abort(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--server-pk", default="server_pk.bin")
    ap.add_argument("--message", default="hello over ML-KEM-1024")
    ap.add_argument("--timeout", type=float, default=15.0, help="seconds to wait for the server")
    args = ap.parse_args()

    with open(args.server_pk, "rb") as f:
        server_pk = f.read()

    print(f"[client] {kex.ALG} via {kex.BACKEND}; {auth.ALG} via {auth.BACKEND}")
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        channel = run_client(sock, server_pk)
        print("[client] handshake OK")
        channel.send(args.message.encode())
        print(f"[client] reply: {channel.recv().decode(errors='replace')}")


if __name__ == "__main__":
    main()
