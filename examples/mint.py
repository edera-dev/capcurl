#!/usr/bin/env python3
"""Mint a capcurl descriptor and drive it, without linking anything.

Demonstrates that a minted descriptor is an ordinary socket and the mint
handshake is an ordinary protocol: this is the whole client, in one file, in a
language that knows nothing about capcurl.

    ./mint.py /run/cap/issues /42

The wire format is capsudo's: a u32 little-endian field type, a u32
little-endian length, then the payload. The descriptor itself arrives
out-of-band over SCM_RIGHTS.
"""

import array
import socket
import struct
import sys

ARG, FD, ERROR, END = 1, 4, 6, 255


def frame(field_type, payload=b""):
    return struct.pack("<II", field_type, len(payload)) + payload


def recv_exactly(sock, n, fds):
    """Reads n bytes, collecting any descriptors that arrive alongside them."""
    buf = b""
    while len(buf) < n:
        space = socket.CMSG_SPACE(4 * 8)
        chunk, ancillary, _flags, _addr = sock.recvmsg(n - len(buf), space)
        if not chunk:
            raise RuntimeError("capability closed during the mint handshake")
        for level, cmsg_type, data in ancillary:
            if level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                received = array.array("i")
                received.frombytes(data[: len(data) - (len(data) % received.itemsize)])
                fds.extend(received)
        buf += chunk
    return buf


def mint(endpoint, method, target):
    """Returns a socket bound to exactly one request."""
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.connect(endpoint)
    control.sendall(frame(ARG, method.encode()) + frame(ARG, target.encode()) + frame(END))

    bound = []
    fds = []
    while True:
        field_type, length = struct.unpack("<II", recv_exactly(control, 8, fds))
        payload = recv_exactly(control, length, fds) if length else b""

        if field_type == ARG:
            bound.append(payload.decode())
        elif field_type == ERROR:
            raise RuntimeError(payload.decode())
        elif field_type == FD:
            if not fds:
                raise RuntimeError("daemon promised a descriptor but sent none")
            # The control socket has done its job; the descriptor is the
            # capability now, and closing this does not revoke it.
            capability = socket.socket(fileno=fds[0])
            control.close()
            return capability, (bound + [method, target])[:2]
        else:
            raise RuntimeError(f"unexpected message type {field_type}")


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <endpoint> [target] [method]")
    endpoint = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else "/"
    method = sys.argv[3] if len(sys.argv) > 3 else "GET"

    capability, (bound_method, bound_target) = mint(endpoint, method, target)

    # Ordinary HTTP/1.1 on an ordinary socket. The authority is the daemon's to
    # know, so Host is a placeholder and is discarded.
    request = (
        f"{bound_method} {bound_target} HTTP/1.1\r\n"
        "Host: capability.invalid\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    capability.sendall(request.encode())

    response = b""
    while True:
        chunk = capability.recv(65536)
        if not chunk:
            break
        response += chunk

    head, _, body = response.partition(b"\r\n\r\n")
    print(head.decode(errors="replace").splitlines()[0])
    sys.stdout.write(body.decode(errors="replace"))


if __name__ == "__main__":
    main()
