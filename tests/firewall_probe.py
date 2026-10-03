"""Echo TCP/UDP para la prueba en namespaces; no usa servicios de producción."""
import socket
import sys
import threading


def serve():
    def tcp_loop(tcp):
        while True:
            connection, _ = tcp.accept()
            with connection:
                connection.settimeout(2)
                connection.sendall(connection.recv(32))

    def udp_loop(udp):
        while True:
            data, peer = udp.recvfrom(32)
            udp.sendto(data, peer)

    # El UDP responde desde la misma IP consultada, incluso al probar otras subredes.
    for family, address in ((socket.AF_INET, "192.168.1.10"), (socket.AF_INET6, "fd42::10")):
        for kind, port, handler in ((socket.SOCK_STREAM, 443, tcp_loop),
                                    (socket.SOCK_DGRAM, 53, udp_loop)):
            listener = socket.socket(family, kind)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((address, port))
            if kind == socket.SOCK_STREAM:
                listener.listen(4)
            threading.Thread(target=handler, args=(listener,), daemon=True).start()
    threading.Event().wait()


def client(address, expected):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    server = "fd42::10" if family == socket.AF_INET6 else "192.168.1.10"
    for kind, port in ((socket.SOCK_STREAM, 443), (socket.SOCK_DGRAM, 53)):
        with socket.socket(family, kind) as connection:
            connection.settimeout(1)
            connection.bind((address, 0))
            try:
                connection.connect((server, port))
                connection.send(b"nexo-probe")
                opened = connection.recv(32) == b"nexo-probe"
            except (TimeoutError, OSError):
                opened = False
            if opened != (expected == "open"):
                raise SystemExit("Resultado inesperado: {} puerto {}".format(address, port))
    print("PASS: {} TCP/443 y UDP/53 {}".format(address, expected))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        client(sys.argv[2], sys.argv[3])
