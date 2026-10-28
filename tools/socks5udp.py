import socket, struct

class Socks5UDP:
    def __init__(self, proxy=("127.0.0.1",10808), timeout=5):
        self.tcp = socket.create_connection(proxy, timeout)
        self.tcp.settimeout(timeout)
        self.tcp.sendall(b"\x05\x01\x00")
        if self.tcp.recv(2) != b"\x05\x00":
            raise RuntimeError("socks5 auth failed")
        self.tcp.sendall(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        rep = self.tcp.recv(10)
        if rep[1] != 0:
            raise RuntimeError(f"udp associate failed rep={rep[1]}")
        atyp = rep[3]
        if atyp == 1:
            self.relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
        elif atyp == 4:
            self.relay = (socket.inet_ntop(socket.AF_INET6, rep[4:20]), struct.unpack(">H", rep[20:22])[0])
        else:
            raise RuntimeError("bad atyp")
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(timeout)

    def sendto(self, data, dst):
        hdr = b"\x00\x00\x00\x01" + socket.inet_aton(dst[0]) + struct.pack(">H", dst[1])
        self.udp.sendto(hdr + data, self.relay)

    def recvfrom(self, n=2048):
        pkt, _ = self.udp.recvfrom(n + 32)
        atyp = pkt[3]
        if atyp == 1:
            off = 4 + 4 + 2
        elif atyp == 4:
            off = 4 + 16 + 2
        else:
            l = pkt[4]; off = 5 + l + 2
        return pkt[off:], None

    def close(self):
        try: self.udp.close()
        except Exception: pass
        try: self.tcp.close()
        except Exception: pass

if __name__ == "__main__":
    import time
    q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"
    s = Socks5UDP()
    print("relay:", s.relay)
    t0 = time.time()
    s.sendto(q, ("8.8.8.8", 53))
    d, _ = s.recvfrom()
    print("dns ok len", len(d), "rtt", round((time.time()-t0)*1000,1))
    s.close()
