import socket
from scapy.all import sniff, send
from scapy.layers.inet import IP, UDP
import json5


def log(*args):
    print(*args)


class Subcriber:
    def __init__(self):
        with open('./config.json5') as f:
            cfg = json5.loads(f.read())
        self.serv_ip = cfg['server_ip']
        self.serv_port = cfg['server_port']
        self.serv_addr = (self.serv_ip, self.serv_port)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            self.bind(self.serv_addr)
        except Exception as e:
            log("Port has been occupied, please change port.")

    def listen(self):
        while True:
            data, src_ip = self.s.recvfrom(16)
            sport, payload = parse(data)
            log(f'{addr}->{self.serv_ip}, len:{len(payload)}')
            broadcast(src_ip, sport, payload)

    def parse(self, data):
        sport = int.from_bytes(data[0:2], byteorder='big')
        payload = data[2:]
        return sport, payload

    def broadcast(self, src_ip, sport, payload):
        for i in range(32, 0, -1):
            for j in range(32, 0, -1):
                for k in range(63, 0, -1):
                    dport = i*j*k + 1024
                    send(IP(src=src_ip, dst=self.serv_ip) / UDP(sport=sport, dport=dport) / payload)


def main():
    s = Subscriber()
    s.listen()


if __name__ == '__main__':
    main()