import socket
from scapy.all import send
from scapy.layers.inet import IP, UDP
import json5


def log(*args):
    print(*args)


class Subscriber:
    def __init__(self):
        with open('./config.json5') as f:
            cfg = json5.loads(f.read())
        self.serv_ip = cfg['server_ip']
        self.serv_port = cfg['server_port']
        self.serv_addr = (self.serv_ip, self.serv_port)

        self.broadcast_list = cfg['broadcast_list']

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.s.bind(self.serv_addr)
        except Exception as e:
            log(f"Port {self.serv_port} has been occupied, please change port.")
        
        log(f"Listening Port {self.serv_port}.")

    def broadcast(self, src, sport, dport, payload):
        for dst in self.broadcast_list:
            if dst == src[0]:
                continue
            print(f'src: {(src[0], sport)}, dst: {(dst, dport)}')
            send(IP(src=src[0], dst=dst) / UDP(sport=sport, dport=dport) / payload)


    def parse(self, data):
        sport = int.from_bytes(data[0:2], byteorder='big')
        dport = int.from_bytes(data[2:4], byteorder='big')
        payload = data[4:]
        return sport, dport, payload

    def listen(self):
        while True:
            data, src = self.s.recvfrom(1024)
            sport, dport, payload = self.parse(data)
            log(f'{src[0]}->{self.serv_ip}, len:{len(payload)}')
            self.broadcast(src, sport, dport, payload)


def main():
    s = Subscriber()
    s.listen()


if __name__ == '__main__':
    main()