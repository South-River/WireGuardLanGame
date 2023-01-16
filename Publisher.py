import socket
from scapy.all import sniff, send
import json5


def log(*args):
	print(*args)


class Publisher:
	def __init__(self):
		with open('./config.json5') as f:
			cfg = json5.loads(f.read())
		self.serv_ip = cfg['server_ip']
		self.serv_port = cfg['server_port']
		self.iface = cfg['iface']
		self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	def prn(self, packet):
		sport = packet[UDP].sport
		dport = packet[UDP].dport
		log(f'catch: {packet[IP].src}:{sport} ->{packet[IP].dst}:{dport}')

		data = port_to_bytes(sport) + bytes(packet[UDP].payload)

		for i in range(0, 20):
			self.s.sendto(data, (self.serv_ip, self.serv_port))
			log(f'send to: {self.serv_ip}:{self.serv_port}, data len:{len(data)}')

	def run(self):
		f = 'udp and dst 255.255.255.255'
		log('sniff:', f)
		sniff(filter=f, prn=self.prn, iface=self.iface)


def main():
	p = Publisher()
	p.run()


if __name__ == '__main__':
	main()