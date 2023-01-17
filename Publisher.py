import socket
from scapy.all import sniff
from scapy.layers.inet import UDP, IP
import json5


def port_to_bytes(n: int):
	return n.to_bytes(length=2, byteorder='big')


class Publisher:
	def __init__(self):
		with open('./config.json5') as f:
			cfg = json5.loads(f.read())
		self.serv_ip = cfg['server_ip']
		self.serv_port = cfg['server_port']
		self.iface = cfg['iface']
		self.debug = cfg['debug']
		self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	def prn(self, packet):
		sport = 65535
		dport = 65535
		try:
			sport = packet[UDP].sport
			dport = packet[UDP].dport
			if self.debug == True:
				print(f'catch: {packet[IP].src}:{sport} ->{packet[IP].dst}:{dport}')
		except Exception as e:
			if self.debug == True:
				print('Layer [UDP] not found')

		data = port_to_bytes(sport) + port_to_bytes(dport) + bytes(packet[UDP].payload)

		self.s.sendto(data, (self.serv_ip, self.serv_port))
		if self.debug == True:
			print(f'send to: {self.serv_ip}:{self.serv_port}, data len:{len(data)}')

	def run(self):
		f = 'udp'
		print('sniff:', f)
		sniff(filter=f, prn=self.prn, iface=self.iface)


def main():
	p = Publisher()
	p.run()


if __name__ == '__main__':
	main()