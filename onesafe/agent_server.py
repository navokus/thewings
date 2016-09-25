import SocketServer
import Crypto
from Crypto.PublicKey import RSA
import os
import time

server_secret = 'THE_WINGS_SCANNER'

CLIENTS = ['THE_WINGS_AGENT']						
class Server(SocketServer.StreamRequestHandler):

	def handle(self):
		#First validate server
		self.data = self.rfile.readline().strip()
		if self.data != 'VALIDATE_SERVER':
			return
		self.wfile.write(server_secret)

		#Then validate client
		self.data = self.rfile.readline().strip()
		if self.data != 'VALIDATE_CLIENT':
			return
		self.data = self.rfile.readline().strip()
		if self.data in CLIENTS:
			self.wfile.write('OK')
		else:
			self.wfile.write('FAILED')
			return

		print 'AUTHENTICATED'

		try:
			os.mkdir('monitor/%s' % (self.client_address[0]))
		except:
			pass

		file_path = 'monitor/%s/' % (self.client_address[0])
		log_content = ''
		while True:
			self.data = self.rfile.readline().strip()
			if self.data == 'END':
				self.data = self.rfile.readline().strip()
				open(os.path.join(file_path, str(int(time.time())) + '_' + self.data + '.txt') , 'wb').write(log_content)
				log_content = ''
			elif self.data == 'FIN':
				return
			elif self.data:
				print 'LOG --> ', self.data
				log_content += self.data + '\r\n'

		return


if __name__ == '__main__':

	key_data = open('priv_key').read().decode('base64')
	priv_key = RSA.importKey(key_data)
	server_secret = priv_key.decrypt(server_secret)


	host, port = '0.0.0.0', 9696

	server = SocketServer.TCPServer((host, port), Server)

	server.serve_forever()
