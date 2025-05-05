#python3

import socket
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		self.msg_hdr_ver = b'\x00\x10'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.temp_key = None
		self.session_key = None
		self.etk = None
		self.sqn = 1
		self.rnd = None
		self.rsv= None
		self.ciphertext = None 
		self.tag = None

		# keeping track of last received sqn number 

		self.last_sqn= 0

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+2], i+2
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+2], i+2
		parsed_msg_hdr['len'], i = msg_hdr[i:i+2], i+2
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+2], i+2
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+6], i+6
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+2], i+2
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received

	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message header received')

		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		# Check for replay attack
		if int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big') <= self.last_sqn:
			raise SiFT_MTP_Error('Wrong sequence number (possible replay attack)')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body) != msg_len - self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message body received')

		# Split encrypted payload and MAC
		epd = msg_body[:-12]
		mac = msg_body[-12:]

		# Construct nonce and decrypt
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		if parsed_msg_hdr['typ'] == self.type_login_req:
			key = self.temp_key
		else:
			key = self.session_key

		if key is None:
			raise SiFT_MTP_Error("Decryption key is not set (session_key or temp_key is None)")

		AES_GCM = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
		AES_GCM.update(msg_hdr)

		try:
			msg_payload = AES_GCM.decrypt_and_verify(epd, mac)
		except:
			raise SiFT_MTP_Error('Unable to decrypt and verify message body')

		# Store the new sequence number
		self.last_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')

		return parsed_msg_hdr['typ'], msg_payload

			

	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		# Calculate full message size (header + payload + MAC)
		msg_size = self.size_msg_hdr + len(msg_payload) + 12
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

		# Build header components
		sqn = self.sqn.to_bytes(2, byteorder='big')           # Current sequence number as bytes
		rnd = get_random_bytes(6)                             # 6-byte random value
		rsv = b'\x00\x00'                                     # Reserved field

		# Final message header (16 bytes)
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn + rnd + rsv

		# Derive nonce = sqn || rnd
		nonce = sqn + rnd
			
		if msg_type == self.type_login_req:
			key = self.temp_key
		else:
			key = self.session_key

		if key is None:
			raise SiFT_MTP_Error("Encryption key is not set (session_key or temp_key is None)")
		
		# AES-GCM encryption
		AES_GCM = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
		AES_GCM.update(msg_hdr)
		epd, mac = AES_GCM.encrypt_and_digest(msg_payload)

		# DEBUG
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(epd + mac)) + '): ')
			print((epd + mac).hex())
			print('------------------------------------------')

		# Send complete message
		try:
			self.send_bytes(msg_hdr + epd + mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		# Increment the sequence number
		self.sqn += 1


	def set_temp_key(self, temp_key, etk, sqn, rnd, ciphertext, tag):
		self.temp_key = temp_key
		self.etk = etk
		self.sqn = int.from_bytes(sqn, byteorder='big')
		self.rnd = rnd
		self.ciphertext = ciphertext
		self.tag = tag

	def get_temp_msg_payload(self):
		return b''.join([
			self.sqn.to_bytes(2, byteorder='big'),
			self.rnd,
			self.tag,
			self.ciphertext,
			self.etk
		])

	def set_session_key(self, session_key):
		self.session_key = session_key
