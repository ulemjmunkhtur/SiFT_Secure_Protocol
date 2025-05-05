#python3


import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error



class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None 

        # Transfer Key
        self.rand_client = None
        self.rand_server = None
        self.final_key = None


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users


    # builds a login request from a dictionary
    def build_login_req(self, timestamp, username, password, client_random):
        req = f"{timestamp}{self.delimiter}{username}{self.delimiter}{password}{self.delimiter}{client_random.hex()}"
        return req.encode(self.coding)


    def parse_login_req(self, login_req):
        fields = login_req.decode(self.coding).split(self.delimiter)
        return {
            'timestamp': fields[0],
            'username': fields[1],
            'password': fields[2],
            'client_random': bytes.fromhex(fields[3])
        }
    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        login_res_str = login_res_struct['request_hash'].hex() 
        login_res_str += self.delimiter + login_res_struct['server_random']
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {
            'request_hash': bytes.fromhex(login_res_fields[0]),
            'server_random': bytes.fromhex(login_res_fields[1])
        }
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False
    
    def handle_login_server(self):
        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # Step 1: Receive message header and body manually
        try:
            msg_hdr = self.mtp.receive_bytes(self.mtp.size_msg_hdr)
            parsed_hdr = self.mtp.parse_msg_header(msg_hdr)
            msg_len = int.from_bytes(parsed_hdr['len'], byteorder='big')
            msg_body = self.mtp.receive_bytes(msg_len - self.mtp.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        if parsed_hdr['typ'] != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # Step 2: Extract nonce and split body
        try:
            sqn = parsed_hdr['sqn']
            rnd = parsed_hdr['rnd']
            nonce = sqn + rnd

            # Layout: ciphertext | mac (12B) | etk (256B)
            etk = msg_body[-256:]
            mac = msg_body[-(256 + 12):-256]
            ciphertext = msg_body[:-(256 + 12)]
        except Exception as e:
            raise SiFT_LOGIN_Error('Invalid login request format --> ' + str(e))

        # Step 3: Decrypt temp_key using RSA
        try:
            with open("server_private_key.pem", "rb") as f:
                rsa_privkey = RSA.import_key(f.read())
            cipher_rsa = PKCS1_OAEP.new(rsa_privkey)
            temp_key = cipher_rsa.decrypt(etk)
        except Exception as e:
            raise SiFT_LOGIN_Error('Unable to decrypt temp key with RSA --> ' + str(e))

        # Step 4: Decrypt and verify ciphertext using AES-GCM
        try:
            cipher = AES.new(temp_key, AES.MODE_GCM, nonce=nonce)
            cipher.update(msg_hdr)
            decrypted = cipher.decrypt_and_verify(ciphertext, mac)
        except Exception as e:
            raise SiFT_LOGIN_Error('AES-GCM decryption or verification failed --> ' + str(e))

        # Step 5: Parse and validate login credentials
        login_req_struct = self.parse_login_req(decrypted)
        username = login_req_struct['username']
        password = login_req_struct['password']
        client_random = login_req_struct['client_random']

        if username not in self.server_users or not self.check_password(password, self.server_users[username]):
            raise SiFT_LOGIN_Error("Invalid credentials")

        # Step 6: Derive final transfer key
        server_random = get_random_bytes(16)
        login_res_struct = {
            'request_hash': SHA256.new(decrypted).digest(),
            'server_random': server_random
        }

        response = self.build_login_res(login_res_struct)
        final_key = HKDF(temp_key, 32, b'', client_random + server_random, SHA256)
        self.mtp.set_session_key(final_key)

        # Step 7: Send login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, response)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to send login response --> " + e.err_msg)

        if self.DEBUG:
            print("User", username, "logged in successfully.")
        return username
