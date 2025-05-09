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

    def handle_login_client(self, username, password):
        timestamp = str(time.time_ns())
        client_random = get_random_bytes(16)
        temp_key = get_random_bytes(32)

        # Create the login request message (plaintext payload)
        msg_payload = self.build_login_req(timestamp, username, password, client_random)

        # Load server's RSA public key and encrypt the temporary AES key (tk)
        with open("server_public_key.pem", "rb") as f:
            rsa_pubkey = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)
        etk = cipher_rsa.encrypt(temp_key)  # This should be exactly 256 bytes

        # Generate nonce from sqn and rnd
        sqn = (1).to_bytes(2, 'big')
        rnd = get_random_bytes(6)
        nonce = sqn + rnd  # 8-byte nonce: 2-byte sequence + 6-byte random

        # Encrypt payload with AES-GCM using temp_key
        cipher = AES.new(temp_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(msg_payload)

        # Build header manually
        msg_type = self.mtp.type_login_req
        msg_hdr_ver = self.mtp.msg_hdr_ver
        total_len = self.mtp.size_msg_hdr + len(ciphertext) + len(tag) + len(etk)
        msg_hdr_len = total_len.to_bytes(self.mtp.size_msg_hdr_len, byteorder='big')
        rsv = b'\x00\x00'
        msg_hdr = msg_hdr_ver + msg_type + msg_hdr_len + sqn + rnd + rsv

        # Build the full message: header + ciphertext + tag + etk
        whole_msg = msg_hdr + ciphertext + tag + etk

        # Send the message over MTP
        try:
            self.mtp.send_bytes(whole_msg)  # Raw send, not send_msg(), since it's a login_req
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # Compute hash of original plaintext payload for validation
        request_hash = SHA256.new(msg_payload).digest()

        # Receive the login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload.decode('utf-8'))
            print('------------------------------------------')

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # Parse and validate login response
        login_res_struct = self.parse_login_res(msg_payload)
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # Derive and store final transfer key
        final_key = HKDF(temp_key, 32, b'', client_random + login_res_struct['server_random'], SHA256)
        self.mtp.set_session_key(final_key)

        if self.DEBUG:
            print(f"User {username} logged in and session key established.")
