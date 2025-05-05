#python3


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

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        etk = msg_payload[-256:]
        nonce = msg_payload[:8]
        tag = msg_payload[8:20]
        ciphertext = msg_payload[20:-256]

        with open("server_private_key.pem", "rb") as f:
            rsa_privkey = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(rsa_privkey)
        temp_key = cipher_rsa.decrypt(etk)

        cipher = AES.new(temp_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        login_req_struct = self.parse_login_req(decrypted)

        username = login_req_struct['username']
        password = login_req_struct['password']
        client_random = login_req_struct['client_random']

        if username not in self.server_users or not self.check_password(password, self.server_users[username]):
            raise SiFT_LOGIN_Error("Invalid credentials")

        server_random = get_random_bytes(16)
        login_res_struct = {
            'request_hash': SHA256.new(decrypted).digest(),
            'server_random': server_random
        }

        response = self.build_login_res(login_res_struct)
        final_key = HKDF(temp_key, 32, b'', client_random + server_random, SHA256)
        self.mtp.set_session_key(final_key)

        try:
            self.mtp.send_msg(self.mtp.type_login_res, response)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error("Unable to send login response --> " + e.err_msg)

        if self.DEBUG:
            print("User", username, "logged in successfully.")
        return username



    # handles login process (to be used by the client)
def handle_login_client(self, username, password):
        
        # generates the timestamp, client_random, and temporary key
        timestamp = str(time.time_ns())
        client_random = get_random_bytes(16)
        # this is the session key
        temp_key = get_random_bytes(32)
        

        # creates the payload  
        # function returns in bytes 
        login_payload_bytes = self.build_login_req(timestamp, username, password, client_random)


        # LOAD SERVER'S RSA PUBLIC KEY
        with open("server_public_key.pem", "rb") as f:
            rsa_pubkey = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)
        # THEN ENCRYPTS SESSION KEY
        etk = cipher_rsa.encrypt(temp_key)
 
        # GENERATES THE NONCE
        sqn = (1).to_bytes(2, 'big')
        rnd = get_random_bytes(6)
        nonce = sqn + rnd

        # ENCRYPTS PAYLOAD IN AES-GCM MODE
        cipher = AES.new(temp_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(login_payload_bytes)


        # sets it as the temporary key
        self.mtp.set_temp_key(temp_key, etk, sqn, rnd, ciphertext, tag)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')
        
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')
        
        final_key = HKDF(temp_key, 32, b'', client_random + login_res_struct['server_random'], SHA256)
        self.mtp.set_session_key(final_key)
