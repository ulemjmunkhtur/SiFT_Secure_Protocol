#python3

from Crypto.Hash import SHA256
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_UPL_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_UPL:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.size_fragment = 1024
        # --------- STATE ------------
        self.mtp = mtp


    # builds an upload response from a dictionary
    def build_upload_res(self, upl_res_struct):

        upl_res_str = upl_res_struct['file_hash'].hex()
        upl_res_str += self.delimiter + str(upl_res_struct['file_size'])
        return upl_res_str.encode(self.coding)


    # parses an upload response into a dictionary
    def parse_upload_res(self, upl_res):

        upl_res_fields = upl_res.decode(self.coding).split(self.delimiter)
        upl_res_struct = {}
        upl_res_struct['file_hash'] = bytes.fromhex(upl_res_fields[0])
        upl_res_struct['file_size'] = int(upl_res_fields[1])
        return upl_res_struct


    # uploads file at filepath in fragments to the server (to be used by the client)
    def handle_upload_client(self, filepath):

        with open(filepath, 'rb') as f:

            # creating hash function for file hash computation
            hash_fn = SHA256.new()

            # upload file in fragments
            byte_count = self.size_fragment
            while byte_count == self.size_fragment:

                file_fragment = f.read(self.size_fragment)
                byte_count = len(file_fragment)
                hash_fn.update(file_fragment)

                if byte_count == self.size_fragment: msg_type = self.mtp.type_upload_req_0
                else: msg_type = self.mtp.type_upload_req_1

                # DEBUG 
                if self.DEBUG:
                    print('Outgoing payload (' + str(len(file_fragment)) + '):')
                    print(file_fragment[:max(512, len(file_fragment))])
                    print('------------------------------------------')
                # DEBUG 

                # trying to upload a fragment
                try:
                    self.mtp.send_msg(msg_type, file_fragment)
                except SiFT_MTP_Error as e:
                    raise SiFT_UPL_Error('Unable to upload file fragment --> ' + e.err_msg)

            file_hash = hash_fn.digest()

        # trying to receive an upload response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_UPL_Error('Unable to receive upload response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_upload_res:
            raise SiFT_UPL_Error('Upload response expected, but received something else')

        # processing upload response
        try:
            upl_res_struct = self.parse_upload_res(msg_payload)
        except:
            raise SiFT_UPL_Error('Parsing command response failed')

        # checking file hash received in the upload response
        if upl_res_struct['file_hash'] != file_hash:
            raise SiFT_UPL_Error('Hash verification of uploaded file failed')


    # handles a file upload on the server (to be used by the server)
    def handle_upload_server(self, filepath):

        with open(filepath, 'wb') as f:

            # creating hash function for file hash computation
            hash_fn = SHA256.new()

            file_size = 0
            upload_complete = False
            while not upload_complete:

                # trying to receive an upload request
                try:
                    msg_type, msg_payload = self.mtp.receive_msg()
                except SiFT_MTP_Error as e:
                    raise SiFT_UPL_Error('Unable to receive upload request --> ' + e.err_msg)

                # DEBUG 
                if self.DEBUG:
                    print('Incoming payload (' + str(len(msg_payload)) + '):')
                    print(msg_payload[:max(512, len(msg_payload))])
                    print('------------------------------------------')
                # DEBUG 

                if msg_type not in (self.mtp.type_upload_req_0, self.mtp.type_upload_req_1) :
                    raise SiFT_UPL_Error('Upload request expected, but received something else')

                if msg_type == self.mtp.type_upload_req_1: upload_complete = True

                file_size += len(msg_payload)
                hash_fn.update(msg_payload)
                f.write(msg_payload)

            file_hash = hash_fn.digest()

        # building an upload response
        upl_res_struct = {}
        upl_res_struct['file_hash'] = file_hash
        upl_res_struct['file_size'] = file_size
        msg_payload = self.build_upload_res(upl_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send upload response
        try:
            self.mtp.send_msg(self.mtp.type_upload_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_UPL_Error('Unable to send upload response --> ' + e.err_msg)



