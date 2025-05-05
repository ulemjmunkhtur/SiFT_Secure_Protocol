#python3

from Crypto.Hash import SHA256
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_DNL_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_DNL:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.size_fragment = 1024
        self.coding = 'utf-8'
        self.ready = 'ready'
        self.cancel = 'cancel'
        # --------- STATE ------------
        self.mtp = mtp


    # cancels file download by the client (to be used by the client)
    def cancel_download_client(self):
        
        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(self.cancel)) + '):')
            print(self.cancel[:max(512, len(self.cancel))])
            print('------------------------------------------')
        # DEBUG 

        # trying to send a download request to cancel file download
        try:
            self.mtp.send_msg(self.mtp.type_dnload_req, self.cancel.encode(self.coding))
        except SiFT_MTP_Error as e:
            raise SiFT_DNL_Error('Unable to send download request (cancel) --> ' + e.err_msg)


    # handles file download at the client (to be used by the client)
    def handle_download_client(self, filepath):
        
        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(self.ready)) + '):')
            print(self.ready[:max(512, len(self.ready))])
            print('------------------------------------------')
        # DEBUG 

        # trying to send a download request to start file download
        try:
            self.mtp.send_msg(self.mtp.type_dnload_req, self.ready.encode(self.coding))
        except SiFT_MTP_Error as e:
            raise SiFT_DNL_Error('Unable to send download request (ready) --> ' + e.err_msg)

        # creating hash function for file hash computation
        hash_fn = SHA256.new()

        file_hash = None
        with open(filepath, 'wb') as f:

            file_size = 0
            download_complete = False
            while not download_complete:

                # trying to receive a download response
                try:
                    msg_type, msg_payload = self.mtp.receive_msg()
                except SiFT_MTP_Error as e:
                    raise SiFT_DNL_Error('Unable to receive download response --> ' + e.err_msg)

                # DEBUG 
                if self.DEBUG:
                    print('Incoming payload (' + str(len(msg_payload)) + '):')
                    print(msg_payload[:max(512, len(msg_payload))])
                    print('------------------------------------------')
                # DEBUG 

                if msg_type not in (self.mtp.type_dnload_res_0, self.mtp.type_dnload_res_1) :
                    raise SiFT_DNL_Error('Download response expected, but received something else')

                if msg_type == self.mtp.type_dnload_res_1: download_complete = True

                file_size += len(msg_payload)
                hash_fn.update(msg_payload)
                f.write(msg_payload)

            file_hash = hash_fn.digest()

        return file_hash


    # handles a file download on the server (to be used by the server)
    def handle_download_server(self, filepath):

        # trying to receive a download request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_DNL_Error('Unable to receive download request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_dnload_req:
            raise SiFT_DNL_Error('Download request expected, but received something else')

        if msg_payload.decode(self.coding) == self.ready:

            with open(filepath, 'rb') as f:

                byte_count = self.size_fragment
                while byte_count == self.size_fragment:

                    file_fragment = f.read(self.size_fragment)
                    byte_count = len(file_fragment)

                    if byte_count == self.size_fragment: msg_type = self.mtp.type_dnload_res_0
                    else: msg_type = self.mtp.type_dnload_res_1

                    # DEBUG 
                    if self.DEBUG:
                        print('Outgoing payload (' + str(len(file_fragment)) + '):')
                        print(file_fragment[:max(512, len(file_fragment))])
                        print('------------------------------------------')
                    # DEBUG 

                    # trying to download a fragment to the client
                    try:
                        self.mtp.send_msg(msg_type, file_fragment)
                    except SiFT_MTP_Error as e:
                        raise SiFT_DNL_Error('Unable to download file fragment --> ' + e.err_msg)

