#python3

import sys, os, socket, cmd, getpass
from Crypto.Hash import SHA256
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error
from siftprotocols.siftupl import SiFT_UPL, SiFT_UPL_Error
from siftprotocols.siftdnl import SiFT_DNL, SiFT_DNL_Error

# ----------- CONFIG -------------
server_ip = '127.0.0.1' # localhost
# server_ip = '192.168.x.y'
server_port = 5150
# --------------------------------

class SiFTShell(cmd.Cmd):
    intro = 'Client shell for the SiFT protocol. Type help or ? to list commands.\n'
    prompt = '(sift) '
    file = None

    # ----- commands -----
    def do_pwd(self, arg):
        'Print current working directory on the server: pwd'

        if arg: print('Command arguments are ignored...')

        cmd_req_struct = {}
        cmd_req_struct['command'] = cmdp.cmd_pwd
        try:
            cmd_res_struct = cmdp.send_command(cmd_req_struct)
        except SiFT_CMD_Error as e:
            print('SiFT_CMD_Error: ' + e.err_msg)
        else:
            if cmd_res_struct['result_1'] == cmdp.res_failure:
                print('Remote_Error: ' + cmd_res_struct['result_2'])
            else:
                print(cmd_res_struct['result_2'])

    def do_ls(self, arg):
        'List content of the current working directory on the server: ls'

        if arg: print('Command arguments are ignored...')

        cmd_req_struct = {}
        cmd_req_struct['command'] = cmdp.cmd_lst
        try:
            cmd_res_struct = cmdp.send_command(cmd_req_struct)
        except SiFT_CMD_Error as e:
            print('SiFT_CMD_Error: ' + e.err_msg)
        else:
            if cmd_res_struct['result_1'] == cmdp.res_failure:
                print('Remote_Error: ' + cmd_res_struct['result_2'])
            else:
                if cmd_res_struct['result_2']: print(cmd_res_struct['result_2'])
                else: print('[empty]')

    def do_cd(self, arg):
        'Change the current working directory on the server: cd <dirname>'

        cmd_req_struct = {}
        cmd_req_struct['command'] = cmdp.cmd_chd
        cmd_req_struct['param_1'] = arg.split(' ')[0]
        try:
            cmd_res_struct = cmdp.send_command(cmd_req_struct)
        except SiFT_CMD_Error as e:
            print('SiFT_CMD_Error: ' + e.err_msg)
        else:
            if cmd_res_struct['result_1'] == cmdp.res_failure:
                print('Remote_Error: ' + cmd_res_struct['result_2'])

    def do_mkd(self, arg):
        'Create a new directory in the current working directory on the server: mkd <dirname>'

        cmd_req_struct = {}
        cmd_req_struct['command'] = cmdp.cmd_mkd
        cmd_req_struct['param_1'] = arg.split(' ')[0]
        try:
            cmd_res_struct = cmdp.send_command(cmd_req_struct)
        except SiFT_CMD_Error as e:
            print('SiFT_CMD_Error: ' + e.err_msg)
        else:
            if cmd_res_struct['result_1'] == cmdp.res_failure:
                print('Remote_Error: ' + cmd_res_struct['result_2'])

    def do_del(self, arg):
        'Delete the given file or (empty) directory on the server: del <filename> or del <dirname>'

        cmd_req_struct = {}
        cmd_req_struct['command'] = cmdp.cmd_del
        cmd_req_struct['param_1'] = arg.split(' ')[0]
        try:
            cmd_res_struct = cmdp.send_command(cmd_req_struct)
        except SiFT_CMD_Error as e:
            print('SiFT_CMD_Error: ' + e.err_msg)
        else:
            if cmd_res_struct['result_1'] == cmdp.res_failure:
                print('Remote_Error: ' + cmd_res_struct['result_2'])

    def do_upl(self, arg):
        'Upload the given file to the server: upl <filename>'

        filepath = arg.split(' ')[0]
        if (not os.path.exists(filepath)) or (not os.path.isfile(filepath)):
            print('Local_Error: ' + filepath + ' does not exist or it is not a file')
            return
        else:
            with open(filepath, 'rb') as f:
                hash_fn = SHA256.new()
                file_size = 0
                byte_count = 1024
                while byte_count == 1024:
                    chunk = f.read(1024)
                    byte_count = len(chunk)
                    file_size += byte_count
                    hash_fn.update(chunk)
                file_hash = hash_fn.digest()

            cmd_req_struct = {}
            cmd_req_struct['command'] = cmdp.cmd_upl
            cmd_req_struct['param_1'] = os.path.split(filepath)[1]
            cmd_req_struct['param_2'] = file_size
            cmd_req_struct['param_3'] = file_hash

            try:
                cmd_res_struct = cmdp.send_command(cmd_req_struct)
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
            else:
                if cmd_res_struct['result_1'] == cmdp.res_reject:
                    print('Remote_Error: ' + cmd_res_struct['result_2'])
                else:
                    print('Strarting upload...')
                    uplp = SiFT_UPL(mtp)
                    try:
                        uplp.handle_upload_client(cmd_req_struct['param_1'])
                    except SiFT_UPL_Error as e:
                        print('Remote_Error: ' + e.err_msg)
                    else: 
                        print('Completed.')

    def do_dnl(self, arg):
        'Download the given file from the server: dnl <filename>'

        cmd_req_struct = {}
        cmd_req_struct['command'] = cmdp.cmd_dnl
        cmd_req_struct['param_1'] = arg.split(' ')[0]
        try:
            cmd_res_struct = cmdp.send_command(cmd_req_struct)
        except SiFT_CMD_Error as e:
            print('SiFT_CMD_Error: ' + e.err_msg)
        else:
            if cmd_res_struct['result_1'] == cmdp.res_reject:
                print('Remote_Error: ' + cmd_res_struct['result_2'])
            else:
                print('File size: ' + str(cmd_res_struct['result_2']))
                print('File hash: ' + cmd_res_struct['result_3'].hex())
                yn = ''
                while yn not in ('y', 'yes', 'Y', 'YES', 'Yes', 'n', 'no', 'N', 'NO', 'No'):
                    yn = input('Do you want to proceed? (y/n) ')
                if yn in ('y', 'yes', 'Y', 'YES', 'Yes'):
                    print('Starting download...')
                    dnlp = SiFT_DNL(mtp)
                    try:
                        file_hash = dnlp.handle_download_client(cmd_req_struct['param_1'])
                    except SiFT_DNL_Error as e:
                        print('Remote_Error: ' + e.err_msg)
                    else:
                        # we could also check here that file_hash is equal to cmd_res_struct['result_3']
                        print('Completed.')

                else:
                    print('Canceling download...')
                    dnlp = SiFT_DNL(mtp)
                    try:
                        dnlp.cancel_download_client()
                    except SiFT_DNL_Error as e:
                        print('Remote_Error: ' + e.err_msg)
                    else:
                        print('Completed.')

    def do_bye(self, arg):
        'Exit from the client shell: bye'
        print('Closing connection with server...')
        sckt.close()
        return True


# --------------------------------------
if __name__ == '__main__':

    try:
        sckt = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sckt.connect((server_ip, server_port))
    except:
        print('Network_Error: Cannot open connection to the server')
        sys.exit(1)
    else:
        print('Connection to server established on ' + server_ip + ':' + str(server_port))

    mtp = SiFT_MTP(sckt)
    loginp = SiFT_LOGIN(mtp)

    print()
    username = input('   Username: ')
    password = getpass.getpass('   Password: ')
    print()

    try:
        loginp.handle_login_client(username, password)
    except SiFT_LOGIN_Error as e:
        print('SiFT_LOGIN_Error: ' + e.err_msg)
        sys.exit(1)

    cmdp = SiFT_CMD(mtp)

    SiFTShell().cmdloop()
