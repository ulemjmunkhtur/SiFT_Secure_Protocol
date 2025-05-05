Instructions and advise for the project assignment
--------------------------------------------------

The zip file on Moodle contains the specification and implementation of version 0.5 of the SiFT protocols and a client and a server implementations that use the protocols. Note that this version of SiFT does not contain any cryptographic protection of messages, but the provided code fully implements the non-security related features (i.e., sending commands to the server for file manipulation and the download and upload of files in smaller pieces). 

The zip file contains the following folders:
- _specification: this contains the specification of the SiFT v0.5 protocols in markdown format
- server: this contains the files and folders needed to run the server:
	server.py is the server program;
	folder siftprotocols contains the implementations of the SiFT protocols;
	users.txt is a file that stores the user credentials;
 	folder 'users' is used to store the users' folders and files on the server (e.g., this is where files are saved when uploaded to the server).
- client: this contains the files and folders needed to run the client:
	client.py is the client program;
	folder siftprotocols contains the implementations of the SiFT protocols (this is just a copy of the folder with the same name at the server);
	some test files to be uploaded to the server.

I recommend to play with this implementation first, to get an idea of what this program is about. To do so,

- unzip the zip file
- open a terminal window and change your working directory to the server folder
- start the server (python3 server.py) (if you want to stop the server later, press Ctrl-C)
- open another terminal window and change your working directory to the client folder
- start the client (python3 client.py); the client will automatiocally connect to the running server.

First you need to log in. There are 3 test users already registered with the following name / password:
- alice / aaa
- bob / bbb
- charlie / ccc

Once you logged in, type help to get some help about the available commands. Then play with the application and observe what happens. If you upload a test file to the server as user alice, it should appear in the server/users/alice folder. There are log messages printed on the terminal console to see how the protocols process and transmit the data. You can also observe that the commands defined in the specification are used by the Command protocol, but they are called differently in the client shell (e.g., you type ls in the shell to list the content of a folder, but this appears as an lst command in the protocol).

Once you understood the functionality of the provided implementation, you can inspect the code. You can observe that the SiFT protocols (mtp, login, cmd, upl, dnl) are implemented in different classes, and these are then instantiated at the appropriate places in the program. Login, cmd, upl, and dnl all use mtp as the underlying message transfer protocol. You can also try to relate the details of the provided specification (in the markdown file) to details of the implementation.

The goal of the project assignment is to implement the SiFT v1.0 specification. One option is to get inspiration from the v0.5 implementation, and then implement v1.0 from scratch. Another option is to start from the v0.5 implementation and to extend it with the security features specified in v1.0. These include extending the login protocol with session key establishment (key exchange and key derivation) and extending the message transfer protocol with cryptographic functions and replay protection. In both cases, you should first read carefully and understand the specification of SiFT v1.0. Then, you should either implement the entire protocol or add the requiered new features to the existing v0.5 implementation. IMPORTANT: in the latter case, you only need to modify login.py, mtp.py, server.py and client.py!

You will need to generate an RSA key-pair for the server. For this, you can write a standalone utility program based on what you did in the corresponding exercise session. You should export and save the public key and the key-pair in different files (e.g., in PEM format), and put the key-pair file in the server folder and the public key file in the client folder. So your server and client programs can read these keys from those files and pass them to the login protocol that will use them for the session key establishment. Essentially, this is the only new thing you have to implement in server.py and client.py, and the bulk of the work will be in mtp.py and login.py.

If you have questions, please, do not hesitate to ask them!
