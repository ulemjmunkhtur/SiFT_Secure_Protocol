from Crypto.PublicKey import RSA

# Load keys
with open("server/server_private_key.pem", "rb") as f:
    privkey = RSA.import_key(f.read())

with open("client/server_public_key.pem", "rb") as f:
    pubkey = RSA.import_key(f.read())

# Extract public part from private key
privkey_pub = privkey.publickey()

# Compare exported key bytes
if privkey_pub.export_key() == pubkey.export_key():
    print("Public and private keys match.")
else:
    print("Public and private keys DO NOT match!")
