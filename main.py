import rsa

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(1024)
    with open('bilisim/pubKey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))
        
    with open('bilisim/privKey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))

def load_keys():
    with open('keys/pubKey.pem', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open('keys/privKey.pem', 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubKey, privKey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)

def sign_shal(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1') 

def verify_sha1(msg, signature, key):
    try:
       return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False
    
generate_keys()
pubKey, privKey = load_keys()

message = input('Bir mesaj giriniz:')
ciphertext = encrypt(message, pubKey)

signature = sign_shal(message, privKey)

print(f'Ciphertext: {ciphertext}')
print(f'Signature: {signature}')

if verify_sha1(signature, pubKey):
    print('kimlik dogrulandi!')
else:
    print('kimlik dogrulanamadi.')

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

while True:
    try:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        break
    except ValueError:
        pass

def decrypt(nonce, ciphertext):
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('ascii')

plaintext = decrypt(ciphertext)
print(f'Cipher text: {ciphertext}')
print(f'plain text: {plaintext}')