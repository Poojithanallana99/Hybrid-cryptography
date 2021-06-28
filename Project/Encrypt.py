from Crypto.Cipher import Blowfish, PKCS1_OAEP, AES
from Crypto.PublicKey import *
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify , unhexlify
import hashlib , json, string, random
from stegano import lsb

def key_generator(size, case="default", punctuations="required"):
    if case=="default" and punctuations=="required":
        return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation, k = size))
    elif case=="upper-case-only" and punctuations=="required":
        return ''.join(random.choices(string.ascii_uppercase + string.digits + string.punctuation, k = size))
    elif case=="lower-case-only"  and punctuations=="required":
        return ''.join(random.choices(string.ascii_lowercase + string.digits + string.punctuation, k = size))
    elif case=="default" and punctuations=="none":
        return ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k = size))
    elif case=="lower-case-only"  and punctuations=="none":
        return ''.join(random.choices(string.ascii_lowercase + string.digits , k = size))
    elif case=="upper-case-only" and punctuations=="none":
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k = size))


def hybrid_encryption(plaintext):
    # Plaintext Input
    global ciphertext
    global decrypted_plaintext
    plaintext = plaintext.encode()
    
    # Dictionary of Keys
    keys_iv = {}

    # Blowfish Layer 1

    blowfish_key =  key_generator(size=16).encode()
    print("Blowfish key is : ",blowfish_key )
    #print(blowfish_key)
    blowfish_cipher = Blowfish.new(blowfish_key, Blowfish.MODE_CBC)
    print("Blowfish cipher  is : ",blowfish_cipher )
    blowfish_ciphertext = blowfish_cipher.encrypt(pad(plaintext, Blowfish.block_size ))

    keys_iv['blowfish_iv'] = hexlify(blowfish_cipher.iv).decode()
    keys_iv['blowfish_key'] = hexlify(blowfish_key).decode()
    
    # RSA Layer 2

    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key
    rsa_public_key = rsa_key.publickey()

    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    rsa_plaintext = blowfish_ciphertext
    print("RSA public key is : ",rsa_public_key)

    rsa_ciphertext = bytearray()
    for i in range(0, len(rsa_plaintext), 190):
        rsa_ciphertext.extend(cipher_rsa.encrypt(rsa_plaintext[i:i+190]))

    keys_iv['rsa_n'] = rsa_private_key.n
    keys_iv['rsa_e'] = rsa_private_key.e
    keys_iv['rsa_d'] = rsa_private_key.d

    # AES Layer 3
    aes_key =  key_generator(size=16).encode()
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    aes_plaintext = rsa_ciphertext
    
    print("AES KEY IS : ", aes_key)
    
    aes_ciphertext = aes_cipher.encrypt(pad(aes_plaintext, AES.block_size))

    ciphertext = aes_ciphertext


    keys_iv['aes_iv'] = hexlify(aes_cipher.iv).decode()
    keys_iv['aes_key'] = hexlify(aes_key).decode()


    # Encryption of Key and IV String
    print(ciphertext)
    password = "hyenc2021"


    hash = hashlib.sha1()
    hash.update(password.encode())
    password_encryption_cipher = AES.new( hash.hexdigest()[:16].encode() , AES.MODE_CBC, iv= '16bitAESInitVect'.encode())

    encrypted_keys_and_iv = hexlify(password_encryption_cipher.encrypt(pad(json.dumps(keys_iv).encode(), AES.block_size)))

   

    #LSB Steganography


    lsb_stegano_image = lsb.hide("E:\major\Major Project\cover_image.png", encrypted_keys_and_iv.decode())
    lsb_stegano_image.save("E:\major\Major Project\stego_image.png") 



def hybrid_decryption(ciphertext):

    unhide_encrypted_keys_and_iv = lsb.reveal("E:\major\Major Project\stego_image.png").encode()
    password = "hyenc2021"
    hash = hashlib.sha1()
    hash.update(password.encode())
    password_decryption_cipher = AES.new( hash.hexdigest()[:16].encode() , AES.MODE_CBC, iv= '16bitAESInitVect'.encode())

    decrypted_keys_iv = json.loads(unpad(password_decryption_cipher.decrypt(unhexlify(unhide_encrypted_keys_and_iv)), AES.block_size))

    #Initializations
    decryption_key_aes = unhexlify(decrypted_keys_iv['aes_key'])
    decryption_iv_aes = unhexlify(decrypted_keys_iv['aes_iv'])
    decryption_key_rsa = RSA.construct(rsa_components = (decrypted_keys_iv['rsa_n'] , decrypted_keys_iv['rsa_e'] , decrypted_keys_iv['rsa_d']))
    decryption_iv_blowfish = unhexlify(decrypted_keys_iv['blowfish_iv'])
    decryption_key_blowfish = unhexlify(decrypted_keys_iv['blowfish_key'])


    aes_cipher_decryption = AES.new(decryption_key_aes, AES.MODE_CBC, iv=decryption_iv_aes)
    rsa_cipher_decryption = PKCS1_OAEP.new(decryption_key_rsa)
    blowfish_cipher_decryption = Blowfish.new(decryption_key_blowfish, Blowfish.MODE_CBC, iv=decryption_iv_blowfish)

    # AES DECRYPTION
    ciphertext_rsa = unpad(aes_cipher_decryption.decrypt(ciphertext), AES.block_size)
    
    
    
    # RSA DECRYPTION
    ciphertext_blowfish = bytearray()
    for i in range(0, len(ciphertext_rsa),256):
        ciphertext_rsa_segment = ciphertext_rsa[i:i+256]
        ciphertext_blowfish.extend(rsa_cipher_decryption.decrypt(ciphertext_rsa_segment))

    # BLOWFISH DECRYPTION
    decrypted_plaintext = unpad(blowfish_cipher_decryption.decrypt(ciphertext_blowfish), Blowfish.block_size)
    print(decrypted_plaintext)

with open("E:\major\Major Project\plaintext.txt", 'r') as text_file:
    plaintext_list = text_file.read().split("\n#######################################################\n")


for plaintext_pt in plaintext_list:
    
    hybrid_encryption(plaintext_pt)


hybrid_decryption(ciphertext)





