import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto import Random

# Función para cifrar el texto en hexadecimal
def encrypt_to_hex(text):
    hex_encrypted_text = ''.join([format(ord(char), '02X') for char in text])
    return hex_encrypted_text

# Función para descifrar el texto en hexadecimal
def decrypt_hex(hex_text):
    text = ''.join([chr(int(hex_text[i:i+2], 16)) for i in range(0, len(hex_text), 2)])
    return text

# Función para generar un par de claves RSA
def generate_key_pair():
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    return key

# Función para cifrar con RSA
def encrypt_rsa(plaintext, public_key):
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext)

# Función para descifrar con RSA
def decrypt_rsa(ciphertext, private_key):
    ciphertext = base64.b64decode(ciphertext)
    cipher = PKCS1_v1_5.new(private_key)
    decrypted_text = cipher.decrypt(ciphertext, None)
    return decrypted_text.decode()

# Generar un par de claves RSA
key_pair = generate_key_pair()

public_key = key_pair.publickey()
private_key = key_pair

# Texto a cifrar
plaintext = input("Introduce el texto a cifrar: ")

# Cifrado hexadecimal
hex_encrypted_text = encrypt_to_hex(plaintext)

# Cifrado RSA de la representación hexadecimal
rsa_encrypted_hex = encrypt_rsa(hex_encrypted_text, public_key)

print("Texto cifrado en hexadecimal: " + hex_encrypted_text)
print("Texto cifrado con RSA: " + rsa_encrypted_hex.decode())

# Descifrar RSA
decrypted_hex = decrypt_rsa(rsa_encrypted_hex, private_key)
decrypted_text = decrypt_hex(decrypted_hex)

print("Texto descifrado: " + decrypted_text)

