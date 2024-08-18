def encrypt_to_hex(text):
    hex_encrypted_text = ''.join([format(ord(char), '02X') for char in text])
    return hex_encrypted_text

def decrypt_hex(hex_text):
    text = ''.join([chr(int(hex_text[i:i+2], 16)) for i in range(0, len(hex_text), 2)])
    return text

def reorder_alphabet(text, encryption_key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = list(encryption_key)

    # Crea un nuevo alfabeto basado en la clave de cifrado
    new_alphabet = alphabet

    for letter in key:
        new_alphabet = new_alphabet.replace(letter, '')

    new_alphabet = ''.join(key) + new_alphabet

    # Descifra el texto reordenando el alfabeto
    decrypted_text = ''

    for char in text.upper():
        if char.isalpha():
            original_char = char
            index = new_alphabet.index(original_char)
            decrypted_char = alphabet[index]
            if char.islower():
                decrypted_text += decrypted_char.lower()
            else:
                decrypted_text += decrypted_char
        else:
            decrypted_text += char

    return decrypted_text

input_text = input("Introduce el texto a cifrar: ")
encryption_key = "ENCRYPTKEY"  

# Cifrado
hex_encrypted_text = encrypt_to_hex(input_text)
alphabet_reordered_text = reorder_alphabet(input_text, encryption_key)

print("Texto cifrado en hexadecimal:", hex_encrypted_text)
print("Texto cifrado con reordenamiento del alfabeto:", alphabet_reordered_text)

# Descifrado
decrypted_hex_text = decrypt_hex(hex_encrypted_text)
decrypted_text = reorder_alphabet(alphabet_reordered_text, encryption_key)

print("Texto descifrado:", decrypted_hex_text)
