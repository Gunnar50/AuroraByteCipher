import random
import string
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from itertools import islice, cycle


class SubsCipher:
    def __init__(self):
        self.alphabet = string.printable

    def create_shift_list(self, private_key):
        # make the shift key list from the key passed in
        shift_keys_long = bytes_to_long(private_key)
        shift_keys = []

        # iterate through pairs of digits
        for i in range(0, len(str(shift_keys_long)), 2):
            pair = str(shift_keys_long)[i:i + 2]
            shift_keys.append(int(pair))
        return shift_keys

    def substitution_encryption(self, plaintext: str, private_key: bytes) -> str:
        shift_keys = self.create_shift_list(private_key)

        ciphertext = ""
        substitution_map = {}
        randomized_alphabet = list(self.alphabet)
        random.shuffle(randomized_alphabet)

        # create the substitution dictionary
        for i, char in enumerate(list(self.alphabet)):
            substitution_map[char] = randomized_alphabet[i]

        for char, shift in zip(plaintext, islice(cycle(shift_keys), len(plaintext))):
            if char in substitution_map:
                # shift the letters using the shift key list
                new_char = self.alphabet[(self.alphabet.index(char) + shift) % len(self.alphabet)]
                ciphertext += substitution_map[new_char]
            else:
                ciphertext += char

        # generate a random delimiter that is not in the ciphertext to be used by the user
        # 4 letter
        while True:
            delimiter = secrets.token_urlsafe(16)[:4]
            if delimiter not in ciphertext:
                break

        combined_text = f"{delimiter}{ciphertext}{delimiter}{substitution_map}"

        return combined_text

    def substitution_decryption(self, combined_text, private_key: bytes) -> str:
        delimiter = combined_text[:4]
        ciphertext, substitution_map_str = combined_text[4:].split(delimiter)
        substitution_map = eval(substitution_map_str)

        shift_keys = self.create_shift_list(private_key)

        plaintext = ""

        reverse_substitution_map = {v: k for k, v in substitution_map.items()}

        for char, shift in zip(ciphertext, islice(cycle(shift_keys), len(ciphertext))):
            if char in reverse_substitution_map:
                new_char = self.alphabet[
                    (self.alphabet.index(reverse_substitution_map[char]) - shift) % len(self.alphabet)]
                plaintext += new_char
            else:
                plaintext += char

        return plaintext


def encrypt(plaintext, password):
    """
    Encryption algorithm.
    it hash the password into a private key which is then separated into KEY and IV variables.
    The plaintext is first inserted into the custom substitution cipher using the private key.
    which is then inserted into AES encryption using the KEY and IV
    then transformed into long integer to be passed again through the substitution cipher
    and encoded with hexadecimal for a final ciphertext.

    :param plaintext: The plaintext to be encrypted
    :param password: A password which is auto generated.
    :return: The encrypted cipher
    """
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    # separate the private key into KEY and IV
    KEY = private_key[2:18]
    IV = private_key[-17:-1]

    subs = SubsCipher()
    aes = AES.new(KEY, AES.MODE_CBC, IV)

    subs_enc = subs.substitution_encryption(plaintext, private_key)  # encrypt first using the subs cipher
    aes_enc = aes.encrypt(pad(subs_enc.encode(), 16))  # pad and pass through AES
    long = bytes_to_long(aes_enc)  # transform into a long interger
    subs_long_enc = subs.substitution_encryption(str(long), private_key)  # pass through the subs cipher again
    byt = subs_long_enc.encode()  # encode into bytes
    bt_long = bytes_to_long(byt)  # take the long form the bytes
    cipher = hex(bt_long)[2::]  # encode with HEX

    return cipher


def decrypt(ciphertext, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    # separate the private key into KEY and IV
    KEY = private_key[2:18]
    IV = private_key[-17:-1]

    subs = SubsCipher()
    aes = AES.new(KEY, AES.MODE_CBC, IV)

    from_hex = int(ciphertext, 16)  # from hex (16 bytes) to long interger
    byt = long_to_bytes(from_hex)  # from long to bytes
    from_bytes = byt.decode()  # decode the bytes to string
    subs_long_dec = subs.substitution_decryption(from_bytes, private_key)  # decrypt the subs into a long int
    long_byte = long_to_bytes(subs_long_dec)  # long to byte
    aes_dec = unpad(aes.decrypt(long_byte), 16)  # decrypt using AES
    plaintext = subs.substitution_decryption(aes_dec.decode(), private_key)  # decrypt the subs again into plaintext

    return plaintext


# plaintext = "test"
# private_key = secrets.token_urlsafe(32)
# encrypted = encrypt(plaintext, private_key)
# decrypted = decrypt(encrypted, private_key)



