import magic

from hashlib import sha256
from base64 import b64encode, b64decode

def hash_data(data, algo=sha256):
    hasher = algo()
    hasher.update(data)
    return hasher.hexdigest()

def encode_data(data):
    return b64encode(data).decode('utf-8')

def decode_data(data):
    return b64decode(data.encode('utf-8'))

def in_string(tokens, string):
    return any(token in str(string).lower() for token in tokens)  

def get_filetype(data):

    #@TODO change to YARA with magic fallback. Yara results should be equal to magic's
    return (
        magic.from_buffer(data, mime=True),
        magic.from_buffer(data),
    )
