import hashlib
import base64
import os
import signal
import sys
import threading
import time
import ssl
import OpenSSL

def AESdecrypt(string,key):
    aeskey = hashlib.md5(key).hexdigest()
    enc = base64.b64decode(string)
    iv = enc[:AES.block_size]
    cipher = AES.new(aeskey, AES.MODE_CBC, iv)
    return cipher.decrypt(enc[AES.block_size:]).decode('utf-8')

def AESencrypt(string , key):
    aeskey = md5(key).hexdigest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aeskey , AES.MODE_CBC , iv)
    return b64encode(iv + cipher.encrypt(string.encode()))

def getkey(dhkey):
    bs =[]
    
    while dhkey!=0:
        bs.append(dhkey & 0xFF)
        dhkey >>=8
    
    sharedSecretBytes = bytes(bytearray(reversed(bs)))
    s = hashlib.sha256()
    s.update(bytes(sharedSecretBytes))
    return s.digest()

me_server_key=99867312680713069655145330934108472996077308403973546274808709336218298828200
cipher="9+ngYAApK2w6x2ENavkrwxEu+B5uSN2p4sFjp+gBoBGTznuXfwkr2yRa6fAV65NTQDR6JElj8Sqy6jmK9dZEuQ=="

new_key=getkey(me_server_key)

print(AESdecrypt(cipher,new_key))

