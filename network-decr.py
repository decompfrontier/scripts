# Brave Frontier Network Decrypt
# Created by Arves100
# License: MIT

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import base64
import sys

REQUESTS_KEYS = {
	"MfZyu1q9" : b"EmcshnQoDr20TZz1",
	"cTZ3W2JG" : b"ScJx6ywWEb0A3njT",
	"D74TYRf1" : b"e2k4s6jc",
	"nJ3A7qFp" : b"bGxX67KB",
	"NiYWKdzs" : b"f6uOewOD",
	"2o4axPIC" : b"EoYuZ2nbImhCU1c0",
}

def pkcs5_pad(s):
	return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

def bfdc(text):
	cipher = AES.new(b"7410958164354871", AES.MODE_CBC, iv=b"Bfw4encrypedPass")
	return cipher.decrypt(base64.b64decode(text))

def bfec(text):
	cipher = AES.new(b"7410958164354871", AES.MODE_CBC, iv=b"Bfw4encrypedPass")
	return base64.b64encode(cipher.encrypt(text))

def bfdc2(text, rq):
	akey = REQUESTS_KEYS[rq]
	for i in range(len(akey), 16):
		akey += b"\x00"

	cipher = AES.new(akey, AES.MODE_ECB)
	return cipher.decrypt(base64.b64decode(text))

def bfec2(text, rq):
	akey = REQUESTS_KEYS[rq]
	for i in range(len(akey), 16):
		akey += b"\x00"

	cipher = AES.new(akey, AES.MODE_ECB)
	return base64.b64encode(cipher.encrypt(text))

if __name__ == "__main__":
	print(bfdc(sys.argv[1]))
