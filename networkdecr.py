# Brave Frontier Network Decrypt
# Created by Arves100
# License: MIT
# Requirements: pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import base64
import sys

''' GME Requests ID and their respective AES keys '''
REQUESTS_KEYS = {
	"MfZyu1q9" : b"EmcshnQoDr20TZz1", # initialize
	"cTZ3W2JG" : b"ScJx6ywWEb0A3njT", # user info
	"D74TYRf1" : b"e2k4s6jc",
	"nJ3A7qFp" : b"bGxX67KB", # badge info
	"NiYWKdzs" : b"f6uOewOD", # home info
	"2o4axPIC" : b"EoYuZ2nbImhCU1c0", # friend get
	"uYF93Mhc" : b"d0k6LGUu", # control center enter
	"ynB7X5P9" : b"7kH9NXwC", # update info light
	"Uo86DcRh" : b"8JbxFvuSaB2CK7Ln", # gacha list
	"m2Ve9PkJ" : b"d7UuQsq8", # deck edit
	"jE6Sp0q4" : b"csiVLDKkxEwBfR70", # mission start
	"4aClzokO" : b"stI81haQ", # daily login request
	"YPBU7MD8" : b"AKjzyZ81", # get achievement info
	"YPBU7MD8" : b"6F9sMzBxEv8jXpau", # present list
}

'''
	Pads a string with PKCS5 padding
	:param s: Stirng to pad
	:return: Padded string
'''
def pkcs5_pad(s: str) -> str:
	return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

'''
	Decodes a SREE object content
	:param str: String to decode
	:return: Decrypted string
'''
def sree_decode(text: str) -> str:
	cipher = AES.new(b"7410958164354871", AES.MODE_CBC, iv=b"Bfw4encrypedPass")
	return cipher.decrypt(base64.b64decode(text))

'''
	Encodes a content for an SREE response
	:param str: String to encode
	:return: Encrypted string
'''
def sree_encode(text: str) -> str:
	cipher = AES.new(b"7410958164354871", AES.MODE_CBC, iv=b"Bfw4encrypedPass")
	return base64.b64encode(cipher.encrypt(text))

'''
	Decodes a game server json
	:param str: String to decode
	:param rq: Request id
	:return: Decrypted string
'''
def gme_decode(text: str, rq: str) -> str:
	akey = REQUESTS_KEYS[rq]
	for i in range(len(akey), 16):
		akey += b"\x00"

	cipher = AES.new(akey, AES.MODE_ECB)
	return cipher.decrypt(base64.b64decode(text))

'''
	Encodes a game server json
	:param str: String to encode
	:param rq: Request id
	:return: Encrypted string
'''
def gme_encode(text: str, rq: str) -> str:
	akey = REQUESTS_KEYS[rq]
	for i in range(len(akey), 16):
		akey += b"\x00"

	cipher = AES.new(akey, AES.MODE_ECB)
	return base64.b64encode(cipher.encrypt(text))
