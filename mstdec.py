# Brave Fronter MST decoder
# Craeted by Arves100
# License: MIT
# Requirements: pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import base64
import sys
import os

"""
    AES keys required to decrypt the MST
"""
MST_KEYS = {
    "F_UNIT_MST" : b"7nL1WTUb",
    "F_SKILL_MST": b"JA03wvHG"
}

"""
    MST names in brave frontier crypt format
"""
MST_NAMES = {
    "2r9cNSdt" : "F_UNIT_MST",
    "wkCyV73D" : "F_SKILL_MST"
}

'''
	Decodes a MST json
	:param str: String to decode
	:param rq: Request id
	:return: Decrypted string
'''
def mst_decode(text: str, rq: str) -> str:
	akey = MST_KEYS[rq]
	for i in range(len(akey), 16):
		akey += b"\x00"

	cipher = AES.new(akey, AES.MODE_ECB)
	return cipher.decrypt(base64.b64decode(text))

'''
	Encodes a MST json
	:param str: String to encode
	:param rq: Request id
	:return: Encrypted string
'''
def mst_encode(text: str, rq: str) -> str:
	akey = MST_KEYS[rq]
	for i in range(len(akey), 16):
		akey += b"\x00"

	cipher = AES.new(akey, AES.MODE_ECB)
	return base64.b64encode(cipher.encrypt(text))

def get_mst(s: str) -> str:
    return MST_NAMES[s]

def get_key(s: str) -> str:
    return MST_KEYS[s]

def decr_mst(s: str):
    basepath = os.path.basename(s)
    startp = basepath.find("_")
    endp = basepath.find("_", startp + 1)
    yes_extra = True
    if endp == -1:
        yes_extra = False
        endp = basepath.find(".", startp + 1)
    
    name = basepath[startp+1:endp]
    decr_name = get_mst(name)

    x = None
    with open(s, "rb") as fp:
        x = fp.read()

    decoded = mst_decode(x, decr_name)
    ver = basepath[3:startp]
    extra = ""
    if yes_extra:
        endp2 = basepath.find(".", endp + 1)
        extra = basepath[endp+1:endp2]

    fullname = "_".join((decr_name, ver))
    if yes_extra:
        fullname += "_"
        fullname += extra
    fullname += ".json"

    with open(fullname, "wb") as fp:
        fp.write(decoded)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python mstdec.py [mst file.dat]")
    else:
        decr_mst(sys.argv[1])
