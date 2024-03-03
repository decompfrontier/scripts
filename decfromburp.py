import networkdecr
import xml.etree.ElementTree as ET
import os
import base64
import sys
import json

q_res = {}
q_req = {}
ROOT = "burp_exports"
NOT_EXISTS = []

def do_burp_dat(b64dec: str, is_response: bool):
    http_end = b64dec.find(b"\r\n\r\n")
    j = b64dec[http_end+4:]

    try:
        y = json.loads(j)
    except json.decoder.JSONDecodeError:
        return # not a json

    try:
        header = y["F4q6i9xe"]
    except TypeError:
        return # not a json

    req_id = header["Hhgi79M1"]

    try:
        body = y["a3vSYuq2"]
        body_content = body["Kn51uR4Y"]
    except KeyError:
        # this is an error, skip it
        return

    tx = "request"
    q = q_req
    if is_response:
        tx = "response"
        q = q_res

    ee = 0
    if req_id in q:
        ee = q[req_id]
        ee += 1

    q[req_id] = ee

    try:
        os.mkdir("{}/{}".format(ROOT, req_id))
    except FileExistsError:
        pass

    try:
        os.mkdir("{}/{}/{}".format(ROOT, req_id, ee))
    except FileExistsError:
        pass

    try:
        dec_body = networkdecr.gme_decode(body_content, req_id)
    except KeyError:
        if not req_id in NOT_EXISTS:
            with open("{}/error.txt".format(ROOT), "a") as fp:
                fp.write(req_id)
                fp.write("\n")
                NOT_EXISTS.append(req_id)

        return
    
    p = "{}/{}/{}/{}.json".format(ROOT, req_id, ee, tx)

    with open(p, "wb") as fp:
        json_end = dec_body.rfind(b"}")
        fp.write(dec_body[:json_end+1])


def do_burp_xml(file: str):
    tree = ET.parse(file)
    root = tree.getroot()
    for child in root:
        if child.tag != "item":
            continue

        for x in child:
            if x.tag == "request" or x.tag == "response":
                xb = base64.b64decode(x.text)
                do_burp_dat(xb, x.tag == "response")

# main code

for path, dir, files in os.walk(ROOT):
    for file in files:
        if file[-4:] == ".xml":
            do_burp_xml("/".join((path, file)))
