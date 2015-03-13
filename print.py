#!/usr/bin/env python2.7
# coding=utf-8

"""Open source implementation of the "xprintserver" protocol version 3.
Only two API calls are implemented: "getaccountlist" and "store3".
However, this should be enough to submit a print job.

"""

from Crypto.Cipher import DES3
import socket
import string
import random
import datetime
import sys

# 3DES key to encrypt API calls (REDACTED)
# md5(KEY) = "0a6d1a902be1182b7e9df7b19f7cba18"
# TODO find key in driver's process memory
KEY = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# IV used for CBC
IV = "\x00\x00\x00\x00\x00\x00\x00\x00"
# Bytes prepended to plaintext prior to encryption "in-band IV"
LEADER = "\x00\x01\x02\x03\x04\x05\x06\x07"
# Number of bytes to read from TCP socket
BUFF_LEN = 1024

__author__ = "Philip Huppert"
__copyright__ = "Copyright 2015, Philip Huppert"
__license__ = "MIT"


def random_string(chars, length):
    """Utility function to generate random strings
    of a given length from a given alphabet."""

    result = []
    while len(result) < length:
        result.append(random.choice(chars))
    return "".join(result)


def random_filename(length=16):
    """Utility function to generate random filenames of a given length."""

    return random_string(string.ascii_letters + string.digits, length)


def encrypt(data):
    """Encrypt data for use in API calls. 112-bit 3DES EDE CBC is used.
    An 8 byte leader is prepended to the plaintext.
    1 to 8 zero bytes are appended to the plaintext for padding."""

    des = DES3.new(key=KEY, mode=DES3.MODE_CBC, IV=IV)
    # Append 1 to 8 zeros to make plaintext a multiple of block length
    padding = "\0" * (8 - (len(data) % 8))
    return des.encrypt(LEADER + data + padding)


def decrypt(data):
    """Decrypt data for use in API calls. 112-bit 3DES EDE CBC is used.
    Any padding, i.e. the first 8 bytes and any trailing zeros, are removed."""

    assert len(data) % 8 == 0, "Ciphertext is not a multiple of block length"

    des = DES3.new(key=KEY, mode=DES3.MODE_CBC, IV=IV)
    decrypted = des.decrypt(data)
    # Strip leader (8 first bytes)
    decrypted = decrypted[8:]
    # Strip padding (trailing zeros)
    decrypted = decrypted.rstrip("\0")
    return decrypted


def get_accountlist(host, port, account):
    """This function implements the "getaccountlist" API call.
    It probably checks if a given account is valid and exists in the system."""

    msg = "M2;%s;1" % account
    body = encrypt(msg)

    # Build HTTP request
    headers = [
            "post getaccountlist HTTP/1.0",
            "Content-length: %d" % len(body),
            "Content-type: text/plain"
            ]
    headers = "\r\n".join(headers)
    request = headers + "\r\n\r\n" + body

    # Send HTTP request
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(request)

    # Receive HTTP response
    response = s.recv(BUFF_LEN)
    s.close()

    # Parse HTTP response (crudely)
    if not response.startswith("HTTP/1.0 200 OK\r\n"):
        return False

    _, _, r_body = response.partition("\r\n\r\n")
    return decrypt(r_body) == "PM2;1;ok"


def make_metadata(filename, document_name, owner):
    """Build metadata XML document."""

    # (tag, value) tuples used in the <metadata> root
    # Only filename, documentname and owner ever change
    metadata = [
            ("filename", filename),
            ("devicegroup", "lp"),
            ("documentname", document_name),
            ("pages", -1),
            ("copies", 0),
            ("color", 0),
            ("format", 0),
            ("price", -1),
            ("owner_encoding", "HEX"),
            ("owner", "".join(map(lambda x: "%02X" % ord(x), str(owner)))),
            ("ownertype", 1),
            ("account", "default"),
            ("printtype", -1),
            ("documentid", ""),
            ("accesscode", "")
            ]

    xml = []
    xml.append("<!DOCTYPE metadata>")
    xml.append("<metadata>")
    # Assemble children of <metadata>
    for m in metadata:
        tag, value = m
        value = str(value)
        xml.append("<{tag}>{value}</{tag}>".format(tag=tag, value=value))
    xml.append("</metadata>")
    xml = "\r\n".join(xml)

    return xml


def send_job(host, port, account, document_name, job_data, filename=None):
    """This function implements the two "store3" API calls.
    The first "store3" call is used to send an XML document containing
    metadata to the server. The second "store3" call is used to send
    the actual print job to the server."""

    if filename is None:
        filename = random_filename()

    # Build metadata request
    metadata = make_metadata(filename, document_name, account)
    date_id = datetime.datetime.now().strftime("5%Y%m%d%H%M%S")
    body = "M2;%s;%s" % (date_id, metadata)
    body = encrypt(body)

    def make_store3(body):
        """Build a store3 request."""

        headers = [
                "POST store3 HTTP/1.0",
                "Content-length: %d" % len(body),
                "Content-type: text/binary"
                ]
        headers = "\r\n".join(headers)
        return headers + "\r\n\r\n" + body

    def get_response(sock, do_decrypt=True):
        """Parse the response returned by the server."""

        resp = sock.recv(BUFF_LEN)
        _, _, resp = resp.partition("\r\n\r\n")
        if do_decrypt:
            resp = decrypt(resp)
        return resp

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Send metadata to server
    s.send(make_store3(body))
    assert get_response(s) == "PM2;1;ok", "Metadata was rejected"

    # Send printjob to server
    s.send(make_store3(job_data))
    r = get_response(s, do_decrypt=False)
    assert r == "PM2;1;ok", "Job data was rejected"

    s.close()


def main():
    if len(sys.argv) != 6:
        sys.stderr.write(
            "usage: %s host port account document_name document_file\n"
            % sys.argv[0])
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    account = int(sys.argv[3])
    document_name = sys.argv[4]
    document_file = sys.argv[5]

    # Read document/job from file
    job = None
    with open(document_file, "r") as fp:
        job = fp.read()
    assert job.startswith("\x1b%"), "Invalid PJL file"

    # Make getaccountlist API call
    account_exists = get_accountlist(host, port, account)
    assert account_exists, "Invalid account"
    print("Account verified")

    # Make store3 API calls
    send_job(host, port, account, document_name, job)
    print("Job sent")


if __name__ == "__main__":
    main()
