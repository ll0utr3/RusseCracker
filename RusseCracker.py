import hashlib
import re
import sys
import binascii
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--format', '-f', required=True)
parser.add_argument('--hash', required=True)
parser.add_argument('--wordlist', '-w', required=True)
parser.add_argument('--salt', '-s', required=False, default="")
args = parser.parse_args()


def fail():
    if last_line == line:
        print("[-] Sorry, we couldn't crack your hash (maybe you should try another wordlist : https://weakpass.com/wordlist)")
        sys.exit()


type_hash = str(args.format.lower())
hash = str(args.hash.lower())
wordlist = str(args.wordlist.lower())
salt = str(args.salt)

try:
    with open(wordlist, 'r', encoding="ISO-8859-1") as f:
        text = f.read().splitlines()
        last_line = text[-1]
except FileNotFoundError:
    print("[-] Wrong file name !")
    sys.exit()
except MemoryError:
    print("[-] Please don't choose a big file like this : MemoryError")
    sys.exit()

if type_hash not in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "ntlm"]:
    print("[-] You need to choose md5, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512 or ntlm for hash type !")
    sys.exit()

print('[*] RusseCracker by JeSuisRusse')
print("[*] Cracking your hash...")

if type_hash == "md5":
    for line in text:
        salted_line = salt+line
        if str(hashlib.md5(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha1":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha1(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha224":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha224(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha256":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha256(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha384":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha384(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha512":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha512(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha3-224":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha3_224(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha3-256":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha3_256(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha3-384":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha3_384(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "sha3-512":
    for line in text:
        salted_line = salt+line
        if str(hashlib.sha3_512(salted_line.encode('utf-8')).hexdigest()) == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()

elif type_hash == "ntlm":
    for line in text:
        salted_line = salt+line
        hashcrack = hashlib.new('md4', salted_line.encode('utf-16le')).digest()
        if binascii.hexlify(hashcrack).decode('utf-8') == hash:
            print("[+] Cracked : "+line)
            sys.exit()
        fail()
