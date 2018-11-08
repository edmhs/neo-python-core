#!/usr/bin/env python3
"""
This cli utility will be installed as `np-utils`. You can see the help with `np-utils -h`.
"""
import sys
import argparse
import base58
import hashlib
import json
import binascii

from Crypto import Random

from neocore import __version__
from neocore.Cryptography.Crypto import Crypto
from neocore.UInt160 import UInt160
from neocore.KeyPair import KeyPair


class ConversionError(Exception):
    pass


def address_to_scripthash(address):
    data = bytes(base58.b58decode(address))

    # Make sure signature byte is correct. In python 3, data[0] is bytes, and in 2 it's str.
    # We use this isinstance check to make it work with both Python 2 and 3.
    is_correct_signature = data[0] != 0x17 if isinstance(data[0], bytes) else b'\x17'
    if not is_correct_signature:
        raise ConversionError("Invalid address: wrong signature byte")

    # Make sure the checksum is correct
    if data[-4:] != hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4]:
        raise ConversionError("Invalid address: invalid checksum")

    # Return only the scripthash bytes
    return data[1:-4]


def scripthash_to_address(scripthash):
    try:
        if scripthash[0:2] != "0x":
            # little endian. convert to big endian now.
            print("Detected little endian scripthash. Converting to big endian for internal use.")
            scripthash_bytes = binascii.unhexlify(scripthash)
            scripthash = "0x%s" % binascii.hexlify(scripthash_bytes[::-1]).decode("utf-8")
            print("Big endian scripthash:", scripthash)
        return Crypto.ToAddress(UInt160.ParseString(scripthash))
    except Exception as e:
        raise ConversionError("Wrong format")


def create_wallet():
    private_key = bytes(Random.get_random_bytes(32))
    keypair = KeyPair(priv_key=private_key)
    public_key = keypair.PublicKey.encode_point(True)
    address = keypair.GetAddress()
    script_hash = address_to_scripthash(address)
    return {
        "private_key": keypair.Export(),
        "address": address,
        "script_hash": "0x{}".format(script_hash[::-1].hex()),
        "public_key": public_key.decode("utf-8")
    }


def wif_to_wallet(WIF):

    private_key = KeyPair.PrivateKeyFromWIF(WIF)
    keypair = KeyPair(priv_key=private_key)
    public_key = keypair.PublicKey.encode_point(True)
    address = keypair.GetAddress()
    script_hash = address_to_scripthash(address)
    return {
        "private_key": keypair.Export(),
        "address": address,
        "script_hash": "0x{}".format(script_hash[::-1].hex()),
        "public_key": public_key.decode("utf-8")
    }


def wif_to_private_key(WIF):

    return {
        "private_key" : KeyPair.PrivateKeyFromWIF(WIF)
    }


def wif_to_nep2(WIF, passphrase):
    private_key = KeyPair.PrivateKeyFromWIF(WIF)
    keypair = KeyPair(priv_key=private_key)

    return keypair.ExportNEP2(passphrase)


def nep2_to_wif(NEP2, passphrase):
    private_key = KeyPair.PrivateKeyFromNEP2(NEP2, passphrase)
    keypair = KeyPair(priv_key=private_key)
    public_key = keypair.PublicKey.encode_point(True)
    address = keypair.GetAddress()
    script_hash = address_to_scripthash(address)
    return {
        "private_key": keypair.Export(),
        "address": address,
        "script_hash": "0x{}".format(script_hash[::-1].hex()),
        "public_key": public_key.decode("utf-8")
    }


def main():
    parser = argparse.ArgumentParser()

    # Show the neo-python version
    parser.add_argument("--version", action="version",
                        version="neocore v{version}".format(version=__version__))

    parser.add_argument("--address-to-scripthash", nargs=1, metavar="address",
                        help="Convert an address to scripthash")

    parser.add_argument("--scripthash-to-address", nargs=1, metavar="scripthash",
                        help="Convert scripthash to address")

    parser.add_argument("--create-wallet", action="store_true", help="Create a wallet")

    parser.add_argument("--wif-to-private-key", nargs=1, metavar="WIF", help="Get the private key from a WIF key")

    parser.add_argument("--wif-to-wallet", nargs=1, metavar="WIF", help="Get the wallet info from a WIF key")

    parser.add_argument("--wif-to-nep2", nargs=2, metavar=("WIF","passphrase"), help="Get the NEP2 encrypted key from a WIF key")

    parser.add_argument("--nep2-to-wif", nargs=2, metavar=("NEP2","passphrase"), help="Get the WIF key and wallet info from encrypted NEP2 key")


    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        exit(1)

    # print(args)
    if args.address_to_scripthash:
        try:
            scripthash = address_to_scripthash(args.address_to_scripthash[0])
            print("Scripthash big endian:  0x{}".format(scripthash[::-1].hex()))
            print("Scripthash little endian: {}".format(scripthash.hex(), scripthash))
            print("Scripthash neo-python format: {!r}".format(scripthash))

        except ConversionError as e:
            print(e)
            exit(1)

    if args.scripthash_to_address:
        try:
            address = scripthash_to_address(args.scripthash_to_address[0])
            print(address)
        except ConversionError as e:
            print(e)
            exit(1)

    if args.create_wallet:
        w = create_wallet()
        print(json.dumps(w, indent=2))

    if args.wif_to_wallet:
        try:
            w = wif_to_wallet(args.wif_to_wallet[0])
            print(json.dumps(w, indent=2))
        except Exception as e:
            print(e)
            exit(1)

    if args.wif_to_private_key:
        try:
            p = wif_to_private_key(args.wif_to_private_key[0])
            print(p)
        except Exception as e:
            print(e)
            exit(1)

    if args.wif_to_nep2:
        try:
            p = wif_to_nep2(args.wif_to_nep2[0], args.wif_to_nep2[1])
            print(p)
        except Exception as e:
            print(e)
            exit(1)

    if args.nep2_to_wif:
        try:
            w = nep2_to_wif(args.nep2_to_wif[0], args.nep2_to_wif[1])
            print(json.dumps(w, indent=2))
        except Exception as e:
            print(e)
            exit(1)

if __name__ == "__main__":
    main()
