from binascii import hexlify, unhexlify
import ecdsa
from ecdsa.ecdsa import int_to_string
import hashlib
import hmac
import struct
from typing import NamedTuple

from .base58 import bytes_to_base58check, hex_to_base58, base58_to_hex
from .base58 import NumberAsHex, NumberAsHexBytes, NumberAsBase58


CURVE = ecdsa.curves.SECP256k1.curve
CURVE_GEN = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER = CURVE_GEN.order()
EC_ORDER = n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FINITE_FIELD = p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

PUBLIC_VERSION_PREFIX = unhexlify('0488b21e')
PRIVATE_VERSION_PREFIX = unhexlify('0488ade4')
PRIVATE_KEY_INDICATOR = unhexlify('00')
RAW_ELEMENTS_OF_EXTENDED_KEY = '>4s B 4s L 32s 33s'
    # 4 bytes for the version prefix
    # 1 byte for the depth
    # 4 bytes for the fingerprint
    # 4 bytes for the index
    # 32 bytes for the chaincode
    # 33 bytes for the indicator+key
FULL_EXTENDED_KEY_FORMAT = RAW_ELEMENTS_OF_EXTENDED_KEY + ' 4s'
    # 4 additional bytes for a checksum


class ExtendedKey(NamedTuple):
    magic_version: NumberAsHexBytes
    depth: int
    fingerprint: NumberAsHexBytes
    key_index: int
    chaincode: NumberAsHexBytes
    indicator: NumberAsHexBytes
    key: NumberAsHexBytes
    checksum: NumberAsHexBytes
    is_private: bool


def deserialize(base58_key: NumberAsBase58) -> ExtendedKey:
    as_hex = base58_to_hex(base58_key)
    struct_format = struct.Struct(FULL_EXTENDED_KEY_FORMAT)
    unpacked_data = struct_format.unpack(unhexlify(as_hex))

    first_byte_of_key = unpacked_data[5][:1]
    if first_byte_of_key == PRIVATE_KEY_INDICATOR:
        #xprv
        is_private = True
        indicator = first_byte_of_key
        key = unpacked_data[5][1:] # everything after the first byte
    else:
        #xpub
        is_private = False
        indicator = b''
        key = unpacked_data[5]

    return ExtendedKey(
        magic_version=NumberAsHexBytes(unpacked_data[0]),
        depth=unpacked_data[1],
        fingerprint=NumberAsHexBytes(unpacked_data[2]),
        key_index=unpacked_data[3],
        chaincode=NumberAsHexBytes(unpacked_data[4]),
        indicator=NumberAsHexBytes(indicator),
        key=NumberAsHexBytes(key),
        checksum=NumberAsHexBytes(unpacked_data[6]),
        is_private=is_private
    )


def serialize_parts(is_private: bool,
                    depth: int,
                    fingerprint: bytes,
                    key_index: int,
                    chaincode: bytes,
                    key: bytes) -> NumberAsBase58:
    if is_private:
        version, indicator = PRIVATE_VERSION_PREFIX, PRIVATE_KEY_INDICATOR
    else:
        version, indicator = PUBLIC_VERSION_PREFIX, b''

    struct_format = struct.Struct(RAW_ELEMENTS_OF_EXTENDED_KEY)
    parts = (version, depth, fingerprint, key_index, chaincode, indicator + key)
    serialized_bytes = struct_format.pack(*parts)

    return bytes_to_base58check(NumberAsHexBytes(serialized_bytes))


def private_to_public(input_bytes: NumberAsHexBytes) -> NumberAsHexBytes:
    signing_key = ecdsa.SigningKey.from_string(input_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key_point = hexlify(verifying_key.to_string())
    public_key_x, public_key_y = public_key_point[:64], public_key_point[64:]
    if (int(public_key_y, 16) % 2) == 0:
        compressed_prefix = b'02'
    else:
        compressed_prefix = b'03'
    return NumberAsHexBytes(unhexlify(compressed_prefix + public_key_x))


def public_key_to_point(public_key: NumberAsHex) -> ecdsa.ellipticcurve.Point:
    x = int(public_key[2:66], 16)
    prefix = public_key[0:2]
    y_square = (pow(x, 3, p)  + 7) % p
    y_square_square_root = pow(y_square, (p+1)//4, p)
    if prefix == b'03':
        y = (-y_square_square_root) % p
    elif prefix == b'02':
        y = y_square_square_root
    else:
        raise ValueError('Invalid prefix on this compressed public key: {}'.format(public_key))

    return ecdsa.ellipticcurve.Point(CURVE, x, y, EC_ORDER)


def point_to_public_key(point: ecdsa.ellipticcurve.Point) -> NumberAsHex:
    if point.y() & 1:
        public_key = b'03' + b'%064x' % point.x()
    else:
        public_key = b'02' + b'%064x' % point.x()
    return NumberAsHex(public_key)


def address_from_public_key(public_key: str) -> str:
    public_key_bytes = unhexlify(public_key)
    public_key_hashed = hash160(public_key_bytes)
    address = unhexlify(b'00' + hexlify(public_key_hashed))
    return bytes_to_base58check(NumberAsHexBytes(address))


def hmac_sha512(chaincode: NumberAsHexBytes, key: NumberAsHexBytes, key_index: int = 1) -> bytes:
    formatted_index = int_to_bytes(key_index, 4)
    hmac_key = chaincode
    hmac_data = unhexlify(hexlify(key) + formatted_index)
    return hmac.new(hmac_key, hmac_data, hashlib.sha512).digest()


def hash160(input_bytes: bytes) -> bytes:
    hash_of_input = hashlib.new('sha256', input_bytes).digest()
    ripe_md_of_hash = hashlib.new('ripemd160', hash_of_input).digest()
    return ripe_md_of_hash


def hex_bytes_to_int(input_bytes: NumberAsHexBytes) -> int:
    return int(hexlify(input_bytes), 16)


def int_to_bytes(input_int: int, number_of_bytes: int) -> bytes:
    return '{}'.format(int(input_int)).zfill(number_of_bytes * 2).encode()


def int_to_private_key(input_int: int) -> NumberAsHexBytes:
    return (b'\0'*32 + int_to_string(input_int))[-32:]
