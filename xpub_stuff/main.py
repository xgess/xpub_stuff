from .base58 import NumberAsHex, NumberAsHexBytes, NumberAsBase58
from .btc_address import *


def xpub_from_xprv(xprv):
    # STEPS
    # 1. decompose the xprv
    # 2. generate the public_key from the private_key
    # 3. compose the xpub from the pieces
    extended_private = deserialize(xprv)
    child_key = private_to_public(extended_private.key)

    return serialize_parts(
        is_private=False,
        depth=extended_private.depth,
        fingerprint=extended_private.fingerprint,
        key_index=extended_private.key_index,
        chaincode=extended_private.chaincode,
        key=child_key
    )


def generate_child_xprv(xprv, index=1, hardened=False):
    # STEPS
    # 1. decompose the xprv
    # 2. build it's corresponding xpub
    # 3. hmac for the new generation
    # 4. calculate the child key from the hmac result
    # 5. compose the child xprv
    extended_private = deserialize(xprv)
    extended_public = deserialize(xpub_from_xprv(xprv))

    # start calculating new values for the child extended key
    fingerprint = hash160(extended_public.key)[:4]

    # this hmac will give us 64 bytes to work with
    # the left 32 will help create the new private key
    # the right 32 will be the new chaincode
    child_hmac_data = hmac_sha512(
        chaincode=extended_private.chaincode,
        key=extended_public.key,
        key_index=index
    )

    new_generation_input = hex_bytes_to_int(child_hmac_data[:32])
    parent_generation_input = hex_bytes_to_int(extended_private.key)
    child_key_int = (new_generation_input + parent_generation_input) % CURVE_ORDER
    child_key = int_to_private_key(child_key_int)

    return serialize_parts(
        is_private=True,
        depth=extended_private.depth + 1,
        fingerprint=fingerprint,
        key_index=index,
        chaincode=child_hmac_data[32:],
        key=child_key
    )


def generate_child_xpub(xpub, index=1):
    # STEPS
    # 1. decompose the xpub
    # 2. hmac for the new generation
    # 3. calculate the child key from the hmac result
    # 4. compose the child xpub
    extended_public = deserialize(xpub)

    # start calculating new values for the child extended key
    parent_fingerprint = hash160(extended_public.key)[:4]

    child_hmac_data = hmac_sha512(
        chaincode=extended_public.chaincode,
        key=extended_public.key,
        key_index=index
    )

    parent_generation_input = public_key_to_point(hexlify(extended_public.key))
    new_generation_input = hex_bytes_to_int(child_hmac_data[:32]) * CURVE_GEN
    child_key_point = new_generation_input + parent_generation_input
    child_key = point_to_public_key(child_key_point)

    return serialize_parts(
        is_private=False,
        depth=extended_public.depth + 1,
        fingerprint=parent_fingerprint,
        key_index=1,
        chaincode=child_hmac_data[32:],
        key=unhexlify(child_key)
    )


def address_from_xpub(xpub):
    # STEPS
    # 1. decompose the xpub
    # 2. extract its public key
    # 3. calculate the address
    extended_public = deserialize(xpub)
    public_key = hexlify(extended_public.key).decode()
    return address_from_public_key(public_key)
