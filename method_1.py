from binascii import hexlify, unhexlify

from xpub_stuff import *


xprv = 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUx' \
    't4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'

###################################
# FIRST METHOD:
# 1. decompose the xprv
# 2. generate the first child private key
# 3. generate a public key from the private key
# 4. compose the child xpub
###################################

# which child number are we going to make?
key_index = 1
# deserialize the xprv
extended_private = deserialize(xprv)
# calculate its xpub
extended_public = deserialize(xpub_from_xprv(xprv))

# calculate the fingerprint for this node
fingerprint = hash160(extended_public.key)[:4]

# this hmac will give us 64 bytes to work with
# the left 32 will help create the new private key
# the right 32 will be the new chaincode
child_hmac_data = hmac_sha512(
    chaincode=extended_private.chaincode,
    key=extended_public.key,
    key_index=key_index
)
# calculate the child private key
new_generation_input = hex_bytes_to_int(child_hmac_data[:32])
parent_generation_input = hex_bytes_to_int(extended_private.key)
child_private_key_int = (new_generation_input + parent_generation_input) % CURVE_ORDER
child_private_key = int_to_private_key(child_private_key_int)

# we could create the child xprv right here since we have all the pieces
# but it's just a passthrough for this exercise

# calculate the public key for the XPUB from the child private key
child_public_key = private_to_public(child_private_key)

# put the pieces together into the child XPUB
child_xpub = serialize_parts(
    is_private=False,
    depth=extended_private.depth + 1,
    fingerprint=fingerprint,
    key_index=key_index,
    chaincode=child_hmac_data[32:],
    key=child_public_key
)
print(child_xpub)

# RESULT:
# xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UF
#    HKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
