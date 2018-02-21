from binascii import hexlify, unhexlify

from xpub_stuff import *


xpub = 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LH' \
    'hwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'

###################################
# SECOND METHOD:
# 1. decompose the xpub
# 2. generate its first child public key
# 3. compose the child xpub
###################################

# which child number are we going to make?
key_index = 1
# deserialize the xpub
extended_public = deserialize(xpub)

# calculate the fingerprint for this node
parent_fingerprint = hash160(extended_public.key)[:4]

# this hmac will give us 64 bytes to work with
# the left 32 will help create the new public key
# the right 32 will be the new chaincode
child_hmac_data = hmac_sha512(
    chaincode=extended_public.chaincode,
    key=extended_public.key,
    key_index=key_index
)
# calculate the child public key
parent_generation_input = public_key_to_point(hexlify(extended_public.key))
new_generation_input = hex_bytes_to_int(child_hmac_data[:32]) * CURVE_GEN
child_public_key_point = new_generation_input + parent_generation_input
child_public_key = point_to_public_key(child_public_key_point)

# put the pieces together into the child XPUB
child_xpub = serialize_parts(
    is_private=False,
    depth=extended_public.depth + 1,
    fingerprint=parent_fingerprint,
    key_index=key_index,
    chaincode=child_hmac_data[32:],
    key=unhexlify(child_public_key)
)
print(child_xpub)

# RESULT:
# xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UF
#    HKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
