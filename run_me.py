from xpub_stuff import generate_child_xprv, xpub_from_xprv, generate_child_xpub


xprv = 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvU' \
    'xt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
print(f"\n\nHere is an xprv: {xprv}")
print(f"Let's calculate its first child's xpub both ways.\n")


###################################
# First method of generating a child extended public key
# 1. start with an xprv
# 2. generate a child xprv from it
# 3. generate the child xpub from its xprv
###################################
print("1: generate the first child xprv, and then calculate that xprv's xpub...")
child_xprv = generate_child_xprv(xprv)
print(f"...child xprv: {child_xprv}")
child_xpub_first_method = xpub_from_xprv(child_xprv)
print(f"...child xprv's xpub: ¡¡¡ {child_xpub_first_method} !!!")


###################################
# Second method of generating a child extended public key
# 1. start with an xpub (i.e. not a private key)
# 2. use the xpub to generate the child xpub
###################################
print("\n2: generate the parent xpub, and then calculate that xpub's first child...")

xpub = xpub_from_xprv(xprv)
print(f"...parent xpub: {xpub}")
child_xpub_second_method = generate_child_xpub(xpub)
print(f"...child xpub: ¡¡¡ {child_xpub_second_method} !!!")

print("\nAnd hopefully, they are the same.")
