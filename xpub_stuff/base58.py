from binascii import hexlify, unhexlify
from hashlib import sha256
from typing import NewType


B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
NumberAsHex = NewType('NumberAsHex', bytes)
NumberAsHexBytes = NewType('NumberAsHexBytes', bytes)
NumberAsBase58 = NewType('NumberAsBase58', str)


class InvalidBase58Error(ValueError):
    pass


def bytes_to_base58check(input_bytes: NumberAsHexBytes) -> NumberAsBase58:
    checksum: bytes = sha256(sha256(input_bytes).digest()).digest()
    input_with_checksum: bytes = hexlify(input_bytes) + hexlify(checksum[:4])
    return hex_to_base58(NumberAsHex(input_with_checksum))


def hex_to_base58(input_hex: NumberAsHex) -> NumberAsBase58:
    as_base10 = int(input_hex, 16)

    # Divide that integer into base58
    running_base58_digits = []
    while as_base10 > 0:
        as_base10, base58_index = divmod(as_base10, 58)
        running_base58_digits.append(B58_DIGITS[base58_index])
    as_base58 = ''.join(running_base58_digits[::-1])

    # Encode leading zeros as base58 zeros
    as_bytes_0_value = 0
    amount_of_padding = 0
    for byte in unhexlify(input_hex):
        if byte == as_bytes_0_value:
            amount_of_padding += 1
        else:
            break
    return NumberAsBase58(B58_DIGITS[0] * amount_of_padding + as_base58)


def base58_to_hex(input_base58: NumberAsBase58) -> NumberAsHex:
    # Convert the string to an integer
    as_base10 = 0
    for character in input_base58:
        as_base10 *= 58
        if character not in B58_DIGITS:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % character)
        digit = B58_DIGITS.index(character)
        as_base10 += digit

    # Convert the integer to base16
    as_base16 = b'%x' % as_base10
    if len(as_base16) % 2:
        as_base16 = b'0' + as_base16

    # Add padding back.
    amount_of_padding = 0
    for character in input_base58[:-1]:
        if character == B58_DIGITS[0]:
            amount_of_padding += 1
        else:
            break

    return NumberAsHex(amount_of_padding * b'0' + as_base16)
