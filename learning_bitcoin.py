# generate keys

#  private key
# get reliable source of randomness from Linux
with open('/dev/urandom', 'r+b') as file:
    # generate random 256 bit number
    random_bytes = file.read(32)
    print("bytes object:", random_bytes) # bytes object, \x.. is for non-printable bytes (non-printable because the bytes >= 128 are not on ASCII table. The rest is ASCII.)
    decimal_format = int.from_bytes(random_bytes)
    print(f"decimal_format: {decimal_format}")
    binary_format = bin(decimal_format)
    print(f"binary_format: {binary_format}")
    hexadecimal_format = random_bytes.hex()
    print(f"hexadecimal_format: {hexadecimal_format}")




#  public key

# generate addresses