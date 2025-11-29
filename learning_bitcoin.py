from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey
from cmath import sqrt
import hashlib

class KeyPair:
    def __init__(self):
        self.private_key:int = self.generate_private_key() #TODO Make inaccessible
        self.public_key:dict[str, int] = self.generate_public_key()
        self.compressed_public_key:str = self.compress_public_key()

    def generate_private_key(self)->int:
        # get reliable source of randomness from Linux
        with open('/dev/urandom', 'r+b') as file:
            # generate random 256 bit number
            random_bytes = file.read(32)
            print("bytes object:", random_bytes) # bytes object, \x.. is for non-printable bytes (non-printable because the bytes >= 128 are not on ASCII table. The rest is ASCII. The two characters after \x are not separate ASCII bytes, but the hexadecimal representation of one byte.)
            decimal_format = int.from_bytes(random_bytes, 'big') # sys.byteorder == 'little'!
            print(f"decimal_format: {decimal_format}")
            binary_format = bin(decimal_format)
            print(f"binary_format: {binary_format}")
            hexadecimal_format = random_bytes.hex()
            print(f"hexadecimal_format: {hexadecimal_format}")

        return decimal_format


    def generate_public_key(self)->dict[str: int]:
        # Generator point
        curve = Curve.get_curve('secp256k1')
        G = curve.generator

        # Generate public key
        public_key = self.private_key * G
        x = hex(public_key.x)[2:]
        y = hex(public_key.y)[2:]
        return {'x': x, 'y': y}
    
        #TODO Try with ECPrivateKey as well and compare results
    

    def compress_public_key(self)->str:
        return '02' + self.public_key['x'] if int(self.public_key['y'], 16) % 2 == 0 else '03' + self.public_key['x']
    

    def decompress_public_key(self)->dict[str, int]:
        prefix = self.compressed_public_key[0:2]
        x = self.compressed_public_key[2:] 
        curve = Curve.get_curve('secp256k1')
        p = curve.field

        # solve curve equation: y^2 = x^3 + 7 mod p
        y_squared = (pow(self.public_key['x'], 3, p) + 7) % p
        # Modular square root
        y = pow(y_squared, (p + 1) // 4, p)

        # Choose correct y based on prefix
        if (y % 2 == 0 and prefix == '02') or (y % 2 == 1 and prefix == '03'):
            y = y
        else:
            y = (p - y) % p

        y = hex(y)[2:]

        return {'x': x, 'y': y}
    

    def generate_public_key_hash(self):
        # sha-256
        # input for sha-256 is public key (compressed?)
        # output is called digest
        hash = hashlib.sha256()
        hash.update(self.compressed_public_key.encode('utf-8'))
        digest = hash.digest()
        hexdigest = hash.hexdigest()
        print("sha-256 digest: ", digest)
        #TODO
        # ripemd60
        # return address
    

    def generate_address(self):
        pass



key_pair = KeyPair()
print(key_pair)
print(key_pair.generate_public_key_hash())


class Transaction:
    pass


#  private key
# get reliable source of randomness from Linux
# with open('/dev/urandom', 'r+b') as file:
#     # generate random 256 bit number
#     random_bytes = file.read(32)
#     print("bytes object:", random_bytes) # bytes object, \x.. is for non-printable bytes (non-printable because the bytes >= 128 are not on ASCII table. The rest is ASCII. The two characters after \x are not separate ASCII bytes, but the hexadecimal representation of one byte.)
#     decimal_format = int.from_bytes(random_bytes, 'big') # sys.byteorder == 'little'!
#     print(f"decimal_format: {decimal_format}")
#     binary_format = bin(decimal_format)
#     print(f"binary_format: {binary_format}")
#     hexadecimal_format = random_bytes.hex()
#     print(f"hexadecimal_format: {hexadecimal_format}")


# private_key_as_int = decimal_format

# # Generator point
# curve = Curve.get_curve('secp256k1')
# G = curve.generator

# # Generate public key
# public_key = private_key_as_int * G
# x = hex(public_key.x)[2:]
# y = hex(public_key.y)[2:]
# print(x)
# print(y)

# compressed_public_key = '02' + x if public_key.y % 2 == 0 else '03' + x


# public_key_2 = ECPrivateKey(private_key_as_int, curve)
# print(public_key_2)
# print(compressed_public_key is public_key_2)

# # Decompress public key
# prefix = compressed_public_key[0:2]
# x = compressed_public_key[2:] 
# p = curve.field

# # solve curve equation: y^2 = x^3 + 7 mod p
# y_squared = (pow(public_key.x, 3, p) + 7) % p
# # Modular square root
# y = pow(y_squared, (p + 1) // 4, p)

# # Choose correct y based on prefix
# if (y % 2 == 0 and prefix == '02') or (y % 2 == 1 and prefix == '03'):
#     y = y
# else:
#     y = (p - y) % p

# y = hex(y)[2:]


# print(x)
# print(y)
# # generate addresses

