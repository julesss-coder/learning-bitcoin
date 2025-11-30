from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey
from cmath import sqrt
import hashlib
print(hashlib.algorithms_available)

class KeyPair:
    def __init__(self):
        self.private_key:int = self.generate_private_key() #TODO Make inaccessible
        self.public_key_coordinates:dict[str, int] = self.generate_public_key_coordinates()
        self.uncompressed_public_key:bytes = self.generate_uncompressed_public_key()
        self.compressed_public_key:str = self.generate_compressed_public_key()
        self.public_key_hash:str = self.generate_public_key_hash()

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


    def generate_public_key_coordinates(self)->dict[str:int]:
        """
        Generates the x and y coordinates of the public key.
        """
        # Generator point
        curve = Curve.get_curve('secp256k1')
        G = curve.generator

        # Generate public key
        public_key = self.private_key * G
        return {
            'x': public_key.x,
            'y': public_key.y
        }
        #TODO Try with ECPrivateKey as well and compare results
    

    def generate_uncompressed_public_key(self)->str:
        """
        Generates an uncompressed public key.
        """
        x_bytes = self.public_key_coordinates['x'].to_bytes(32, "big")
        y_bytes = self.public_key_coordinates['y'].to_bytes(32, "big")
        uncompressed_public_key = b"\x04" + x_bytes + y_bytes
        return uncompressed_public_key
    

    def generate_compressed_public_key(self)->str:
        """
        Generates compressed public key.
        """
        return '02' + hex(self.public_key_coordinates['x']) if self.public_key_coordinates['y'] % 2 == 0 else '03' + hex(self.public_key_coordinates['x'])
    

    def decompress_public_key(self)->dict[str, int]:
        """
        Returns the x and y coordinates of the public key.
        """
        prefix = self.compressed_public_key[0:2]
        x = self.compressed_public_key[2:] 
        curve = Curve.get_curve('secp256k1')
        p = curve.field

        # solve curve equation: y^2 = x^3 + 7 mod p
        y_squared = (pow(self.public_key_coordinates['x'], 3, p) + 7) % p
        # Modular square root
        y = pow(y_squared, (p + 1) // 4, p)

        # Choose correct y based on prefix
        if (y % 2 == 0 and prefix == '02') or (y % 2 == 1 and prefix == '03'):
            y = y
        else:
            y = (p - y) % p

        y = hex(y)[2:]

        return {'x': int(x, 16), 'y': int(y, 16)}
    

    def generate_public_key_hash(self)->str:
        # sha-256
        # input for sha-256 is public key (compressed?)
        sha256_hash = hashlib.sha256()
        sha256_hash.update(self.compressed_public_key.encode('utf-8')) #encode argument to bytes-like object first
        sha256_digest = sha256_hash.digest()
        
        # ripemd60
        ripemd160_hash = hashlib.new('ripemd160')
        ripemd160_hash.update(sha256_digest)
        return ripemd160_hash.hexdigest()


    def generate_address(self):
        pass



key_pair = KeyPair()
print(key_pair)
print("key_pair.public_key_coordinates: ", key_pair.public_key_coordinates)
print("decompressed public key", key_pair.decompress_public_key())


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

