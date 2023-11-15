from random import SystemRandom
from ecdsa import ecdsa
import sha3
import binascii
from typing import Tuple
import uuid
import os
import math

def hash_message(msg: str) -> int:
    """
    hash the message using keccak256, truncate if necessary
    """
    k = sha3.keccak_256()
    k.update(msg.encode("utf8"))
    d = k.digest()
    n = int(binascii.hexlify(d), 16)
    olen = ecdsa.generator_secp256k1.order().bit_length() or 1
    dlen = len(d)
    n >>= max(0, dlen - olen)
    return n

def modInverse(b,m):
  g = math.gcd(b, m)
  if (g != 1):
    return -1
  else:
    return pow(b, m - 2, m)

# Function to compute a/b under modulo m
def modDivide(a,b,m):
  a = a % m
  inv = modInverse(b,m)
  if(inv == -1):
    print("Division not defined")
  else:
    return (inv*a) % m

if __name__ == "__main__":
    msg1 = input("msg1? ")
    msg1_hashed = hash_message(msg1)
    msg2 = input("msg2? ")
    msg2_hashed = hash_message(msg2)
    r1 = int(input("r1? "), 16)
    s1 = int(input("s1? "), 16)
    s2 = int(input("s2? "), 16)

    g = ecdsa.generator_secp256k1

    k = modDivide((msg1_hashed - msg2_hashed), (s1 - s2))

    d = modDivide(((s1 * k) - msg1_hashed), r1)

    test = int(input("test? "), 16)

    pub = ecdsa.Public_key(g, g * d)
    priv = ecdsa.Private_key(pub, d)

    sig = priv.sign(test, k)
    print(f"solved r=0x{sig.r:032x}")
    print(f"solved s=0x{sig.s:032x}")