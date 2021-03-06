################################################################################
#
# General cryptographic utility functions. These are implementations of
# constructions for which we could't find any well-known libraries.
#
# Authors: Andres Fabrega, Jonathan Esteban, Damian Barabonkov.
#
# Note: unless otherwise stated, all keys are RSAPublicKey and RSAPrivateKey
#       objects, from the "cryptography" package. Imported keys must be
#       converted to this format before being used.
#
################################################################################

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import base64

def byte_xor(ba1, ba2):
    """ From https://nitratine.net/blog/post/xor-python-byte-strings/
    """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

class Trapdoor_Perm:
    def __init__(self, k, iv=None):
        """
        Pseudorandom trapdoor permutation.

        AES-CBC with fixed IV between encryptions.

        Args:
            k: key of the PTP.
            iv: the iv to be used for CBC mode, or None if a fresh one will be
                used.
        """
        # Sanity check the input key which must be 32 bytes
        assert(type(k) == bytes)
        assert(len(k) == 32)

        # Create a random IV to use for the encryption, if none was specified.
        self.iv = os.urandom(16) if not iv else iv

        # Save the key
        self.k = k

        self.cipher = Cipher(algorithms.AES(self.k),
                             modes.CBC(self.iv),
                             backend=default_backend())

    def eval(self, m):
        """
        Evaluate permutation. I.e., E_k(m).

        Args:
            m: message to be evaluated.

        Returns:
            The PTP  evaluated at m. Note that this is a deterministic
            computation.
        """
        # Sanity check
        assert(type(m) == int)

        length = m.bit_length() // 8 - 1
        length = length - length % 16 + 16

        encryptor = self.cipher.encryptor()
        ret = encryptor.update(m.to_bytes(length, "big")) + \
              encryptor.finalize()

        return int.from_bytes(ret, "big")

    def invert(self, y):
        """
        Inverts permutation. I.e., E_k^-1(y).

        Args:
            y: message to be inverted.

        Returns:
            The PTP inverted at y. That is, returns the value m s.t. E_k(m) = y.
        """
        # Sanity check
        assert(type(y) == int)

        length = y.bit_length() // 8 - 1
        length = length - length % 16 + 16

        decryptor = self.cipher.decryptor()
        ret = decryptor.update(y.to_bytes(length, "big")) + \
              decryptor.finalize()

        return int.from_bytes(ret, "big")
