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
    def __init__(self, k):
        """
        Pseudorandom trapdoor permutation.

        Args:
            k: key of the PTP.
        """
        # Sanity check the input key which must be 32 bytes
        assert(type(k) == bytes)
        assert(len(k) == 32)

        # Create a random IV to use for the encryption
        #
        # TODO: This IV should probably be passed to the validator
        self.iv = os.urandom(16)

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

        # TODO: 1024 is temporary placeholder
        encryptor = self.cipher.encryptor()
        ret = encryptor.update(m.to_bytes(1024, "little")) + \
              encryptor.finalize()

        return int.from_bytes(ret, "little")

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

        # TODO: 64 is temporary placeholder
        decryptor = self.cipher.decryptor()
        ret = decryptor.update(y.to_bytes(1024, "little")) + \
              decryptor.finalize()

        return int.from_bytes(ret, "little")
