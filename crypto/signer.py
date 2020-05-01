################################################################################
#
# Library for the implementation of RSA-based ring signatures.
# Utility functions to sign messages.
#
# Original protocol: www.iacr.org/archive/asiacrypt2001/22480554.pdf
#
# Authors: Andres Fabrega, Jonathan Esteban, Damian Barabonkov.
#
# Note: unless otherwise stated, all keys are RSAPublicKey and RSAPrivateKey
#       objects, from the "cryptography" package. Imported keys must be
#       converted to this format before being used.
#
################################################################################
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


class Signer:
    def __init__(self, m, pks, s, sk):
        """
        Used to sign messages.

        Args:
            pks: (ordered) list of public keys. [PK_1, ... , PK_r.]
            s: index of the actual signer (who's public key is PK_s).
            sk: secret key of the s-th ring member.
        """
        self.pks = pks
        self.ring_size = len(self.pks)
        self.s = s
        self.sk = sk

        # Find exponent of smallest power of 2 greater than all moduli.
        self.b = (max([pk.key_size for pk in pks]) - 1).bit_length()

    def ring_sign(self):
        """
        Crafts a ring signature for the message m, based on the SK and PK(s).

        Args:
            m: message (in bytes) to sign.

        Returns:
            The signature.
        """
        # Step 1: hash message to get key.
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(m)
        k = digest.finalize()

        # Step 2: pick a random glue value.
        v = secrets.randbits(b)

        # Step 3: pick random x_i's for all other ring members.
        x_i = [secrets.randbits(b) for i in range(self.ring_size - 1)]
        y_i = [self._g(self.pks[i], x_i[i]) for i in range(self.ring_size)]

        # Step 4: solve ring equation for y_s.

        # Step 5: invert g_s(y_s) to find x_s, using the trapdoor (i.e., SK).

        # Step 6: output the ring signature.

    def _g(self, pk, m):
        """
        The extended trap-door permutation over Z_{n_i}.

        Args:
            pk: the publc key associated with a particular ring member. This
                carries the modulus and encryption exponent.
            m: the message to be evaluated at g.

        Returns:
            g_i(m), As defined on the spec.
        """
        q, r = int(m/n), m - q*n

        if (q + 1).bit_length()  < b - 1:
            pk_nums = pk.public_numbers()
            return q * pk.key_size + pow(m, pk_nums.e, pk_nums.key_size)
        else:
            return m

    def _c(self, y_i, v):
        """
        Solves the ring equation for y_s.

        Args:
            y_i: g_i(x_i) for every ring member i.
            v: glue value.

        Returns:
            The only value g_s satisfying the ring equation for all values of
            y_i and v.
        """
        pass
