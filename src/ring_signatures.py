#####################################################################
#
# Library for the implementation of RSA-based ring signatures.
# Utility functions to sign and verify.
#
# Original protocol: www.iacr.org/archive/asiacrypt2001/22480554.pdf
#
# Authors: Andres Fabrega, Jonathan Esteban, Damian Barabonkov.
#
# Note: unless otherwise stated, all keys are RSAPublicKey and RSAPrivateKey
#       objects, from the "cryptography" package. Imported keys must be
#       converted to this format before being used.
#####################################################################
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
        x_i = [secrets.randbits(b) for i in range(len(pks) - 1)]
        y_i = []

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
            return q * pk.key_size + pk.encrypt(m, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))
        else:
            return m


class Verifier:

    def ring_verify(self, m, sigma):
        """
        Verifies if sigma is a valid ring signature for m.

        Args:
            m: the message that was signed.
            sigma: the ring signature for m, which contains all PKs of ring members.

        Returns:
            True if the signature is valid, and False otherwise.
        """
        pass
