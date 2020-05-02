################################################################################
#
# Library for the implementation of RSA-based ring signatures.
# Utility functions to verify ring signatures.
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class Verifier(Ring):
    def __init__(self, pks):
        """
        Used to verify messages.

        Args:
            pks: (ordered) list of public keys. [PK_1, ... , PK_r].
        """
        self.pks = pks
        # Find exponent of smallest power of 2 greater than all moduli.
        self.b = (max([pk.key_size for pk in pks]) - 1).bit_length()

    def ring_verify(self, m, sigma):
        """
        Verifies if sigma is a valid ring signature for m.

        Args:
            m: the message that was signed.
            sigma: the ring signature for m. Contains the glue value 'v', and
                    the x_i's for all ring members, as defined in the protocol.

        Returns:
            True if the signature is valid, and False otherwise.
        """
        # Step 1: compute trapdoor permutations.
        y_i = [self._g(sigma[i + 1], self.pks[i].public_numbers()) \
                for i in range(self.ring_size)]

        # Step 2: get key.
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(m)
        k = digest.finalize()
        enc_oracle = Trapdoor_Perm(k)

        # Step 3: verify the ring equation.
        return self._check_c(y_i, sigma[0], enc_oracle)

    def _check_c(self, y_i, v, enc_oracle):
        """
        Checks the ring equation for the y_i's.

        Args:
            y_i: g_i(x_i) for every ring member i.
            v: glue value.
            enc_oracle: trapdoor permutation oracle.

        Returns:
            True if the y_i's and v satisfy the ring equation.
        """
        y_enc
        for j in range(self.r):
            y_enc = enc_oracle.eval(y_enc ^ y_i[j])

        return y_enc == v
