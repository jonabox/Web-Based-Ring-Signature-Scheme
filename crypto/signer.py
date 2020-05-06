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
from cryptography.hazmat.primitives import hashes

from crypto_utils import Trapdoor_Perm
from ring.py import Ring


class Signer(Ring):
    def __init__(self, pks, s, sk):
        """
        Used to sign messages. Extends the 'Ring' interface.

        Args:
            pks: (ordered) list of public keys. [PK_1, ... , PK_r].
            s: index of the actual signer (who's public key is PK_s).
                0 <= s <= r - 1.
            sk: secret key of the s-th ring member.
        """
        super().__init__(pks)
        self.s = s
        self.sk = sk

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
        enc_oracle = Trapdoor_Perm(k)

        # Step 2: pick a random glue value.
        v = secrets.randbits(b)

        # Step 3: pick random x_i's for all other ring members.
        x_i = [secrets.randbits(b) for i in range(self.ring_size - 1)]
        y_i = [self._g(x_i[i], self.pks[i].public_numbers()) \
                for i in range(self.ring_size)]

        # Step 4: solve ring equation for y_s.
        y_s = self._c(y_i, v, enc_oracle)

        # Step 5: invert g_s(y_s) to find x_s, using the trapdoor (i.e., SK).
        x_s = self._g(y_s, self.sk.public_numbers(), self.sk)
        x_i.insert(s, x_s)

        # Step 6: output the ring signature.
        return self.pks + [v] + x_i


    def _c(self, y_i, v, enc_oracle):
        """
        Solves the ring equation for y_s.

        Args:
            y_i: g_i(x_i) for every ring member i (except s).
            v: glue value.
            enc_oracle: trapdoor permutation oracle.

        Returns:
            The only value g_s satisfying the ring equation for all values of
            y_i and v.
        """
        y_enc, y_dec = v, v
        for j in range(self.s):
            y_enc = enc_oracle.eval(y_enc ^ y_i[j])
        for p in range(self.ring_size - 1, self.s, -1):
            y_dec = y_i[p] ^ enc_oracle.invert(y_dec)

        # Perform the last iteration to solve for y_s
        y_s = y_enc ^ enc_oracle.invert(y_dec)
        
        return y_s
