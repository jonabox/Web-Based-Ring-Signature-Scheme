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
