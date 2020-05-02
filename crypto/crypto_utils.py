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

class Pseudorandom_Perm:
    def __init__(self, k):
        """
        Pseudorandom trapdoor permutation.

        Args:
            k: key of the PTP.
        """
        self.k = k

    def eval(self, m):
        """
        Evaluate permutation. I.e., E_k(m).

        Args:
            m: message to be evaluated.

        Returns:
            The PTP  evaluated at m. Note that this is a deterministic
            computation.
        """
        pass

    def invert(self, y):
        """
        Inverts permutation. I.e., E_k^-1(y).

        Args:
            m: message to be evaluated.

        Returns:
            The PTP inverted at y. That is, returns the value m s.t. E_k(m) = y.
        """
        pass
