################################################################################
#
# Library for the implementation of RSA-based ring signatures.
# Ring interface (later "implemented" the by Signer and Verifier classes).
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

class Ring:
    def __init__(self, pks):
        """
        Main interface regresenting a ring of users.

        Args:
            pks: (ordered) list of public keys of the members of the ring.
        """
        self.pks = pks
        self.ring_size = len(self.pks)

        # Find exponent of smallest power of 2 greater than all moduli.
        self.b = (max([pk.key_size for pk in pks]) - 1).bit_length()

    def _g(self, m, pk_nums, sk=None):
        """
        The extended trap-door permutation over Z_{n_i}.

        Args:
            m: the message/output to be evaluated at g or g^-1, respectively
                (depending on the 'invert' flag).
            pk_nums: the public key (numbers) associated with a particular ring
                    member. This is a RSAPublicNumbers object, which carries the
                    modulus and encryption exponent.
            sk: if set, use trapdoor it to invert. Otherwise,
                simply evaluate.

        Returns:
            g_i(m), As defined on the spec, or g^-1_i(m) (depending on if 'sk'
            is set).
        """
        q, r = int(m/n), m - q*n

        if (q + 1).bit_length()  < self.b - 1:
            # This is safe to do: this code will only run locally on the
            # machine of the person that holds the secret key.
            exponent = pk_nums.e if not sk else sk.private_numbers().d
            return q * pk_nums.key_size + pow(m, exponent, pk_nums.key_size)
        else:
            return m
