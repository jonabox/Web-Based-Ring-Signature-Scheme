################################################################################
#
# Library for the implementation of RSA-based ring signatures.
# Main file for testing purposes of ring signatures
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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import random
from signer import Signer
from verifier import Verifier


def generate_pub_keys(n_keys):
    """ Generates `n_keys` number of RSAPublicKey keys
    """
    KEY_SIZE = 2048

    ret = []
    for i in range(n_keys):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        ret.append(public_key)

    return ret


def test_signing():
    N_PLAYERS = 3

    # Generate all of the public keys
    pks = generate_pub_keys(N_PLAYERS)

    # Choose which of the players that we are
    s = random.randrange(N_PLAYERS)

    # Load the private key from file and over-write the
    # public key at location `s`
    sk = None
    with open("./test_key.pem", "rb") as key_file:
        sk = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
    pks[s] = sk.public_key()

    # Create a `Signer` object
    signer = Signer(pks, s, sk)

    # Sign a message
    msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    sigma = signer.ring_sign(msg)

    # Create a 'Verifier' object.
    verifier = Verifier(pks)

    # Verify the sinature.
    out = verifier.ring_verify(msg, sigma[len(pks):])
    print(out)


if __name__ == "__main__":
    test_signing()
