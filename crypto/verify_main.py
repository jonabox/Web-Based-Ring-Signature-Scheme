################################################################################
#
# Main interface to verify messages. Uses the "verifier.py" library underneath.
#
# Original protocol: www.iacr.org/archive/asiacrypt2001/22480554.pdf
#
# Authors: Andres Fabrega, Jonathan Esteban, Damian Barabonkov.
#
# Note: all public/private keys are RSA keys in the standard PEM format.
#
################################################################################
import sys
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from verifier import Verifier


def parse_signature_file(signature_file):
    """
    Parses the signature file to the appropriate Python objects.

    PEM Format keys get converted to RSAPublicKey objects, and the base 64
        encoded integers/bytes get decoded.

    Args:
        signature_file: file where the signature is saved.

    Returns:
        Two-element tuple containing a list of RSAPublicKey objects, and a list
            with the glue value 'v', the x_i's for all ring members (as defined
            in the protocol), and the IV for the trapdoor permutation.
    """
    pks = []
    sigma = []
    with open(signature_file, "rb") as signature_file:
        key = b""
        for line in signature_file:
            # We finished reading all keys.
            if not key and line != b"-----BEGIN PUBLIC KEY-----\n":
                elts = line.split(b"==")
                # Last element of elts is simply "\n".
                for elt in elts[:-2]:
                    # We have to append the padding again to avoid a
                    # "Incorrect padding" error.
                    sigma.append(int.from_bytes(
                                    base64.b64decode(elt + b"=="), "big"))
                sigma.append(base64.b64decode(elts[-2] + b"=="))

            else:
                key += line
                if line == b"-----BEGIN PUBLIC KEY-----\n":
                    key = line
                elif line == b"-----END PUBLIC KEY-----\n":
                    pk = serialization.load_pem_public_key(
                        key, backend=default_backend())
                    pks.append(pk)
                    key = b""

    return pks, sigma


def verify(m, signature_file):
    """
    Crafts a ring signature for the message m, based on the SK and PK(s).

    Args:
        m: the message (a string) to verify.
        signature_file: file containing the signature, in the format specified
                        in sign_main.py

    Returns:
        True if the signature is valid, and False otherwise.
    """
    pks, sigma = parse_signature_file(signature_file)

    verifier = Verifier(pks)

    return verifier.ring_verify(m.encode(), sigma)


if __name__ == '__main__':
    # The first command-line argument is the module name.
    print(verify(*sys.argv[1:]))
