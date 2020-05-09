################################################################################
#
# Main interface to sign messages. Uses the "signer.py" library underneath.
#
# Original protocol: www.iacr.org/archive/asiacrypt2001/22480554.pdf
#
# Authors: Andres Fabrega, Jonathan Esteban, Damian Barabonkov.
#
# Note: all public/private keys are RSA keys in the standard PEM format.
#
################################################################################
import sys
import getpass
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from signer import Signer

# TODO: maybe but this function in one common file.
def process_pks(pks_pem):
    """
    Converts the public keys from PEM format to a list of RSAPublicKey objects.

    Args:
        pks_pem: a PEM file containing the public keys that form the ring.

    Returns:
        List of RSAPublicKey objects.
    """
    pks = []
    with open(pks_pem, "rb") as keys_file:
        key = b""
        for line in keys_file:
            key += line
            if line == b"-----BEGIN PUBLIC KEY-----\n":
                key = line
            elif line == b"-----END PUBLIC KEY-----\n":
                pk = serialization.load_pem_public_key(
                    key, backend=default_backend())
                pks.append(pk)
                key = b""
    return pks


def write_to_file(sigma, output_file):
    """
    Writes the signature to an output file.

    RSAPublicKey objects get converted to PEM format keys, integers get encoded
        to base 64 bytes, and bytes get base 64 encoded.

    Args:
        pks_pem: a PEM file containing the public keys that form the ring.
        output_file: name of file where the signature should be saved.

    Returns:
        List of RSAPublicKey objects.
    """
    with open(output_file, "wb") as output_file:
        for elt in sigma:
            if isinstance(elt, RSAPublicKey) or isinstance(elt, RSAPublicKey):
                elt = elt.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
            elif isinstance(elt, int):
                elt = base64.b64encode(elt.to_bytes(1024, "big"))
            elif isinstance(elt, bytes):
                elt = base64.b64encode(elt)
            # Probably some sanity check where, if it's not bytes, throw some error.
            output_file.write(elt)


def sign(m, pks_pem, s, sk_pem, output_file, pwd=None):
    """
    Crafts a ring signature for the message m, based on the SK and PK(s).

    Args:
        pks_pem: a PEM file containing the public keys that form the ring.
        s: index of the actual signer (i.e., index specifying which entry in
            pks_csv corresponds to the signer's PK).
        sk_pem: a PEM file containing the signers (encrypted) secret key.
        m: the message (a string) to sign.
        output_file: name of file where the signature should be saved.

    Returns:
        The signature.
    """
    # TODO: validate inputs.

    pks = process_pks(pks_pem)

    s = int(s)

    sk_password = pwd if pwd else getpass.getpass(prompt="Secret key password:")
    sk = None
    with open(sk_pem, "rb") as key_file:
        sk = serialization.load_pem_private_key(
            key_file.read(),
            password=sk_password.encode(),
            backend=default_backend())

    signer = Signer(pks, s, sk)

    sigma = signer.ring_sign(m.encode())
    write_to_file(sigma, output_file)


if __name__ == '__main__':
    # The first command-line argument is the module name.
    print(sign(*sys.argv[1:]))
