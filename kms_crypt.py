#!/usr/bin/python3
#
# Tool to encrypt and decrypt strings using AWS KMS
import boto3, base64, argparse
from botocore.config import Config
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from argparse import ArgumentParser
from pathlib import Path

def encrypt_w_kms_key( secret_string, aws_kms_key_id ):
    # awscli kms encrypt --key-id <KEY-ID> --encryption-algorithm RSAES_OAEP_SHA_256 --plaintext "<B64_SECRET>"
    kms_client = boto3.client('kms')
    response = kms_client.encrypt(Plaintext=secret_string, KeyId=aws_kms_key_id, EncryptionAlgorithm='RSAES_OAEP_SHA_256')
    return str( base64.b64encode( response["CiphertextBlob"] ), "utf-8")

def encrypt_w_public_key( secret_string, public_key_path ):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    #openssl pkeyutl -encrypt -pubin -inkey <PUB_KEY> -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256
    encrypted_bytes = public_key.encrypt(secret_string.encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    encrypted_bytes_b64 = base64.b64encode( encrypted_bytes )
    encrypted_string = str(encrypted_bytes_b64, "utf-8")
    return   encrypted_string

def decrypt( encrypted_string, aws_kms_key_id ):
    encrypted_bytes_b64 = base64.b64decode( encrypted_string )
    #aws kms decrypt --key-id <KEY-ID> --encryption-algorithm RSAES_OAEP_SHA_256 --ciphertext-blob "<B64_BLOB>" --region <REGION>
    kms_client = boto3.client('kms')
    response = kms_client.decrypt(CiphertextBlob=encrypted_bytes_b64, KeyId=aws_kms_key_id, EncryptionAlgorithm='RSAES_OAEP_SHA_256')
    return base64.b64encode((response['Plaintext']))

# CLI Arguments Parsing
parser = argparse.ArgumentParser(description="Tool to encrypt and decrypt strings using AWS KMS.")
parser.add_argument("--encrypt", help = "String to encrypt. Must also provide a --public-key or --kms-key-id.", required=False)
parser.add_argument("--decrypt", help = "String to decrypt. Must also provide --kms-key-id.", required=False)
parser.add_argument("--public-key", help = "Path to the public key to be used for encryption. This is preferred over KMS encruption as it's local.", required=False)
parser.add_argument("--kms-key-id", help = "The id of the AWS KMS key to be used for encryption/decryption. AWS credentials with permissions must be set in ENV vars (AWS_DEFAULT_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, [AWS_SESSION_TOKEN]).", required=False)
args = parser.parse_args()

if args.encrypt is not None and ( args.public_key is not None or args.kms_key_id is not None ):
    if args.public_key is not None:
        path = Path(args.public_key)
        if not path.is_file():
            print("ERROR: Public key not found at defined path.")
            parser.print_help()
            exit(1)
        encrypted_t = encrypt_w_public_key(args.encrypt, path)
    else:
        encrypted_t = encrypt_w_kms_key(args.encrypt, args.kms_key_id)
    print(encrypted_t)

elif args.decrypt is not None and args.kms_key_id is not None:
    decrypted_t = decrypt(args.decrypt, args.kms_key_id)
    decrypted_decoded_t = base64.b64decode( decrypted_t )
    print( str(decrypted_decoded_t, "utf-8") )

else:
    print("ERROR: Wrong combination of arguments was passed.")
    parser.print_help()
    exit(1)