#!/usr/bin/python3
#
# Filter to decrypt strings using AWS KMS
import boto3, base64, argparse, os
from botocore.config import Config
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from argparse import ArgumentParser
from pathlib import Path

class FilterModule(object):
    ''' AWS KMS Decrypt filter '''

    allowed_aws_env_vars = ["AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_KMS_KEY_ID", "AWS_SESSION_TOKEN"]

    def filters(self):
        return {
            'decryptstring': self.decryptstring
        }

    def test_input(self, input_sting, aws_kms_environment):
        if type(input_sting) is not str:
            raise Exception("The first argument must be a string. Not " + str(type(input_sting)))
        if type(aws_kms_environment) is not dict:
            raise Exception("The second argument must be a dictionary. Not "+ str(type(aws_kms_environment)) +". Allowed AWS env vars: " + str(self.allowed_aws_env_vars))

    def set_environment(self, aws_kms_environment):
        for envar in aws_kms_environment:
            if envar in self.allowed_aws_env_vars:
                os.environ[envar] = aws_kms_environment[envar]

    def kms_decrypt(self, encrypted_string, aws_kms_key_id ):
        encrypted_bytes_b64 = base64.b64decode( encrypted_string )
        kms_client = boto3.client('kms')
        response = kms_client.decrypt(CiphertextBlob=encrypted_bytes_b64, KeyId=aws_kms_key_id, EncryptionAlgorithm='RSAES_OAEP_SHA_256')
        return base64.b64encode((response['Plaintext']))

    # input_string: ""
    #     the string to decrypt. If it is prefixed with 'VAULT:' a decryption is attempted
    #     otherwise it is returned unchanged
    # aws_kms_environment: {}
    #     a dictionary containing the connection information for aws in their env var format
    #     {AWS_DEFAULT_REGION: "", AWS_ACCESS_KEY_ID: "", AWS_SECRET_ACCESS_KEY: "", AWS_KMS_KEY_ID: "", AWS_SESSION_TOKEN: ""}
    def decryptstring(self, input_sting, aws_kms_environment):
        self.test_input(input_sting, aws_kms_environment)
        output_sting = input_sting
        if output_sting.startswith("VAULT:"):
            self.set_environment(aws_kms_environment)
            decrypted_encoded_t = self.kms_decrypt(output_sting[6:], os.getenv('AWS_KMS_KEY_ID'))
            decrypted_decoded_t = base64.b64decode( decrypted_encoded_t )
            output_sting = str(decrypted_decoded_t, "utf-8")
        return output_sting