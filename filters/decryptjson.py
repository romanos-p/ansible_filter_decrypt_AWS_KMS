#!/usr/bin/python3
#
# Filter to recursively decrypt json objects using AWS KMS
import boto3, base64, argparse, os, json
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
            'decryptjson': self.decryptjson
        }

    def test_input(self, input_json, aws_kms_environment):
        if type(input_json) is not list and type(input_json) is not dict:
            raise Exception("The first argument must be a list or dictionary. Not " + str(type(input_json)))
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


    def decryptrecurse(self, input_item, aws_kms_key_id):
        if type(input_item) is list:
            output_item = []
            for item in input_item:
                output_item += [self.decryptrecurse(item, aws_kms_key_id)]
            return output_item
        elif type(input_item) is dict:
            output_item = {}
            for item in input_item:
                output_item[item] = self.decryptrecurse(input_item[item], aws_kms_key_id)
            return output_item
        elif type(input_item) is str and input_item.startswith("VAULT:"):
            decrypted_encoded_t = self.kms_decrypt(input_item[6:], aws_kms_key_id)
            decrypted_decoded_t = base64.b64decode( decrypted_encoded_t )
            return str(decrypted_decoded_t, "utf-8")
        else:
            return input_item

    # input_json: ""
    #     the json string to decrypt values of. If a string is prefixed with 'VAULT:' a decryption is attempted
    #     otherwise it is returned unchanged
    # aws_kms_environment: {}
    #     a dictionary containing the connection information for aws in their env var format
    #     {AWS_DEFAULT_REGION: "", AWS_ACCESS_KEY_ID: "", AWS_SECRET_ACCESS_KEY: "", AWS_KMS_KEY_ID: "", [AWS_SESSION_TOKEN: ""]}
    def decryptjson(self, input_json, aws_kms_environment):
        self.test_input(input_json, aws_kms_environment)
        self.set_environment(aws_kms_environment)
        return self.decryptrecurse(input_json, os.getenv('AWS_KMS_KEY_ID'))
