# Ansible Filter 
A set of 3 ansible filters to decrypt json objects (recursively), lists and strings using a key saved in AWS KMS.

## Use Case
Some data about your infrastructure is stored in a mongoDB including some sensitive pieces of information.\
This could be data describing a website and the sensitive data credentials for AWS S3 and a MySQL database.\
Using ansible vault would be a problem because you also use this data in a web app where users can view and update site information.

## Contents
```
filters\                # contains the 3 custom ansible filters
  |_decryptjson.py      # filter to recursively decrypt entire json objects
  |_decryptlist.py      # filter to decrypt strings in a list
  |_decryptstring.py    # filter to decrypt a string
ansible_example.yml     # example playbook using the filters
kms_crypt.py            # python cli tool to encrypt and decrypt strings
```

## Requirements
python3
python modules:
  - botocore
  - boto3
  - ansible-core
  - ansible
AWS account with an asymmetric key pair in KMS
AWS access credentials with permissions to kms:ListKeys, kms:Encrypt, kms:Decrypt.

## Setup & Notes
The key used is an RSA anymetric key pair. The encryption algorithm is RSAES-OAEP with SHA256 for the MGF and hash function.\
If using the public key locally to encrypt a string with the `kms_crypt.py` tool, the key must be in PEM format.\
The encrypted strings need to be prefixed with 'VAULT:' so they can be quickly identified by the filter.\
A dictionary containing the AWS connection information must be defined in ansible vault so it can be used by the filter.\
The variable should use this format:
```yaml
aws_kms_environment:
  AWS_DEFAULT_REGION: ""
  AWS_ACCESS_KEY_ID: ""
  AWS_SECRET_ACCESS_KEY: ""
  AWS_KMS_KEY_ID: ""
  AWS_SESSION_TOKEN: ""
```
In your `ansible.cfg` file, make sure to point to the directory containing these filters:
```
filter_plugins = ./filters/
```

## Example 1

1. Create the RSA key pair in AWS KMS and download the public key in PEM format for faster local encryption.
2. Encrypt your secret string using the included cli tool: `python3 kms_crypt.py --encrypt "foo" --public-key ./id_rsa.pub`
3. You could now test your work with this playbook:
```yml
---
- hosts: localhost
  gather_facts: false
  vars:
    kmsenv:
      AWS_DEFAULT_REGION: ""
      AWS_ACCESS_KEY_ID: ""
      AWS_SECRET_ACCESS_KEY: ""
      AWS_KMS_KEY_ID: ""
      AWS_SESSION_TOKEN: ""
    secret: 'bWdpkjm...MgiXF+Af'
  tasks:
    - name: Decrypt secret
      debug:
        msg: "shhhhh: {{ secret | decryptstring(kmsenv) }}"
```

## Example 2

1. Create the RSA key pair in AWS KMS.
2. Encrypt your secret string using the included cli tool: `python3 kms_crypt.py --encrypt "foo" --kms-key-id "123"`
3. Create your json object:
```json
{
    "_id": 1, 
    "name": "bob",
    "secret": "bWdpkjm...MgiXF+Af"
}
```
4. Push it to your mongodb.
5. Create a vault file for the AWS KMS credentials: `ansible-vault create aws-creds/kms_vault.yml`
6. Add the following dictionary inside:
```yml
aws_kms_user_envars:
  AWS_DEFAULT_REGION: ""
  AWS_ACCESS_KEY_ID: ""
  AWS_SECRET_ACCESS_KEY: ""
  AWS_KMS_KEY_ID: ""
  AWS_SESSION_TOKEN: ""
```
7. You should do something similar for the mondodb credentials but for this example you can put them in `vars` section of the `ansible_example.yml` playbook. 
8. Run the playbook with: `ansible-playbook ansible_example.yml -i "localhost,"`
