<!--
Copyright (C) 2025 Dremio Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
# OpenSSL Generated Test Resources

## Overview
This directory contains the following files:

* `rsa_private_key_pkcs8.pem` - RSA private key in PKCS#8 format (`BEGIN PRIVATE KEY`)
* `rsa_private_key_pkcs1.pem` - RSA private key in PKCS#1 format (`BEGIN RSA PRIVATE KEY`)
* `ecdsa_private_key.pem` - ECDSA private key (`BEGIN EC PRIVATE KEY`)
* `rsa_certificate.pem` - Self-signed certificate from RSA key with CN="test"
* `ecdsa_certificate.pem` - Self-signed certificate from ECDSA key with CN="test"

> [!WARNING]
> These files are generated using `openssl` and are for testing purposes only. They are NOT
> secure and should NOT be used in production!

## Commands Summary

```shell
# 1. Generate RSA private key in PKCS#8 format
openssl genpkey -algorithm RSA -out rsa_private_key_pkcs8.pem

# 2. Convert RSA key to PKCS#1 format
openssl rsa -in rsa_private_key_pkcs8.pem -traditional -out rsa_private_key_pkcs1.pem

# 3. Generate ECDSA private key (standard format with embedded parameters)
openssl ecparam -genkey -name prime256v1 -noout -out ecdsa_private_key.pem

# 4. Generate long-lived self-signed certificate from RSA key (100 years)
openssl req -new -x509 -key rsa_private_key_pkcs8.pem -out rsa_certificate.pem -days 36500 -subj "/CN=test"

# 5. Generate long-lived self-signed certificate from ECDSA key (100 years)
openssl req -new -x509 -key ecdsa_private_key.pem -out ecdsa_certificate.pem -days 36500 -subj "/CN=test"
```

Explanation:

* `-traditional` flag: Converts PKCS#8 format to PKCS#1 format (changes `BEGIN PRIVATE KEY` to `BEGIN RSA PRIVATE KEY`)
* `-noout` flag: embeds curve parameters within the private key section instead of creating separate `BEGIN EC PARAMETERS` section
* `prime256v1`: Uses the P-256 elliptic curve (most commonly used)
* `-subj "/CN=test"`: Sets the certificate Common Name without interactive prompts
