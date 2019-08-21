#
# Copyright (c) 2019 Nightwatch Cybersecurity.
#
# This file is part of truegaze
# (see https://github.com/nightwatchcybersecurity/truegaze).
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
import re

from androguard.core.bytecodes.apk import APK
from asn1crypto import cms
from cryptography.hazmat.primitives.asymmetric import utils
import click
from roca.detect import RocaFingerprinter as Roca

from truegaze.plugins.base import BasePlugin

# Regex pattern for the configuration file
CERTIFICATE_FILE_PATTERN =\
    re.compile(r'META-INF/.*\.RSA|META-INF/.*\.DSA')


# Plugin to check for weak Android signing keys and signatures
class WeakKeyPlugin(BasePlugin):
    name = 'WeakKeyPlugin'
    desc = 'Detection of weak Android signing keys'
    supports_android = True
    supports_ios = False

    # Main scanning method
    def scan(self):
        # Open the file
        apk = APK(self.filename)

        # Get certificates
        unique_certs = WeakKeyPlugin.get_certificates(apk)
        if len(unique_certs) == 0:
            click.echo('-- Cannot find the any certificates in the APK File, skipping')
            return

        # Loop through the certificates and check for weak keys
        messages = list()
        messages.extend(WeakKeyPlugin.check_for_short_keys(unique_certs))
        messages.extend(WeakKeyPlugin.check_for_roca(unique_certs))

        # Check for weak DSA signatures
        signatures = WeakKeyPlugin.get_signatures(apk)
        if len(signatures) > 1:
            messages = WeakKeyPlugin.check_for_weak_signatures(signatures)

        # Show results if needed
        if len(messages) > 0:
            click.echo("-- Found " + str(len(messages)) + ' issues')
            for message in messages:
                click.echo(message)
        else:
            click.echo("-- No issues found")

    # Get a list of certificates from the apk
    # TODO: add tests
    @staticmethod
    def get_certificates(apk):
        all_certs = list()
        all_certs.extend(apk.get_certificates_v1())
        all_certs.extend(apk.get_certificates_v2())
        all_certs.extend(apk.get_certificates_v3())

        unique_certs = dict()
        for cert in all_certs:
            unique_certs[cert.sha256_fingerprint] = cert

        return unique_certs.values()

    # Get a list of DSA/ECDSA signatures from the APK file
    # TODO: add tests
    @staticmethod
    def get_signatures(apk):
        signatures = list()
        certs_v1 = apk.get_certificates_v1()
        for x in range(len(certs_v1)):
            if certs_v1[x].public_key.algorithm == 'dsa' or certs_v1[x].public_key.algorithm == 'ecdsa':
                data = cms.ContentInfo.load(apk.get_signatures()[x])
                signatures.append(data['content']['signer_infos'][0]['signature'].contents)

        if apk._is_signed_v2:
            certs_v2 = apk.get_certificates_v2()
            for x in range(len(certs_v2)):
                if certs_v2[x].public_key.algorithm == 'dsa' or certs_v1[x].public_key.algorithm == 'ecdsa':
                    signatures.append(apk._v2_signing_data[x].signatures[0][1])

        if apk._is_signed_v3:
            certs_v3 = apk.get_certificates_v3()
            for x in range(len(certs_v3)):
                if certs_v3[x].public_key.algorithm == 'dsa' or certs_v1[x].public_key.algorithm == 'ecdsa':
                    signatures.append(apk._v3_signing_data[x].signatures[0][1])

        return signatures

    # Check for short keys
    # TODO: add tests
    @staticmethod
    def check_for_short_keys(certs):
        messages = []
        for cert in certs:
            if (cert.public_key.algorithm == 'rsa' and cert.public_key.bit_size < 2048) or \
                    (cert.public_key.algorithm == 'dsa' and cert.public_key.bit_size < 2048) or \
                    (cert.public_key.algorithm == 'ecdsa' and cert.public_key.bit_size < 224):
                messages.append('---- ISSUE (' +
                                'algorithm: ' + cert.public_key.algorithm +
                                ', fingerprint: ' + cert.sha1_fingerprint.replace(' ', '') +
                                '): Key is less than 2048 bits, size is ' + str(cert.public_key.bit_size) + ' bits')
        return messages

    # Check for ROCA attacks
    # TODO: add tests
    @staticmethod
    def check_for_roca(certs):
        messages = []
        for cert in certs:
            if cert.public_key.algorithm == 'rsa':
                modulus = cert.public_key.native['public_key']['modulus']
                if Roca().has_fingerprint_moduli(modulus) or Roca().has_fingerprint_dlog(modulus):
                    messages.append('---- ISSUE (' +
                                    'algorithm: ' + cert.public_key.algorithm +
                                    ', fingerprint: ' + cert.sha1_fingerprint.replace(' ', '') +
                                    '): Key vulnerable to ROCA attack - see https://roca.crocs.fi.muni.cz/')

        return messages

    # Check for weak DSA/ECDSA signatures
    # TODO: add tests
    @staticmethod
    def check_for_weak_signatures(signatures):
        messages = []

        # Extra r values from signatures
        values = list()
        for signature in signatures:
            (r, s) = utils.decode_dss_signature(signature)
            values.append(r)

        # Check if any appear more than once
        for r in values:
            if values.count(r) > 1:
                messages.append('---- ISSUE: DSA "r" value occurs more than once, private key is recoverable; k = ' + r)

        return messages
