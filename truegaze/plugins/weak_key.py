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
import click
from roca.detect import RocaFingerprinter as Roca

from truegaze.plugins.base import BasePlugin
from truegaze.utils import TruegazeUtils

# Regex pattern for the configuration file
CERTIFICATE_FILE_PATTERN =\
    re.compile(r'META-INF/.*\.RSA|META-INF/.*\.DSA')


#
# Plugin to support weak Android signing keys
#
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

        # Loop through the certificates and validate
        messages = list()
        messages.extend(WeakKeyPlugin.check_for_short_keys(unique_certs))
        messages.extend(WeakKeyPlugin.check_for_roca(unique_certs))
        if len(messages) > 0:
            click.echo("-- Found " + str(len(messages)) + ' issues')
            for message in messages:
                click.echo(message)
        else:
            click.echo("-- No issues found")

    # Gets paths for the certificate files from the ZIP File
    @staticmethod
    def get_paths(zip_file):
        return TruegazeUtils.get_matching_paths_from_zip(zip_file, CERTIFICATE_FILE_PATTERN)

    # Get a list of certificates from the apk
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

    # Check for short keys
    @staticmethod
    def check_for_short_keys(certs):
        messages = []
        for cert in certs:
            # Check for small key size (DSA and RSA only, ECC keys are usually small)
            if cert.public_key.algorithm == 'rsa' or cert.public_key.algorithm == 'dsa':
                if cert.public_key.bit_size < 2048:
                    messages.append('---- ISSUE (' +
                                    'algorithm: ' + cert.public_key.algorithm +
                                    ', fingerprint: ' + cert.sha1_fingerprint.replace(' ', '') +
                                    '): Key is less than 2048 bits, size is ' + str(cert.public_key.bit_size) + ' bits')
        return messages

    # Check for ROCA attacks
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

