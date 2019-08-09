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
import json
import re

import click
from OpenSSL import crypto
from roca.detect import RocaFingerprinter as Roca

from truegaze.plugins.base import BasePlugin
from truegaze.utils import TruegazeUtils

# Regex pattern for the configuration file
CERTIFICATE_FILE_PATTERN =\
    re.compile(r'META-INF/.*\.RSA')


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
        # Search all paths for the certificate files
        paths = WeakKeyPlugin.get_paths(self.zip_file)
        if len(paths) == 0:
            click.echo('-- Cannot find the any *.RSA files in the META-INF folder, skipping')
            return

        # Loop through files, parse the JSON and analyze
        click.echo('-- Found ' + str(len(paths)) + ' certificate file(s)')
        for path in paths:
            click.echo('-- Scanning "' + path + "'")

            # Try to parse the data
            certs = WeakKeyPlugin.parse_data(self.zip_file, path)
            if len(certs) == 0:
                click.echo('---- ERROR: Unable to certificate file - will skip. File: ' + path)
                continue

            # Validate the certificates
            messages = WeakKeyPlugin.validate(certs)
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

    # Gets the certificate file from a given path and converts to x509
    @staticmethod
    def parse_data(zip_file, path):
        cert = []
        data = zip_file.read(path)
        try:
            # Android uses PKCS7, we must load it that way then convert to X.509
            pkcs7_data = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, data)
            certs = TruegazeUtils.get_certificates_from_pkcs7(pkcs7_data)
        except TypeError:
            return None
        return certs

    # Validates certificates for any weaknesses
    @staticmethod
    def validate(certs):
        messages = []
        for cert in certs:
            key = cert.get_pubkey().to_cryptography_key()

            # Check for small key size
            if key.key_size < 2048:
                messages.append('---- ISSUE: Key is less than 2048 bits, actual size is ' + str(key.key_size) + ' bits')

            # Check for ROCA attack
            numbers = key.public_numbers()
            click.echo("Exponent: " + str(numbers.e))
            click.echo("Modulus: " + str(numbers.n))
            if Roca().has_fingerprint_moduli(numbers.n) or Roca().has_fingerprint_dlog(numbers.n):
                messages.append('---- ISSUE: Key vulnerable to ROCA attack - see https://roca.crocs.fi.muni.cz/')

        return messages


