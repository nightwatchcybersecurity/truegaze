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
import jmespath
from jsonschema.validators import validator_for

from truegaze.plugins.base import BasePlugin
from truegaze.utils import TruegazeUtils

# Regex pattern for the configuration file
CONFIG_FILE_PATTERN =\
    re.compile(r'assets/ADBMobileConfig\.json|ADBMobileConfig\.json|.*/ADBMobileConfig\.json')


#
# Plugin to support detection of incorrect SSL configuration in the Adobe Mobile SDK. This plugin will not
# search for config files that are not named in a standard fashion.
#
# Adobe documentation including field definitions can be found here:
# https://docs.adobe.com/content/help/en/mobile-services/android/configuration-android/json-config.html
# https://docs.adobe.com/content/help/en/mobile-services/ios/config-ios/json-config.html
#


class AdobeMobileSdkPlugin(BasePlugin):
    name = 'AdobeMobileSdk'
    desc = 'Detection of incorrect SSL configuration\nin the Adobe Mobile SDK'
    supports_android = True
    supports_ios = True

    # Main scanning method
    def scan(self):
        # On Android, the config file is usually in the assets folder but can be placed elsewhere.
        # On iOS the configuration file can be anywhere.

        # Search all paths for the config file
        paths = AdobeMobileSdkPlugin.get_paths(self.zip_file)
        if len(paths) == 0:
            click.echo('-- Cannot find the "ADBMobileConfig.json" file, skipping')
            return

        # Loop through files, parse the JSON and analyze
        click.echo('-- Found ' + str(len(paths)) + ' configuration file(s)')
        for path in paths:
            click.echo('-- Scanning "' + path + "'")

            # Try to parse the data
            parsed_data = AdobeMobileSdkPlugin.parse_data(self.zip_file, path)
            if not parsed_data:
                click.echo('---- ERROR: Unable to parse config file - will skip. File: ' + path)
                continue

            # Validate the file
            messages = AdobeMobileSdkPlugin.validate(parsed_data)
            if len(messages) > 0:
                click.echo("-- Found " + str(len(messages)) + ' issues')
                for message in messages:
                    click.echo(message)
            else:
                click.echo("-- No issues found")

    # Gets paths for the configuration file from the ZIP File
    @staticmethod
    def get_paths(zip_file):
        return TruegazeUtils.get_matching_paths_from_zip(zip_file, CONFIG_FILE_PATTERN)

    # Parses the config file from a given path
    @staticmethod
    def parse_data(zip_file, path):
        data = zip_file.read(path)
        try:
            parsed_data = json.loads(data.decode())
        except json.JSONDecodeError:
            return None
        return parsed_data

    # Validates the config file against the JSON schema
    @staticmethod
    def validate(parsed_data):
        # Load the schema
        schema_file = open('rules/adobe_mobile_sdk.schema', 'r')
        schema_data = json.load(schema_file)

        # Validate the file
        validator = validator_for(schema_data)
        errors = validator(schema=schema_data).iter_errors(parsed_data)

        # Extract error messages and return
        messages = []
        for error in errors:
            messages.append('---- ISSUE: ' + error.schema['title'] + '; ' + error.message)
        return messages
