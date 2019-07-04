4#
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
from .base import BasePlugin
import click
import jmespath
import json
import re
from utils import get_matching_paths_from_zip

from pprint import pprint

# Regex pattern for the configuration file
CONFIG_FILE_PATTERN = re.compile(r'assets\/ADBMobileConfig\.json|ADBMobileConfig\.json|.*/ADBMobileConfig\.json')

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
            parsed_data = AdobeMobileSdkPlugin.parse_data(self.zip_file, path)

            # Check the SSL setting
            if AdobeMobileSdkPlugin.is_ssl_setting_vulnerable(parsed_data):
                click.echo('---- FOUND: The ["analytics"]["ssl"] setting is missing or false - SSL is not being used')

            # Check the POI URL
            poi_url = AdobeMobileSdkPlugin.get_vulnerable_poi_url(parsed_data)
            if poi_url:
                click.echo('---- FOUND: The ["remotes"]["analytics.poi"] URL doesn\'t use SSL: ' + poi_url)

            # Check the messages URL
            messages_url = AdobeMobileSdkPlugin.get_vulnerable_poi_url(parsed_data)
            if messages_url:
                click.echo('---- FOUND: The ["remotes"]["messages"] URL doesn\'t use SSL: ' + messages_url)

            # Checking postback URLs in the messages section
            postback_urls = AdobeMobileSdkPlugin.get_vulnerable_postback_urls(parsed_data)
            for url in postback_urls:
                click.echo('---- FOUND: A "templateurl" in ["messages"]["payload"] doesn\'t use SSL: ' + url)

    # Gets paths for the configuration file from the ZIP File
    @staticmethod
    def get_paths(zip_file):
        return get_matching_paths_from_zip(zip_file, CONFIG_FILE_PATTERN)

    # Parses the config file from a given path
    @staticmethod
    def parse_data(zip_file, path):
        data = zip_file.read(path)
        parsed_data = json.loads(data)
        return parsed_data

    # Checks if the SSL setting is present, and set to true, Otherwise, the default is false.
    @staticmethod
    def is_ssl_setting_vulnerable(parsed_data):
        ssl_setting = jmespath.search('analytics.ssl', parsed_data)
        if not ssl_setting:
            return True
        else:
            return False

    # Extracts and returns the POI URL if it is vulnerable
    @staticmethod
    def get_vulnerable_poi_url(parsed_data):
        poi_url = jmespath.search('remotes."analytics.poi"', parsed_data)
        if poi_url and not poi_url.strip().startswith('https://'):
            return poi_url
        else:
            return None

    # Extracts and returns the Messages URL if it is vulnerable
    @staticmethod
    def get_vulnerable_messages_url(parsed_data):
        messages_url = jmespath.search('remotes.messages', parsed_data)
        if messages_url and not messages_url.strip().startswith('https://'):
            return messages_url
        else:
            return None

    # Extracts and returns a list of vulnerable template URLs in the messages postbacks section.
    @staticmethod
    def get_vulnerable_postback_urls(parsed_data):
        vulnerable_urls = []
        postback_urls = jmespath.search('messages[].payload.templateurl', parsed_data)
        for url in postback_urls:
            if not url.strip().startswith('https://'):
                vulnerable_urls.append(url)

        return vulnerable_urls
