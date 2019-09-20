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
from androguard.core.bytecodes.apk import APK
import click
import requests
import tldextract

from truegaze.plugins.base import BasePlugin


# TODO: Add iOS support
# Plugin to check for insecure Firebase databases and GCP storage buckets
class FirebasePlugin(BasePlugin):
    name = 'FirebasePlugin'
    desc = 'Detection of insecure Firebase databases and GCP storage buckets'
    supports_android = True
    supports_ios = False
    supports_online = True

    # Main scanning method
    def scan(self):
        # Open the file
        apk = APK(self.filename)

        # If online check is disabled then skip
        if not self.is_online_testing_supported():
            click.echo('-- Online tests are disabled, skipping check...')
            return

        # Get the Firebase URL
        db_name = FirebasePlugin.get_db_name(apk)
        if db_name:
            click.echo('Found Firebase database: ' + db_name + ', checking if the database/bucket are accessible...')
        else:
            click.echo('-- No Firebase database found, skipping...')
            return

        # Check if the database and bucket are accessible
        messages = list()
        messages.append(FirebasePlugin.check_firebase_db(db_name))
        messages.append(FirebasePlugin.check_bucket(db_name))
        messages = list(filter(None, messages))

        # Show results if needed
        if len(messages) > 0:
            click.echo("-- Found " + str(len(messages)) + ' issues')
            for message in messages:
                click.echo(message)
        else:
            click.echo("-- No issues found")

    # Get the firebase URL from the APK
    # TODO: add tests
    @staticmethod
    def get_db_name(apk):
        res = apk.get_android_resources().get_string(apk.package, 'firebase_database_url')
        if res is not None:
            url = res[1]
            return tldextract.extract(url).subdomain

        return None

    # Check if the Firebase database is accessible
    @staticmethod
    def check_firebase_db(db_name):
        url = 'https://' + db_name + '.firebaseio.com/.json'
        res = requests.get(url, stream=True)
        if res.status_code == 200:
            return '---- ISSUE: Unprotected Firebase DB found - ' + url

        return None

    # Check if the bucket is accessible
    @staticmethod
    def check_bucket(db_name):
        url = 'https://storage.googleapis.com/' + db_name + '.appspot.com'
        res = requests.head(url)
        if res.status_code == 200:
            return '---- ISSUE: Unprotected bucket found - ' + url

        return None