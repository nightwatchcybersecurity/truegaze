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

        # Get Firebase URL and derive the bucket name
        db_url = FirebasePlugin.get_db_url(apk)
        if db_url:
            bucket_name = tldextract.extract(db_url).subdomain + '.appspot.com'
            click.echo('Found Firebase URL: ' + db_url + ', bucket name: ' + bucket_name)



        # If online check is disabled then skip
        if not self.is_online_testing_supported():
            click.echo('-- Online tests are disabled, skipping check...')
            return

        # Do a GET request to check if the database is accessible
        res1 = requests.get(db_url + '/.json', stream=True)


        # Do a HEAD request to check if the storage bucket is accessible
        res2 = requests.head('https://storage.googleapis.com/' + bucket_name)
        pass

        # unique_certs = WeakKeyPlugin.get_certificates(apk)
        # if len(unique_certs) == 0:
        #     click.echo('-- Cannot find the any certificates in the APK File, skipping')
        #     return
        #
        # # Loop through the certificates and check for weak keys
        # messages = list()
        # messages.extend(WeakKeyPlugin.check_for_short_keys(unique_certs))
        # messages.extend(WeakKeyPlugin.check_for_roca(unique_certs))
        #
        # # Check for weak DSA signatures
        # signatures = WeakKeyPlugin.get_signatures(apk)
        # if len(signatures) > 1:
        #     messages = WeakKeyPlugin.check_for_weak_signatures(signatures)
        #
        # # Show results if needed
        # if len(messages) > 0:
        #     click.echo("-- Found " + str(len(messages)) + ' issues')
        #     for message in messages:
        #         click.echo(message)
        # else:
        #     click.echo("-- No issues found")

    # Get the firebase URL from the APK
    # TODO: add tests
    @staticmethod
    def get_db_url(apk):
        res = apk.get_android_resources().get_string(apk.package, 'firebase_database_url')
        if res is not None:
            return res[1]

        return None
