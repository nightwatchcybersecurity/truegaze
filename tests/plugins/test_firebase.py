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
from truegaze.plugins.firebase import FirebasePlugin


# Tests for FirebasePlugin
# TODO: Add tests for click output
class TestFirebasePlugin(object):
    def test_plugin_properties_name_desc(self):
        plugin = FirebasePlugin({}, is_android=True, is_ios=False, do_online=False)
        assert not plugin.name.startswith('Base')
        assert not plugin.desc.startswith('Base')

    def test_plugin_properties_support(self):
        assert FirebasePlugin.supports_android is True
        assert FirebasePlugin.supports_ios is False
        assert FirebasePlugin.supports_online is True

    def test_is_os_supported(self):
        plugin = FirebasePlugin({}, is_android=False, is_ios=False, do_online=False)
        assert plugin.is_os_supported() is False
        plugin = FirebasePlugin({}, is_android=True, is_ios=False, do_online=False)
        assert plugin.is_os_supported() is True
        plugin = FirebasePlugin({}, is_android=False, is_ios=True, do_online=False)
        assert plugin.is_os_supported() is False
        plugin = FirebasePlugin({}, is_android=True, is_ios=True, do_online=False)
        assert plugin.is_os_supported() is True

    def test_is_online_testing_supported(self):
        plugin = FirebasePlugin({}, is_android=False, is_ios=False, do_online=False)
        assert plugin.is_online_testing_supported() is False
        plugin = FirebasePlugin({}, is_android=False, is_ios=False, do_online=True)
        assert plugin.is_online_testing_supported() is True


class TestFirebasePluginCheckFirebaseDb(object):
    def test_check_firebase_db_valid(self, requests_mock):
        db_name = 'test'
        requests_mock.get('https://' + db_name + '.firebaseio.com/.json', status_code=200)
        message = FirebasePlugin.check_firebase_db(db_name)
        assert message == '---- ISSUE: Unprotected Firebase DB found - https://' + db_name + '.firebaseio.com/.json'

    def test_check_firebase_db_error(self, requests_mock):
        db_name = 'test'
        requests_mock.get('https://' + db_name + '.firebaseio.com/.json', status_code=500)
        message = FirebasePlugin.check_firebase_db(db_name)
        assert message is None

    def test_check_firebase_db_access_denied(self, requests_mock):
        db_name = 'test'
        requests_mock.get('https://' + db_name + '.firebaseio.com/.json', status_code=401)
        message = FirebasePlugin.check_firebase_db(db_name)
        assert message is None

    def test_check_firebase_db_not_found(self, requests_mock):
        db_name = 'test'
        requests_mock.get('https://' + db_name + '.firebaseio.com/.json', status_code=404)
        message = FirebasePlugin.check_firebase_db(db_name)
        assert message is None

    def test_check_firebase_db_redirect(self, requests_mock):
        db_name = 'test'
        requests_mock.get('https://' + db_name + '.firebaseio.com/.json', status_code=301)
        message = FirebasePlugin.check_firebase_db(db_name)
        assert message is None


class TestFirebasePluginCheckBucket(object):
    def test_check_bucket_valid(self, requests_mock):
        db_name = 'test'
        requests_mock.head('https://storage.googleapis.com/' + db_name + '.appspot.com', status_code=200)
        message = FirebasePlugin.check_bucket(db_name)
        assert message == '---- ISSUE: Unprotected bucket found - https://storage.googleapis.com/'\
               + db_name + '.appspot.com'

    def test_check_bucket_error(self, requests_mock):
        db_name = 'test'
        requests_mock.head('https://storage.googleapis.com/' + db_name + '.appspot.com', status_code=500)
        message = FirebasePlugin.check_bucket(db_name)
        assert message is None

    def test_check_bucket_access_denied(self, requests_mock):
        db_name = 'test'
        requests_mock.head('https://storage.googleapis.com/' + db_name + '.appspot.com', status_code=401)
        message = FirebasePlugin.check_bucket(db_name)
        assert message is None

    def test_check_bucket_not_found(self, requests_mock):
        db_name = 'test'
        requests_mock.head('https://storage.googleapis.com/' + db_name + '.appspot.com', status_code=404)
        message = FirebasePlugin.check_bucket(db_name)
        assert message is None

    def test_check_bucket_redirect(self, requests_mock):
        db_name = 'test'
        requests_mock.head('https://storage.googleapis.com/' + db_name + '.appspot.com', status_code=301)
        message = FirebasePlugin.check_bucket(db_name)
        assert message is None