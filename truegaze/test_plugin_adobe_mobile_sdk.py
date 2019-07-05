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
import io
from zipfile import ZipFile

from truegaze.plugin_adobe_mobile_sdk import AdobeMobileSdkPlugin


# Tests for AdobeMobileSdkPlugin
# TODO: Add tests for click output
class TestAdobeMobileSdkPlugin(object):
    def test_plugin_properties_name_desc(self):
        plugin = AdobeMobileSdkPlugin({}, True, False)
        assert not plugin.name.startswith('Base')
        assert not plugin.desc.startswith('Base')

    def test_plugin_properties_support(self):
        assert AdobeMobileSdkPlugin.supports_android is True
        assert AdobeMobileSdkPlugin.supports_ios is True

    def test_check_support_is(self):
        plugin = AdobeMobileSdkPlugin({}, False, False)
        assert plugin.is_os_supported() is False
        plugin = AdobeMobileSdkPlugin({}, True, False)
        assert plugin.is_os_supported() is True
        plugin = AdobeMobileSdkPlugin({}, False, True)
        assert plugin.is_os_supported() is True
        plugin = AdobeMobileSdkPlugin({}, True, True)
        assert plugin.is_os_supported() is True


# Tests for the get_paths method
class TestAdobeMobileSdkPluginGetPaths(object):
    def test_empty(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        paths = AdobeMobileSdkPlugin.get_paths(zip_file)
        assert len(paths) == 0

    def test_valid_one_file(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        zip_file.writestr('assets/ADBMobileConfig.json', '')
        paths = AdobeMobileSdkPlugin.get_paths(zip_file)
        assert len(paths) == 1
        assert paths[0] == 'assets/ADBMobileConfig.json'

    def test_valid_three_files(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        zip_file.writestr('ADBMobileConfig.json', '')
        zip_file.writestr('test/ADBMobileConfig.doc', '')
        zip_file.writestr('test/ADBMobileConfig.json/test3.md', '')
        paths = AdobeMobileSdkPlugin.get_paths(zip_file)
        assert len(paths) == 2
        assert paths[0] == 'ADBMobileConfig.json'
        assert paths[1] == 'test/ADBMobileConfig.json'


# Tests for the parse_data method
class TestAdobeMobileSdkPluginParseData(object):
    def test_empty_file(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        zip_file.writestr('assets/ADBMobileConfig.json', '')
        data = AdobeMobileSdkPlugin.parse_data(zip_file, 'assets/ADBMobileConfig.json')
        assert data is None

    def test_junk_file(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        zip_file.writestr('assets/ADBMobileConfig.json', '<junky junk>')
        data = AdobeMobileSdkPlugin.parse_data(zip_file, 'assets/ADBMobileConfig.json')
        assert data is None

    def test_malformed_file(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        zip_file.writestr('assets/ADBMobileConfig.json', '{"welcome,')
        data = AdobeMobileSdkPlugin.parse_data(zip_file, 'assets/ADBMobileConfig.json')
        assert data is None

    def test_no_elements(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        zip_file.writestr('assets/ADBMobileConfig.json', '{}')
        data = AdobeMobileSdkPlugin.parse_data(zip_file, 'assets/ADBMobileConfig.json')
        assert len(data) == 0

    def test_valid_file(self):
        zip_file = ZipFile(io.BytesIO(), 'a')
        zip_file.writestr('assets/ADBMobileConfig.json', '{"test1": true, "test2": "str"}')
        data = AdobeMobileSdkPlugin.parse_data(zip_file, 'assets/ADBMobileConfig.json')
        assert bool(data) is not False
        assert len(data) == 2
        assert data['test1'] is True
        assert data['test2'] == 'str'


# Tests for the is_ssl_setting_correct method
class TestAdobeMobileSdkPluginIsSSLSettingCorrect(object):
    def test_empty(self):
        data = {}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is False

    def test_parent_present_setting_absent(self):
        data = {"analytics": {}}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is False

    def test_different_parent(self):
        data = {"othersection": {"ssl": True}}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is False

    def test_setting_present_but_false(self):
        data = {"analytics": {"ssl": False}}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is False

    def test_setting_present_but_not_boolean(self):
        data = {"analytics": {"ssl": "foobar"}}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is False

    def test_array(self):
        data = {"analytics": [{"ssl": True}, {"ssl": False}]}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is False

    def test_empty_element(self):
        data = {"analytics": {"ssl": ""}}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is False

    def test_valid(self):
        data = {"analytics": {"ssl": True}}
        assert AdobeMobileSdkPlugin.is_ssl_setting_correct(data) is True


# Tests for the get_vulnerable_poi_url method
class TestAdobeMobileSdkPluginGetVulnerablePoiUrl(object):
    def test_empty(self):
        data = {}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) is None

    def test_parent_present_setting_absent(self):
        data = {"remotes": {}}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) is None

    def test_different_parent(self):
        data = {"othersection": {"analytics.poi": 'http://www.example.com'}}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) is None

    def test_empty_element(self):
        data = {"othersection": {"analytics.poi": ''}}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) is None

    def test_setting_present_but_not_string(self):
        data = {"remotes": {"analytics.poi": False}}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) is None

    def test_array(self):
        data = {"remotes": [{"analytics.poi": 'http://www.example.com'}, {"analytics.poi1": 'http://www.example.com'}]}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) is None

    def test_not_vulnerable(self):
        data = {"remotes": {"analytics.poi": 'https://www.example.com'}}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) is None

    def test_is_vulnerable(self):
        data = {"remotes": {"analytics.poi": 'http://www.example.com'}}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) == 'http://www.example.com'

    def test_is_vulnerable_with_spaces(self):
        data = {"remotes": {"analytics.poi": '   http://www.example.com   '}}
        assert AdobeMobileSdkPlugin.get_vulnerable_poi_url(data) == 'http://www.example.com'


# Tests for the get_vulnerable_messages_url method
class TestAdobeMobileSdkPluginGetVulnerableMessagesUrl(object):
    def test_empty(self):
        data = {}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) is None

    def test_parent_present_setting_absent(self):
        data = {"remotes": {}}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) is None

    def test_different_parent(self):
        data = {"othersection": {"messages": 'http://www.example.com'}}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) is None

    def test_empty_element(self):
        data = {"othersection": {"messages": ''}}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) is None

    def test_setting_present_but_not_string(self):
        data = {"remotes": {"messages": False}}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) is None

    def test_array(self):
        data = {"remotes": [{"messages": 'http://www.example.com'}, {"messages1": 'http://www.example.com'}]}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) is None

    def test_not_vulnerable(self):
        data = {"remotes": {"messages": 'https://www.example.com'}}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) is None

    def test_is_vulnerable(self):
        data = {"remotes": {"messages": 'http://www.example.com'}}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) == 'http://www.example.com'

    def test_is_vulnerable_with_spaces(self):
        data = {"remotes": {"messages": '   http://www.example.com   '}}
        assert AdobeMobileSdkPlugin.get_vulnerable_messages_url(data) == 'http://www.example.com'


# Tests for the get_vulnerable_postback_urls method
class TestAdobeMobileSdkPluginGetVulnerablePostbackUrls(object):
    def test_empty(self):
        data = {}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_parent_present_setting_absent(self):
        data = {"messages": []}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_different_parent(self):
        data = {"othersection": [{"payload": {"templateurl": 'http://www.example.com'}}]}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_empty_payload(self):
        data = {"messages": [{"payload": ""}]}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_empty_element(self):
        data = {"messages": [{"payload": {"templateurl": ''}}]}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_setting_present_but_not_string(self):
        data = {"messages": [{"payload": {"templateurl": False}}]}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_not_vulnerable(self):
        data = {"messages": [{"payload": {"templateurl": 'https://www.example.com'}}]}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_not_vulnerable_multiple(self):
        data = {"messages": [
            {"payload": {"templateurl": 'https://www1.example.com'}},
            {"payload": {"templateurl": 'https://www2.example.com'}}
        ]}
        assert len(AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)) == 0

    def test_is_vulnerable(self):
        data = {"messages": [{"payload": {"templateurl": 'http://www.example.com'}}]}
        urls = AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)
        assert len(urls) == 1
        assert urls[0] == 'http://www.example.com'

    def test_is_vulnerable_some(self):
        data = {"messages": [
            {"payload": {"templateurl": 'https://www1.example.com'}},
            {"payload": {"templateurl": 'http://www2.example.com'}}
        ]}
        urls = AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)
        assert len(urls) == 1
        assert urls[0] == 'http://www2.example.com'

    def test_is_vulnerable_multiple(self):
        data = {"messages": [
            {"payload": {"templateurl": 'http://www1.example.com'}},
            {"payload": {"templateurl": 'http://www2.example.com'}}
        ]}
        urls = AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)
        assert len(urls) == 2
        assert urls[0] == 'http://www1.example.com'
        assert urls[1] == 'http://www2.example.com'

    def test_is_vulnerable_with_spaces(self):
        data = {"messages": [{"payload": {"templateurl": '     http://www.example.com    '}}]}
        urls = AdobeMobileSdkPlugin.get_vulnerable_postback_urls(data)
        assert len(urls) == 1
        assert urls[0] == 'http://www.example.com'
