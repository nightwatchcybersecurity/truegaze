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

from truegaze.plugins.adobe_mobile_sdk import AdobeMobileSdkPlugin


# Tests for AdobeMobileSdkPlugin
# TODO: Add tests for click output
class TestAdobeMobileSdkPlugin(object):
    def test_plugin_properties_name_desc(self):
        plugin = AdobeMobileSdkPlugin({}, is_android=True, is_ios=False, do_online=False)
        assert not plugin.name.startswith('Base')
        assert not plugin.desc.startswith('Base')

    def test_plugin_properties_support(self):
        assert AdobeMobileSdkPlugin.supports_android is True
        assert AdobeMobileSdkPlugin.supports_ios is True
        assert AdobeMobileSdkPlugin.supports_online is False

    def test_is_os_supported(self):
        plugin = AdobeMobileSdkPlugin({}, is_android=False, is_ios=False, do_online=False)
        assert plugin.is_os_supported() is False
        plugin = AdobeMobileSdkPlugin({}, is_android=True, is_ios=False, do_online=False)
        assert plugin.is_os_supported() is True
        plugin = AdobeMobileSdkPlugin({}, is_android=False, is_ios=True, do_online=False)
        assert plugin.is_os_supported() is True
        plugin = AdobeMobileSdkPlugin({}, is_android=True, is_ios=True, do_online=False)
        assert plugin.is_os_supported() is True

    def test_is_online_testing_supported(self):
        plugin = AdobeMobileSdkPlugin({}, is_android=False, is_ios=False, do_online=False)
        assert plugin.is_online_testing_supported() is False
        plugin = AdobeMobileSdkPlugin({}, is_android=False, is_ios=False, do_online=True)
        assert plugin.is_online_testing_supported() is False


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


# Testing validation - analytics / ssl setting
class TestAdobeMobileSdkPluginIsSSLSettingCorrect(object):
    def test_empty(self):
        data = {}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: Schema for checking security settings of the Adobe Mobile SDK configuration files; \'analytics\' is a required property'

    def test_parent_present_setting_absent(self):
        data = {"analytics": {}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The Analytics Schema requires the SSL setting; \'ssl\' is a required property'

    def test_different_parent(self):
        data = {"othersection": {"ssl": True}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: Schema for checking security settings of the Adobe Mobile SDK configuration files; \'analytics\' is a required property'

    def test_setting_present_but_false(self):
        data = {"analytics": {"ssl": False}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["analytics"]["ssl"] setting is missing or false - SSL is not being used; True was expected'

    def test_setting_present_but_not_boolean(self):
        data = {"analytics": {"ssl": "foobar"}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 2
        assert(messages[0]) == '---- ISSUE: The [\"analytics\"][\"ssl\"] setting is missing or false - SSL is not being used; \'foobar\' is not of type \'boolean\''
        assert(messages[1]) == '---- ISSUE: The ["analytics"]["ssl"] setting is missing or false - SSL is not being used; True was expected'

    def test_array(self):
        data = {"analytics": [{"ssl": True}, {"ssl": False}]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The Analytics Schema requires the SSL setting; [{\'ssl\': True}, {\'ssl\': False}] is not of type \'object\''

    def test_empty_element(self):
        data = {"analytics": {"ssl": ""}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 2
        assert(messages[0]) == '---- ISSUE: The ["analytics"]["ssl"] setting is missing or false - SSL is not being used; \'\' is not of type \'boolean\''
        assert(messages[1]) == '---- ISSUE: The ["analytics"]["ssl"] setting is missing or false - SSL is not being used; True was expected'

    def test_valid(self):
        data = {"analytics": {"ssl": True}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0


# Testing validation - mediaHeartbeat / ssl setting
class TestAdobeMobileSdkPluginIsMediaHeartbeatSSLSettingCorrect(object):
    def test_parent_present_setting_absent(self):
        data = {"analytics": {"ssl": True}, "mediaHeartbeat": {}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The MediaHeartbeat Schema requires the SSL setting; \'ssl\' is a required property'

    def test_different_parent(self):
        data = {"analytics": {"ssl": True}, "othersection": {"ssl": True}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_setting_present_but_false(self):
        data = {"analytics": {"ssl": True}, "mediaHeartbeat": {"ssl": False}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["mediaHeartbeat"]["ssl"] setting is missing or false - SSL is not being used; True was expected'

    def test_setting_present_but_not_boolean(self):
        data = {"analytics": {"ssl": True}, "mediaHeartbeat": {"ssl": "foobar"}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 2
        assert(messages[0]) == '---- ISSUE: The [\"mediaHeartbeat\"][\"ssl\"] setting is missing or false - SSL is not being used; \'foobar\' is not of type \'boolean\''
        assert(messages[1]) == '---- ISSUE: The ["mediaHeartbeat"]["ssl"] setting is missing or false - SSL is not being used; True was expected'

    def test_array(self):
        data = {"analytics": {"ssl": True}, "mediaHeartbeat": [{"ssl": True}, {"ssl": False}]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The MediaHeartbeat Schema requires the SSL setting; [{\'ssl\': True}, {\'ssl\': False}] is not of type \'object\''

    def test_empty_element(self):
        data = {"analytics": {"ssl": True}, "mediaHeartbeat": {"ssl": ""}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 2
        assert(messages[0]) == '---- ISSUE: The ["mediaHeartbeat"]["ssl"] setting is missing or false - SSL is not being used; \'\' is not of type \'boolean\''
        assert(messages[1]) == '---- ISSUE: The ["mediaHeartbeat"]["ssl"] setting is missing or false - SSL is not being used; True was expected'

    def test_valid(self):
        data = {"analytics": {"ssl": True}, "mediaHeartbeat": {"ssl": True}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0


# Testing validation - remotes / analytics.poi setting
class TestAdobeMobileSdkPluginHasVulnerablePoiUrl(object):
    def test_parent_present_setting_absent(self):
        data = {"analytics": {"ssl": True}, "remotes": {}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_different_parent(self):
        data = {"analytics": {"ssl": True}, "othersection": {"analytics.poi": 'http://www.example.com'}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_empty_element(self):
        data = {"analytics": {"ssl": True}, "othersection": {"analytics.poi": ''}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_setting_present_but_not_string(self):
        data = {"analytics": {"ssl": True}, "remotes": {"analytics.poi": False}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["remotes"]["analytics.poi"] URL doesn\\\'t use SSL; False is not of type \'string\''

    def test_array(self):
        data = {"analytics": {"ssl": True}, "remotes": [
            {"analytics.poi": 'http://www.example.com'},
            {"analytics.poi1": 'http://www.example.com'}
        ]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The Remotes Schema; [{\'analytics.poi\': \'http://www.example.com\'}, {\'analytics.poi1\': \'http://www.example.com\'}] is not of type \'object\''

    def test_not_vulnerable(self):
        data = {"analytics": {"ssl": True}, "remotes": {"analytics.poi": 'https://www.example.com'}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_is_vulnerable(self):
        data = {"analytics": {"ssl": True}, "remotes": {"analytics.poi": 'http://www.example.com'}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["remotes"]["analytics.poi"] URL doesn\\\'t use SSL; \'http://www.example.com\' does not match \'^https://(.*)$\''

    def test_is_vulnerable_with_spaces(self):
        data = {"analytics": {"ssl": True}, "remotes": {"analytics.poi": '   http://www.example.com   '}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["remotes"]["analytics.poi"] URL doesn\\\'t use SSL; \'   http://www.example.com   \' does not match \'^https://(.*)$\''


# Testing validation - remotes / messages setting
class TestAdobeMobileSdkPluginHasVulnerableMessagesUrl(object):
    def test_parent_present_setting_absent(self):
        data = {"analytics": {"ssl": True}, "remotes": {}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_different_parent(self):
        data = {"analytics": {"ssl": True}, "othersection": {"messages": 'http://www.example.com'}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_empty_element(self):
        data = {"analytics": {"ssl": True}, "othersection": {"messages": ''}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_setting_present_but_not_string(self):
        data = {"analytics": {"ssl": True}, "remotes": {"messages": False}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["remotes"]["messages"] URL doesn\\\'t use SSL; False is not of type \'string\''

    def test_array(self):
        data = {"analytics": {"ssl": True}, "remotes": [
            {"messages": 'http://www.example.com'},
            {"messages1": 'http://www.example.com'}
        ]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The Remotes Schema; [{\'messages\': \'http://www.example.com\'}, {\'messages1\': \'http://www.example.com\'}] is not of type \'object\''

    def test_not_vulnerable(self):
        data = {"analytics": {"ssl": True}, "remotes": {"messages": 'https://www.example.com'}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_is_vulnerable(self):
        data = {"analytics": {"ssl": True}, "remotes": {"messages": 'http://www.example.com'}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["remotes"]["messages"] URL doesn\\\'t use SSL; \'http://www.example.com\' does not match \'^https://(.*)$\''

    def test_is_vulnerable_with_spaces(self):
        data = {"analytics": {"ssl": True}, "remotes": {"messages": '   http://www.example.com   '}}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: The ["remotes"]["messages"] URL doesn\\\'t use SSL; \'   http://www.example.com   \' does not match \'^https://(.*)$\''


# Testing validation - vulnerable postback URLs
class TestAdobeMobileSdkPluginHasVulnerablePostbackUrls(object):
    def test_parent_present_setting_absent(self):
        data = {"analytics": {"ssl": True}, "messages": []}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_different_parent(self):
        data = {"analytics": {"ssl": True}, "othersection": [{"payload": {"templateurl": 'http://www.example.com'}}]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_empty_element(self):
        data = {"analytics": {"ssl": True}, "messages": [{"payload": {"templateurl": ''}}]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: A "templateurl" in ["messages"]["payload"] doesn\\\'t use SSL; \'\' does not match \'^https://(.*)$\''

    def test_setting_present_but_not_string(self):
        data = {"analytics": {"ssl": True}, "messages": [{"payload": {"templateurl": False}}]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: A "templateurl" in ["messages"]["payload"] doesn\\\'t use SSL; False is not of type \'string\''

    def test_not_vulnerable(self):
        data = {"analytics": {"ssl": True}, "messages": [{"payload": {"templateurl": 'https://www.example.com'}}]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_not_vulnerable_multiple(self):
        data = {"analytics": {"ssl": True}, "messages": [
            {"payload": {"templateurl": 'https://www1.example.com'}},
            {"payload": {"templateurl": 'https://www2.example.com'}}
        ]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 0

    def test_is_vulnerable(self):
        data = {"analytics": {"ssl": True}, "messages": [{"payload": {"templateurl": 'http://www.example.com'}}]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: A "templateurl" in ["messages"]["payload"] doesn\\\'t use SSL; \'http://www.example.com\' does not match \'^https://(.*)$\''

    def test_is_vulnerable_some(self):
        data = {"analytics": {"ssl": True}, "messages": [
            {"payload": {"templateurl": 'https://www1.example.com'}},
            {"payload": {"templateurl": 'http://www2.example.com'}}
        ]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: A "templateurl" in ["messages"]["payload"] doesn\\\'t use SSL; \'http://www2.example.com\' does not match \'^https://(.*)$\''

    def test_is_vulnerable_multiple(self):
        data = {"analytics": {"ssl": True}, "messages": [
            {"payload": {"templateurl": 'http://www1.example.com'}},
            {"payload": {"templateurl": 'http://www2.example.com'}}
        ]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 2
        assert(messages[0]) == '---- ISSUE: A "templateurl" in ["messages"]["payload"] doesn\\\'t use SSL; \'http://www1.example.com\' does not match \'^https://(.*)$\''
        assert(messages[1]) == '---- ISSUE: A "templateurl" in ["messages"]["payload"] doesn\\\'t use SSL; \'http://www2.example.com\' does not match \'^https://(.*)$\''

    def test_is_vulnerable_with_spaces(self):
        data = {"analytics": {"ssl": True}, "messages": [{
            "payload": {"templateurl": '     http://www.example.com    '}
        }]}
        messages = AdobeMobileSdkPlugin.validate(data)
        assert len(messages) == 1
        assert(messages[0]) == '---- ISSUE: A "templateurl" in ["messages"]["payload"] doesn\\\'t use SSL; \'     http://www.example.com    \' does not match \'^https://(.*)$\''
