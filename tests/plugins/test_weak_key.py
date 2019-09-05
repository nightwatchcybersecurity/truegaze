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
from truegaze.plugins.weak_key import WeakKeyPlugin


# Tests for WeakKeyPlugin
# TODO: Add tests for click output
class TestWeakKeyPlugin(object):
    def test_plugin_properties_name_desc(self):
        plugin = WeakKeyPlugin({}, is_android=True, is_ios=False, do_online=False)
        assert not plugin.name.startswith('Base')
        assert not plugin.desc.startswith('Base')

    def test_plugin_properties_support(self):
        assert WeakKeyPlugin.supports_android is True
        assert WeakKeyPlugin.supports_ios is False
        assert WeakKeyPlugin.supports_online is False

    def test_is_os_supported(self):
        plugin = WeakKeyPlugin({}, is_android=False, is_ios=False, do_online=False)
        assert plugin.is_os_supported() is False
        plugin = WeakKeyPlugin({}, is_android=True, is_ios=False, do_online=False)
        assert plugin.is_os_supported() is True
        plugin = WeakKeyPlugin({}, is_android=False, is_ios=True, do_online=False)
        assert plugin.is_os_supported() is False
        plugin = WeakKeyPlugin({}, is_android=True, is_ios=True, do_online=False)
        assert plugin.is_os_supported() is True

    def test_is_online_testing_supported(self):
        plugin = WeakKeyPlugin({}, is_android=False, is_ios=False, do_online=False)
        assert plugin.is_online_testing_supported() is False
        plugin = WeakKeyPlugin({}, is_android=False, is_ios=False, do_online=True)
        assert plugin.is_online_testing_supported() is False


