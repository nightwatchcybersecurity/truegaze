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
import pytest

from truegaze.plugins.base import BasePlugin


# Tests for BasePlugin
class TestBasePlugin(object):
    def test_plugin_properties_name_desc(self):
        plugin = BasePlugin({}, True, True, True)
        assert plugin.name.startswith('Base')
        assert plugin.desc.startswith('Base')

    def test_plugin_properties(self):
        plugin = BasePlugin({}, True, True, True)
        assert plugin.supports_android is False
        assert plugin.supports_ios is False
        assert plugin.supports_online is False

    def test_is_os_supported(self):
        assert BasePlugin({}, False, False, True).is_os_supported() is False
        assert BasePlugin({}, False, True, True).is_os_supported() is False
        assert BasePlugin({}, True, False, True).is_os_supported() is False
        assert BasePlugin({}, True, True, True).is_os_supported() is False

    def test_is_online_testing_supported(self):
        assert BasePlugin({}, False, False, False).is_online_testing_supported() is False
        assert BasePlugin({}, False, False, True).is_online_testing_supported() is False

    def test_scan_not_implemented(self):
        plugin = BasePlugin({}, True, True, True)
        with pytest.raises(NotImplementedError):
            assert plugin.scan()
