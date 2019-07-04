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
from truegaze.plugins import BasePlugin


# Tests for BasePlugin
class TestBasePlugin(object):
    def test_plugin_properties_name_desc(self):
        plugin = BasePlugin()
        assert plugin.name.startswith('Base')
        assert plugin.desc.startswith('Base')

    def test_plugin_properties_support(self):
        plugin = BasePlugin()
        assert plugin.supports_android is False
        assert plugin.supports_ios is False

    def test_check_support_is(self):
        plugin = BasePlugin()
        assert plugin.check_supported_os(False, False) is False
        assert plugin.check_supported_os(False, True) is False
        assert plugin.check_supported_os(True, False) is False
        assert plugin.check_supported_os(True, True) is False

    def test_scan_not_implemented(self):
        plugin = BasePlugin()
        with pytest.raises(NotImplementedError):
            assert plugin.scan({}, True, True)
