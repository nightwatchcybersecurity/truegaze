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

#
# Base plugin, implements basic methods and attributes all plugins must use. To create a new plugin,
# please extend this class, set the attributes correctly and implement the scan method.
#
class BasePlugin:
    def __init__(self):
        self.name = 'Base Plugin'
        self.desc = 'Base class used for all other plugins, do not access directly'
        self.supports_android = False
        self.supports_ios = False

    # Main scanning method, scans the provided file assuming the plugin supports the OS and returns results
    def scan(self, filename, is_android, is_ios):
        raise NotImplemented('Scanning functionality not implemented')
