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
# please extend this class, set the attributes correctly. implement the scan method and add the class
# to the ACTIVE_PLUGINS list in the truegaze.py file.
#


class BasePlugin(object):
    name = 'Base Plugin'
    desc = 'Base class used for all other plugins, do not access directly'
    supports_android = False
    supports_ios = False

    # Main constructor
    def __init__(self, zip_file, is_android, is_ios):
        self.zip_file = zip_file
        self.is_android = is_android
        self.is_ios = is_ios

    # Utility method used to check if this plugin supports a given OS
    def is_os_supported(self):
        if (self.is_android and self.supports_android) or (self.is_ios and self.supports_ios):
            return True

        return False

    # Main scanning method - we are passing in the ZIP file object, and various flags
    def scan(self):
        raise NotImplementedError('Scanning functionality not implemented')
