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

    # Whether scanning of Android files is supported
    supports_android = False

    # Whether scanning of iOS files is supported
    supports_ios = False

    # Whether supports online tests
    supports_online = False

    def __init__(self, filename, is_android, is_ios, do_online):
        # Main constructor
        #
        # :param filename: Filename to scan
        # :param is_android: Whether the provided file is an Android application
        # :param is_ios: Whether the provided is an iOS application
        # :param do_online: Whether online tests should be performed
        #
        self.filename = filename
        self.is_android = is_android
        self.is_ios = is_ios
        self.do_online = do_online

    # Utility method used to check if this plugin supports a given OS
    def is_os_supported(self):
        if (self.is_android and self.supports_android) or (self.is_ios and self.supports_ios):
            return True

        return False

    # Utility method used to check if this plugin supports online tests
    def is_online_testing_supported(self):
        if self.do_online and self.supports_online:
            return True

        return False

    # Main scanning method
    def scan(self):
        raise NotImplementedError('Scanning functionality not implemented')
