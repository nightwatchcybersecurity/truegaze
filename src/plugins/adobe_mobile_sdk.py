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
from src.plugins.base import BasePlugin

#
# Plugin to support detection of incorrect SSL configuration in the Adobe Mobile SDK.
#
class AdobeMobileSdkPlugin(BasePlugin):
    def __init__(self):
        self.name = 'AdobeMobileSdk'
        self.desc = 'Detection of incorrect SSL configuration in the Adobe Mobile SDK'
        self.supports_android = True
        self.supports_ios = True

    # Main scanning method
    def scan(self, filename, is_android, is_ios):
        raise NotImplemented('Scanning functionality not implemented')
