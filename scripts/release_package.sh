#!/usr/bin/env bash
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
# This script builds and uploads a new release to PYPI. Make sure that the version gets updated in utils.py,
# and a release is done on GitHub at the same time.
#
# Package can be viewed online at:
# Sandbox: https://test.pypi.org/project/truegaze/
# Prod: https://pypi.org/project/truegaze/

# Installs requirements
echo Installing required tools...
pip3 install -q setuptools twine setupext-janitor

# Ask the user if production PYPI should be used, otherwise it will be the sandbox
read -p "Upload to production (y/n)?" choice
case "$choice" in
  y|Y ) PYPI_URL="https://upload.pypi.org/legacy/";;
  n|N ) PYPI_URL="https://test.pypi.org/legacy/";;
  *) exit;;
esac

# Build
echo
echo Building...
python3 setup.py sdist bdist_wheel

# Upload to PYPI
echo
echo Uploading to the following URL: $PYPI_URL
twine upload --repository-url $PYPI_URL dist/*

# Clean
echo
echo Cleaning...
python3 setup.py clean --dist --eggs
