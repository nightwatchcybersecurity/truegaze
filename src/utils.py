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
import click
import plistlib, pprint, re, sys
from zipfile import BadZipfile, LargeZipFile, ZipFile

# Name of the Android manifest file
ANDROID_MANIFEST = 'AndroidManifest.xml'

# Regex pattern to use when searching iOS files
IOS_PATTERN = re.compile(r'Payload/[^/]*.app/Info.plist')


def open_file_as_zip(filename):
    # Tries to open the application file as a ZIP file
    try:
        return ZipFile(filename, 'r')
    except BadZipfile:
        click.echo('ERROR: Unable to open the file - please check to make sure it is an APK or IPA file')
        sys.exit(-1)
    except LargeZipFile:
        click.echo('ERROR: The file is too large - please enable ZIP64 support')
        sys.exit(-1)


def check_if_android(zip_file):
    # Check if this is an Android application by looking for the AndroidManifest.xml file in root
    try:
        zip_file.getinfo(ANDROID_MANIFEST)
        click.echo('Identified as an Android application via manifest located at: ' + ANDROID_MANIFEST)
        return True
    except KeyError:
        return False


def check_if_ios(zip_file):
    # Check if this is an iOS application by looking for the application and its plist

    # IPA files have a /Payload/[something].app directory with the plist file in it, try to find it via regex
    file_list = zip_file.namelist()
    plist_path = None
    for file_path in file_list:
        matched = IOS_PATTERN.match(file_path)
        if matched is not None:
            plist_path = matched.group()
            break

    # Check if the path was found and try to parse
    if plist_path:
        plist_contents = zip_file.read(plist_path)
        plist_dic = plistlib.loads(plist_contents)

        # Test to make sure some required keys are present
        if plist_dic['CFBundleDisplayName'] and\
           plist_dic['CFBundleIdentifier'] and\
           plist_dic['CFBundleShortVersionString']:

            click.echo('Identified as an iOS application via manifest located at: ' + plist_path)
            return True

    # Otherwise, return false if not detected
    return False