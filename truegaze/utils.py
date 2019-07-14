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
import plistlib
import re
import zipfile

# Name of the Android manifest file
ANDROID_MANIFEST = 'AndroidManifest.xml'

# Regex pattern to use when searching iOS files
IOS_PATTERN = re.compile(r'Payload/[^/]*.\.app/Info.plist')


class TruegazeUtils(object):
    """Various utility functions, split off from the main class for ease of unit testing"""

    @staticmethod
    def get_version():
        """Gets the current version"""
        return "0.1.2"

    @staticmethod
    def open_file_as_zip(filename):
        """
        Tries to open the provided file as a zipfile

        :param filename: file to open
        :return: zipfile.ZipFile
        """
        try:
            return zipfile.ZipFile(filename, 'r')
        except (zipfile.BadZipfile, FileNotFoundError, zipfile.LargeZipFile):
            return None

    @staticmethod
    def get_android_manifest(zip_file):
        """
        Check if this is an Android application by looking for the AndroidManifest.xml file in root

        :param zip_file: zipfile.ZipFile to scan
        :return: path to the Android manifest file
        """
        try:
            file_info = zip_file.getinfo(ANDROID_MANIFEST)
            if file_info.file_size > 0:
                return ANDROID_MANIFEST
        except KeyError:
            return None

    def get_ios_manifest(zip_file):
        """
        Check if this is an iOS application by looking for the application and its plist

        :param zip_file: zipfile.ZipFile to scan
        :return: path to the iOS plist file
        """
        # IPA files have a /Payload/[something].app directory with the plist file in it, try to find it via regex
        paths = TruegazeUtils.get_matching_paths_from_zip(zip_file, IOS_PATTERN, True)

        # Check if the path was found and try to parse
        if len(paths) > 0:
            plist_path = paths[0]
            plist_contents = zip_file.read(plist_path)
            try:
                plist_dic = plistlib.loads(plist_contents)
            except plistlib.InvalidFileException:
                return None

            # Test to make sure some required keys are present
            if ('CFBundleDisplayName' in plist_dic) and \
                    ('CFBundleIdentifier' in plist_dic) and \
                    ('CFBundleShortVersionString' in plist_dic):
                return plist_path

        # Otherwise, return None if not detected
        return None

    @staticmethod
    def get_matching_paths_from_zip(zip_file, pattern, stop_after_first=False):
        """
        Searches ZIP file for list of matching paths

        :param zip_file: zipfile.ZipFile to scan
        :param pattern: regex pattern to use
        :param stop_after_first: whether to stop once first match is found
        :return: list of matched paths
        """
        file_list = zip_file.namelist()
        paths = []
        for file_path in file_list:
            matched = pattern.match(file_path)
            if matched is not None:
                paths.append(matched.group())
                if stop_after_first:
                    break

        return paths
