# truegaze
[![Build Status](https://travis-ci.org/nightwatchcybersecurity/truegaze.svg?branch=master)](https://travis-ci.org/nightwatchcybersecurity/truegaze)
[![codecov](https://codecov.io/gh/nightwatchcybersecurity/truegaze/branch/master/graph/badge.svg)](https://codecov.io/gh/nightwatchcybersecurity/truegaze)
![GitHub](https://img.shields.io/github/license/nightwatchcybersecurity/truegaze.svg)

A static analysis tool for Android and iOS applications focusing on security issues outside the
source code such as resource strings, third party libraries and configuration files.

## Requirements
Python 3 is required and you can find all required modules in the **requirements.txt** file.
Only tested on Python 3.7 but should work on other 3.x releases. No plans to 2.x support at
this time.

## How to use 
```
truegaze list - to list all modules
truegaze scan [APK or IPA file] - to scan an aplication
```

## Structure
The application is command line and will consist of several modules that check for various
vulnerabilities. Each module does its own scanning, and all results get printed to command line.

## Reporting bugs and feature requests
Please use the GitHub issue tracker to report issues or suggest features:
https://github.com/nightwatchcybersecurity/truegaze

You can also send emai to ***research /at/ nightwatchcybersecurity [dot] com***

## Wishlist
   * More unit test coverage for code that interacts with Click 
   * Ability to extract additional files from online source
   * Ability to check if a particular vulnerability is exploitable
   * Ability to produce JSON or XML output that can feed into other tools
   * More modules!

## About the name
"True Gaze" or "Истинное Зрение" is a magical spell that reveals the invisible (from the book "Last Watch" by Sergei Lukyanenko)