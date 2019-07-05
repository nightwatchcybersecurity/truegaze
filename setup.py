from setuptools import find_packages, setup
from truegaze.utils import TruegazeUtils

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='truegaze',
    version=TruegazeUtils.get_version(),
    description='Static analysis tool for Android/iOS apps focusing on security issues outside the source code.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/nightwatchcybersecurity/truegaze',
    author='Nightwatch Cybersecurity',
    author_email='research@nightwatchcybersecurity.com',
    license='GNU',
    packages=find_packages(exclude=["scripts.*", "scripts", "tests.*", "tests"]),
    include_package_data=True,
    install_requires=[
        'beautifultable',
        'click',
        'jmespath'
    ],
    extras_require={
        'test': ['pytest', 'pytest-cov'],
    },
    entry_points={
        'console_scripts': [
            'truegaze = truegaze.cli:cli'
        ]
    },
    classifiers=[
        'Environment :: Console',
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
    ],
    python_requires='>=3.7',
    project_urls={
        'Bug Reports': 'https://github.com/nightwatchcybersecurity/truegaze/issues',
        'Source': 'https://github.com/nightwatchcybersecurity/truegaze',
    },
)
