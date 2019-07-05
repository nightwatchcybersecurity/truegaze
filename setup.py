from setuptools import setup

setup(
    name='truegaze',
    version='0.1',
    description='Static analysis tool for Android/iOS apps focusing on security issues outside the source code.',
    url='https://github.com/nightwatchcybersecurity/truegaze',
    author='Nightwatch Cybersecurity',
    author_email='research@nightwatchcybersecurity.com',
    license='GNU',
    packages=['truegaze'],
    install_requires=[
        'beautifultable >= 0.7.0',
        'click >= 7.0',
        'jmespath >= 0.9.4'
    ],
    extras_require={
        'test': ['pytest', 'pytest-cov'],
    },
    entry_points={
        'console_scripts': ['truegaze = truegaze:main'],
    },
    classifiers=[
        'Environment :: Console',
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.7',
    ],
    python_requires='>=3.7',
    project_urls={
        'Bug Reports': 'https://github.com/nightwatchcybersecurity/truegaze/issues',
        'Source': 'https://github.com/nightwatchcybersecurity/truegaze',
    },
)
