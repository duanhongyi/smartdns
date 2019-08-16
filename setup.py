#coding:utf-8

import os
import sys
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md'), encoding="utf8") as f:
    README = f.read()

requires = [
    'twisted',
    'pyyaml',
    'pyopenssl',
    'setuptools',
    'service_identity',
]

test_requirements = [
    'nose',
]


setup(

    name='smartdns',
    description='An Intelligent DNS Similar to DNSPod',
    version='3.1.7',
    author='duanhongyi',
    author_email='duanhyi@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    long_description=README,
    url='https://github.com/duanhongyi/smartdns',
    install_requires=requires,
    tests_require=test_requirements,
    platforms='all platform',
    license='BSD',
    # install
    entry_points={'console_scripts': ['sdns=smartdns.sdns:main']}
)