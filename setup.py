#!/usr/bin/env python
from __future__ import print_function
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import io
import os

here = os.path.abspath(os.path.dirname(__file__))

def read_version(version_filepath):
    import re
    verstrline = open(version_filepath, "rt").read()
    VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
    mo = re.search(VSRE, verstrline, re.M)
    return mo.group(1)
#
def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)

long_description = read('README.md')

setup(
    name='Instarecon',
    version=read_version('src/_version.py'),
    url='http://github.com/vergl4s/instarecon/',
    license='MIT License',
    author='Luis Teixeira',
    install_requires=[
        'dnspython>=1.14.0',
        'ipaddr>=2.1.11',
        'ipaddress>=1.0.16',
        'ipwhois>=0.13.0',
        'pythonwhois>=2.4.3',
        'requests>=2.10.0',
        'shodan>=1.5.3'
    ],
    scripts = ['scripts/instarecon.py'],
    author_email='luis@teix.co',
    description='Automated basic digital reconnaissance',
    packages=find_packages('.'),
    include_package_data=True,
    classifiers = [
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers, Hackers',
        'License :: OSI Approved :: MIT License',
        ],
    test_suite='tests',
)
