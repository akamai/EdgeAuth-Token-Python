# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.rst', 'r') as f:
    readme = f.read()

setup (
    name = 'akamai-edgeauth',
    version = '0.1.1',
    description = 'Akamai Edge Authorization Token for Property Manager Behavior',
    long_description = readme,
    namespace_packages=['akamai'],
    packages=find_packages(exclude=['spike']),
    author = 'Astin Choi',
    author_email = 'asciineo@gmail.com',
    url = 'https://github.com/AstinCHOI/Akamai-EdgeAuth-Python',
    license='Apache 2.0',
    keywords='edgeauth auth token akamai openapi open api',
    classifiers=(
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy'
    ),
)