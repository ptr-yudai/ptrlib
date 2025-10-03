#!/usr/bin/env python
from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ptrlib',
    version='3.0.1',
    description='CTF library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/ptr-yudai/ptrlib/',
    author='ptr-yudai',
    author_email='ptr.yudai+dev@gmail.com',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    keywords='pwn crypto algorithm',
    packages=find_packages(exclude=['examples', 'tests']),
    python_requires='>=3.10',
    install_requires=['pycryptodome', "pywin32; platform_system=='Windows'"],
    entry_points={
        'console_scripts': [
            'ptrlib=ptrlib.__init__:main',
        ],
    },
)
