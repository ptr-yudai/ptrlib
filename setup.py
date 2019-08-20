#!/usr/bin/env python
from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ptrlib',
    version='1.1.0',
    description='CTF library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://bitbucket.org/ptr-yudai/ptrlib/',
    author='ptr-yudai',
    author_email='ptr.yudai@gmail.com',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='pwn crypto',
    packages=find_packages(exclude=['examples']),
    python_requires='!=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4',
    install_requires=['pycrypto', 'capstone'],
    entry_points={  # Optional
        'console_scripts': [
            'ptrlib=ptrlib.__init__:main',
        ],
    },
)
