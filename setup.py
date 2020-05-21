# Copyright (C) 2020 Karim Kanso. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import setuptools
import ast

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("oddhash/__init__.py", "r") as f:
    for line in f.readlines():
        if line.startswith('name ='):
            name = ast.literal_eval(line.split("=",1)[1].strip())
        if line.startswith('version ='):
            version = ast.literal_eval(line.split("=",1)[1].strip())

setuptools.setup(
    name=name,
    version=version,
    author="Karim Kanso",
    author_email="kaz.kanso@gmail.com",
    description="Tool to hash odd format passwords.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kazkansouh/odd-hash",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    entry_points={
        "console_scripts": [
            "odd-hash = oddhash.main:main",
            "odd-crack = oddhash.crack:main",
        ]
    },
    install_requires=[
        'lark-parser',
        'pycryptodome',
    ],
)
