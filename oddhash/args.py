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

import re
import binascii
import base64

import argparse
import textwrap

class OddHashHelpFormatter(argparse.HelpFormatter):
    """Format blocks of text by paragraphs.
    Based on implementation based on:
    https://github.com/python/cpython/blob/master/Lib/argparse.py

    Makes use of internal api to argparse, but appears to work.
    """

    def _fill_text(self, text, width, indent):
        text = text.strip()
        lines = ""
        for line in text.split('\n\n'):
            line = self._whitespace_matcher.sub(' ', line).strip()
            lines += textwrap.fill(
                line,
                width,
                initial_indent=indent + "  ",
                subsequent_indent=indent
            ) + '\n\n'
        return lines

    def _split_lines(self, text, width):
        text=text.strip()
        lines = []
        for line in text.split('\n\n'):
            line = self._whitespace_matcher.sub(' ', line).strip()
            lines += textwrap.wrap(line, width) + ['']
        return lines


# below are a list of various encodings that are used for input of
# strings from user

__codings = {
    'hex'           : binascii.unhexlify,
    'base64'        : base64.b64decode,
    'base64urlsafe' : base64.urlsafe_b64decode,
    'utf8'          : lambda x: x.encode('utf8')
}

def codings():
    return [x for x in __codings]

__regex = re.compile('^(?:(' + '|'.join(codings()) + '):)?(.*)$')

def toBytes(s, default='utf8'):
    '''Parse strings that are in the form ^[(hex|base64|base64safe|utf8):].*$
If the prefix is omitted, then the string is iterpreted as ascii.'''

    g = __regex.match(s).groups()
    return __codings[g[0] if g[0] else default](g[1])
