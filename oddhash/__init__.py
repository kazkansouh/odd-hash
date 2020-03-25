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

name = "oddhash"
version = "0.0.1"

from lark import Lark, Transformer
import Crypto.Hash
import pkgutil

debug = False

__grammar = '''
?start: function

function: algorithm [ "_" RAW ] "(" concat ")"

algorithm: ALG_NAME [ "_" DIGEST_SIZE ]

?concat:  param ("." param)?

?param: function
      | SALT
      | PASSWORD

SALT: "$s"
PASSWORD: "$p"

RAW: "raw"
DIGEST_SIZE: ("0".."9")+
ALG_NAME: ("a".."z"|"A".."Z"|"0".."9")+
WHITESPACE: " "+
%ignore WHITESPACE
'''

__parser = Lark(__grammar)

def parser():
    return __parser

class OddHashError(Exception):
    pass

class AlgorithmNotFoundError(OddHashError):
    def __init__(self, name, args):
        self.name = name
        if len(args) > 0:
            self.name = '{}_{}'.format(name.args[0])

    def __str__(self):
        return 'could not find hash function "{}"'.format(
            self.name)

class AlgorithmTestError(OddHashError):
    def __init__(self, name, args, err):
        self.name = name
        if len(args) > 0:
            self.name = '{}_{}'.format(name.args[0])
        self.err = err

    def __str__(self):
        return 'self test of algorithm "{}" failed with error: {}'.format(
            self.name, self.err)

def algorithms():
    "return a list of hash modules provided by Crypto.Hash"
    return [
        m.name
        for m in pkgutil.iter_modules(Crypto.Hash.__path__)
        if m.name[0] != '_'
    ]

class HashBuilder(Transformer):
    """Traverses the parse tree and builds/compiles a hash function that
computes the desired function. Where possible, eagerly evaluate hashes
of salts. E.g. md5($s.sha256($s)) will be evaluated during the
compilation.
    """

    def __lookup(self, name, size=None):
        if size:
            l = [
                a for a in self.__algorithms
                if a.upper() == (name + "_" + str(size)).upper()
            ]
        else:
            l = [
                a for a in self.__algorithms
                if a.upper() == name.upper()
            ]
        if len(l) == 1:
            return l[0]

    def __init__(self, salt=None):
        if salt and type(salt) != bytes:
            raise TypeError('salt should be bytes')
        self.salt = salt

        self.__algorithms = algorithms()

    def function(self, items):
        f = items.pop(0)
        if items[0] == "raw":
            g = lambda data, f=f: f(data).digest()
            items.pop(0)
        else:
            g = lambda data, f=f: f(data).hexdigest().encode('utf-8')
        param = items.pop(0)
        if type(param) == bytes:
            return g(param)
        return lambda data, g=g: g(param(data))

    def PASSWORD(self, item):
        return lambda x: x

    def SALT(self, item):
        if not self.salt:
            raise ValueError('salt required but not specified')
        return self.salt

    def concat(self, items):
        a1, a2 = items
        if type(a1) == bytes and type(a2) == bytes:
            return a1 + a2
        if type(a1) == bytes:
            return lambda data, a1=a1, a2=a2: a1 + a2(data)
        if type(a2) == bytes:
            return lambda data, a1=a1, a2=a2: a1(data) + a2
        return lambda data, a1=a1, a2=a2: a1(data) + a2(data)

    def algorithm(self, items):
        name = items.pop(0)
        if debug:
            print("[*] looking up: {}".format(name))

        if self.__lookup(name):
            name = self.__lookup(name)
        elif items and self.__lookup(name, int(items[0])):
            name = self.__lookup(name, int(items[0]))
            del items[0]
        else:
            if debug:
                print('[E] algorithm not found:', name, items)
            raise AlgorithmNotFoundError(name, items)

        try:
            m = __import__('Crypto.Hash.{}'.format(name), fromlist=['new'])
        except ModuleNotFoundError:
            if debug:
                print('[E] algorithm not found: {}'.format(name))
            raise AlgorithmNotFoundError(name, items)

        if items:
            def h(data, f=m.new, s=int(items[0])):
                h = f(digest_bits=s)
                h.update(data)
                return h
        else:
            def h(data, f=m.new):
                h = f()
                h.update(data)
                return h

        try:
            h(b'test')
        except Exception as e:
            if debug:
                print(
                    '[E] test of algorithm {} ({}) raised exception {}'.format(
                        name, items, e
                    )
                )
            raise AlgorithmTestError(name, items, e)
        return h
