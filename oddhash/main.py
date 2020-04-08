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

import oddhash
import oddhash.args as A
import sys
import argparse
import textwrap

def main():
    parser = argparse.ArgumentParser(description=textwrap.dedent('''

    Configurable password hasher. It is designed to be easy to
    generate different format hashes using a standard hash
    specification similar to what is often shown in PHP.

    Selection of supported hash algorithms depends on what is
    available in the installed version of pycryptodome. See following
    link for more details:

    https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html

    Currently it is not possible to use this tool for any of the
    algorithms that use a different interface, such either of the
    SHAKEs or the MAC algorithms (with the exception of HMAC). To
    better understand, compare the usage of these with MD5 on the
    above link.

    Parameters such as salt and message can be specified with a prefix
    of: {}.

    '''.format(', '.join(A.codings()))),
    epilog='''
    {} v{}.
    Copyright (C) 2020 Karim Kanso. All Rights Reserved.
    '''.format(oddhash.name, oddhash.version),
    formatter_class=A.OddHashHelpFormatter,
    )
    parser.add_argument(
        'format',
        help=textwrap.dedent('''

        Hash format specification, e.g. "md5($p)" or something much
        more complex such as
        "sha3_384(md5($s).keccak_512(blake2b_224($p)))".

        Any of the algorithm names can be given the suffix with
        "_raw", which does not convert the resulting hash back into
        base16 before the next hash. E.g. "sha256(sha256_raw($p))"
        will hash the resulting 32 bytes of the first hash (instead of
        turning them into hex first, i.e. 64 chars).

        It is possible to prefix algorithm names with "hmac_". This
        will use the password value as the secret and value passed in
        between the parameters as the message. E.g. "hmac_sha256($m)"
        or even "sha256(hmac_md5($s.sha1($p)))" is possible. Be aware
        that not all possible combinations of hmac and digest
        algorithms are supported, this is especially true of sponge
        based algorithms (e.g. sha3, keccak, blake2b).

        The following is a list of hash functions available from the
        installed version of pycryptodome: {}.

        '''.format(', '.join(oddhash.algorithms())))
    )
    parser.add_argument(
        '--salt',
        type=A.toBytes,
        metavar="S",
        help='If needed, specify a salt value: $s'
    )
    parser.add_argument(
        '--message',
        type=A.toBytes,
        metavar="M",
        help='If needed, specify a message value: $m'
    )
    parser.add_argument(
        'password',
        type=A.toBytes,
        help='The password to hash'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Increase verbosity of print messages'
    )

    args = parser.parse_args()
    oddhash.debug = args.debug

    try:
        tree = oddhash.parser().parse(args.format)
    except Exception as e:
        print('[E] unable to parse hash format specification:\n', e)
        return

    if args.debug:
        print(tree.pretty())

    try:
        func = oddhash.HashBuilder(args.salt, args.message).transform(tree)
    except Exception as e:
        print('[E] unable compile hash function:\n{}'.format(e))
        return

    if type(func) == bytes:
        print('[*] salt only hash')
        try:
            print(func.decode('utf-8'))
        except UnicodeError:
            print('[!] raw hash: {}'.format(func))
        return

    hash = func(args.password)
    try:
        print(hash.decode('utf-8'))
    except UnicodeError:
        print('[!] raw hash: {}'.format(hash))
    return

if __name__ == '__main__':
    main()
