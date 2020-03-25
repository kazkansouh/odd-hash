#! /usr/bin/env python3

import oddhash
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
    algorithms that use a different interface, such as HMAC or either
    of the SHAKEs. Compare the usage of either of these with MD5 on
    the above link.

    '''),
    epilog='''
    {} v{}.
    Copyright (C) 2020 Karim Kanso. All Rights Reserved.
    '''.format(oddhash.name, oddhash.version)
    )
    parser.add_argument(
        'format',
        help=textwrap.dedent('''

        hash format specification, e.g. "md5($p)" or something much
        more complex such as
        "sha3_384(md5($s).keccak_512(blake2b_224($p)))".

        Any of the algorithm names can be given the suffix with
        "_raw", which does not convert the resulting hash back into
        base16 before the next hash. E.g. "sha256(sha256_raw($p))"
        will hash the resulting 32 bytes of the first hash (instead of
        turning them into hex first, i.e. 64 chars).

        The following is a list of hash functions available from the
        installed version of pycryptodome: {}

        '''.format(', '.join(oddhash.algorithms())))
    )
    parser.add_argument(
        '--salt',
        type=lambda x: x.encode('utf-8'),
        help='if needed, specify a salt value'
    )
    parser.add_argument(
        'password',
        type=lambda x: x.encode('utf-8'),
        help='the password to hash'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='increase verbosity of print messages'
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
        func = oddhash.HashBuilder(args.salt).transform(tree)
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
