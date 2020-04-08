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
import binascii
import concurrent.futures
import signal

# used child by processes, needs to be global
def checkHash(password):
    global hasher
    global args
    try:
        result = hasher(password)
        for h in args.hashes:
            if h == result:
                return h
    except KeyboardInterrupt:
        pass

def main():
    global hasher
    global args
    parser = argparse.ArgumentParser(description=textwrap.dedent('''

    Configurable password hash cracker. It is designed to be easy to
    specify different format hashes, however it is not designed to be
    fast. The tool was created as often serious password crackers
    (e.g. john or hashcat) can be time consuming to use a format that
    is not pre-configured.

    Selection of supported hash algorithms depends on what is
    available in the installed version of pycryptodome. See following
    link for more details:

    https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html

    Currently it is not possible to use this tool for any of the
    algorithms that use a different interface, such either of the
    SHAKEs or the MAC algorithms (with the exception of HMAC). To
    better understand, compare the usage of these with MD5 on the
    above link.

    Parameters such as salt, message and hashes can be specified
    with a prefix of: {}.

    '''.format(', '.join(A.codings()))),
    epilog='''
    {} v{}.
    Copyright (C) 2020 Karim Kanso. All Rights Reserved.
    '''.format(oddhash.name, oddhash.version),
    fromfile_prefix_chars='@',
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

        '''.format(', '.join(oddhash.algorithms()))
        )
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
        'wordlist',
        type=argparse.FileType('rb'),
        help='Wordlist to use for cracking'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Increase verbosity of print messages'
    )
    parser.add_argument(
        'hashes',
        metavar='HASH',
        nargs='+',
        type=lambda x: binascii.hexlify(A.toBytes(x, 'hex')),
        help=textwrap.dedent('''

        List of base16 (i.e. hex) hashes to attempt to crack. Caution,
        no validation is performed on the length.

        If a hash begins with "@" then it will be treated as a file
        and hashes read from it.

        ''')
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
        hasher = oddhash.HashBuilder(args.salt, args.message).transform(tree)
    except Exception as e:
        print('[E] unable compile hash function:\n{}'.format(e))
        return

    if type(hasher) == bytes:
        print('[!] salt only hash, no point continuing')
        return

    print('[*] loading file...')
    # Using ProcessPoolExecutor is easy way to get concurrent
    # execution, but the tradeoff is that there are lots of
    # inefficiencies with the ipc using pickling. However, it appears
    # approx 40% faster on my 4 core laptop than using a single core.
    #
    # todo: look into other concurrent execution methods
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as exe:
        with args.wordlist as f:
            lines = [ line.rstrip(b'\r\n') for line in f.readlines() ]
        results = exe.map(checkHash, lines, chunksize=1000)

        def handler(signum, frame):
            print('ctrl-c')
            sys.exit(1)
        signal.signal(signal.SIGINT, handler)

        ctr = 0
        print('[*] tried 0', end='\r', flush=True)
        for password, hash in zip(lines, results):
            ctr += 1;
            if ctr % 1000 == 0:
                print('[*] tried {}'.format(ctr), end='\r', flush=True)
            if hash:
                try:
                    password = password.decode('latin-1')
                except:
                    if debug:
                        print('[!] check encoding')
                print('[*] found \x1B[92m{}={}\x1B[39m'.format(
                password, hash.decode('utf-8')))

                try:
                    args.hashes.remove(hash)
                except ValueError:
                    print('[!] same hash found multiple times!!')
                if not args.hashes:
                    print('[*] all hashes found, shutdown requested')
                    results.close()
                    break
    print('[*] done, tried {} passwords'.format(ctr))

if __name__ == '__main__':
    main()
