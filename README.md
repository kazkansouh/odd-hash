# odd-hash: your digesting friend

Simple tools to *hash* or *dictionary attack* passwords that use
non-standard hash schemes like:
`sha256(md5(sha1($p).sha3_384($s)).$p)`.

## Why was it made?

There have been a few occasions where I have come across (or wondered
in a CTF setting if I had come across) hashing schemes that standard
tools such as [`john`][john] or [`hashcat`][hashcat] do not support
out of the box. Configuring these tools to deal with non-standard
formats is often time consuming and requires digging through lots of
documentation, alternatively a throwaway script can be written.

To improve this situation, these tools aim to have a clean user
interface for dealing with non-standard formats to allow the user to
easily try out different schemes, sadly this does trade lots of
efficiency when compared to purpose written crackers.

## How to specify

The following are examples of how formats can be specified:

* `md5($p)`
* `sha256(sha256($p).sha256_raw($s))`
* `sha3_384(md5($s).keccak_512(blake2b_224($p)))`
* `hmac_md5($m)`
* `sha256(hmac_sha512(keccak_224($s)))`

The `$p`, `$s` and `$m` are substituted for the *password*, *salt*,
and *message* respectively. Any algorithm can end in `_raw`, which
means its result will be the raw binary hash (i.e. it has not been
*hexlified*). Many of the algorithms can be prefixed with `hmac_`, the
notable exception to this are the sponge based algorithms like `sha3`
(which are not vulnerable to length extension attack so `hmac` is of
less value).

This is a fairly self explanatory specification and was inspired by
the way [dynamic][john-dynamic] formats are displayed in
[`john`][john]. However there are some differences as the exact format
here encodes an algorithm name that is looked up from
[PyCryptodome][pycryptodome-hash]'s hash library: `Crypto.Hash`. For
this reason, some formats will have an underscore between the digest
size and others do not.

The resolution logic works as follows (segments are separated by `_`):

1. If the first segment is `hmac`, remove it (so the second segment is
   now the first, i.e. the digest algorithm name).

   1. In the case that it was `hmac`, take the resolved algorithm from
      the below rules and use it as the digest method in `hmac`.

2. If the first segment of the algorithm name is a module in
   `Crypto.Hash`. Use that as the algorithm. (e.g. `md5` or `sha256`)

    1. If the second segment is a number, pass this to the `new`
       function of the hash algorithm as the `digest_bits`
       parameter. (e.g. `keccak_256`)

3. If the first two segments of the algorithm form a module in
   `Crypto.Hash`. Use that as the algorithm. (e.g. `sha3_512`)

### Limits

First, obviously if the algorithm is not supported by *PyCryptodome*,
then it will not be supported by `odd-hash`.

Secondly, *MAC* formats such as `CMAC` follow a slightly different
interface (as a secret/key is passed when instantiating the
algorithm). Thus, these are not supported. Due to the usefulness of
`HMAC` special provision has been provided for it.

Finally, both the *SHAKE* formats follow a slightly different
interface in that the digest size is not part of the name or passed to
the `new` function. This has been left as future work to support.

## The Tools

Two tools are provided:

* `odd-hash` used for hashing a password [[usage](#odd-hash-usage)] [[examples](#odd-hash-examples)]
* `odd-crack` used for dictionary attack against a hash [[usage](#odd-crack-usage)] [[examples](#odd-crack-examples)]

### Install

From [pypi.org][pypi]:

```
pip3 install oddhash
```

From source:

```
pip3 install -r requirements.txt
python3 setup.py install
```

### `odd-hash` usage

```
$ odd-hash -h
usage: odd-hash [-h] [--salt S] [--message M] [--debug] format password

  Configurable password hasher. It is designed to be easy to generate
different format hashes using a standard hash specification similar to what is
often shown in PHP.

  Selection of supported hash algorithms depends on what is available in the
installed version of pycryptodome. See following link for more details:

  https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html

  Currently it is not possible to use this tool for any of the algorithms that
use a different interface, such either of the SHAKEs or the MAC algorithms
(with the exception of HMAC). To better understand, compare the usage of these
with MD5 on the above link.

  Parameters such as salt and message can be specified with a prefix of: hex,
base64, base64urlsafe, utf8.

positional arguments:
  format       Hash format specification, e.g. "md5($p)" or something much
               more complex such as
               "sha3_384(md5($s).keccak_512(blake2b_224($p)))".

               Any of the algorithm names can be given the suffix with "_raw",
               which does not convert the resulting hash back into base16
               before the next hash. E.g. "sha256(sha256_raw($p))" will hash
               the resulting 32 bytes of the first hash (instead of turning
               them into hex first, i.e. 64 chars).

               It is possible to prefix algorithm names with "hmac_". This
               will use the password value as the secret and value passed in
               between the parameters as the message. E.g. "hmac_sha256($m)"
               or even "sha256(hmac_md5($s.sha1($p)))" is possible. Be aware
               that not all possible combinations of hmac and digest
               algorithms are supported, this is especially true of sponge
               based algorithms (e.g. sha3, keccak, blake2b).

               The following is a list of hash functions available from the
               installed version of pycryptodome: BLAKE2b, BLAKE2s, CMAC,
               HMAC, MD2, MD4, MD5, Poly1305, RIPEMD, RIPEMD160, SHA, SHA1,
               SHA224, SHA256, SHA384, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
               SHA512, SHAKE128, SHAKE256, keccak.

  password     The password to hash


optional arguments:
  -h, --help   show this help message and exit

  --salt S     If needed, specify a salt value: $s

  --message M  If needed, specify a message value: $m

  --debug      Increase verbosity of print messages


  oddhash v0.0.3. Copyright (C) 2020 Karim Kanso. All Rights Reserved.
```

### `odd-hash` examples


```
$ odd-hash 'md5($p)' 'password123'
482c811da5d5b4bc6d497ffa98491e38
```

```
$ odd-hash 'md5($p.sha256($s))' --salt oddhash 'password123'
86e2e5671b8b7f9f6264ecd6d1d749c3
```

```
$ odd-hash 'md5($p.sha256($s))' --salt hex:6f646468617368 'password123'
86e2e5671b8b7f9f6264ecd6d1d749c3
```

```
$ odd-hash 'md5($p.sha256($s))' --salt base64:b2RkaGFzaA== 'password123'
86e2e5671b8b7f9f6264ecd6d1d749c3
```

```
$ odd-hash 'keccak_256(keccak_256_raw($p))' 'password123'
7e7471197b18c087ce6fd7abdcd1991481eb650e39cb0eeafc82cfb7186c0cfe
```

```
$ odd-hash 'hmac_sha256($m)' --message 'gjdkdkic894m' 'password123'
7de36a5d1374d690ebe19d42be1e89023fe1f7548f38fa0eae89dc91bd8901dd
```

### `odd-crack` usage

```
usage: odd-crack [-h] [--salt S] [--message M] [--debug]
                format wordlist HASH [HASH ...]

  Configurable password hash cracker. It is designed to be easy to specify
different format hashes, however it is not designed to be fast. The tool was
created as often serious password crackers (e.g. john or hashcat) can be time
consuming to use a format that is not pre-configured.

  Selection of supported hash algorithms depends on what is available in the
installed version of pycryptodome. See following link for more details:

  https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html

  Currently it is not possible to use this tool for any of the algorithms that
use a different interface, such either of the SHAKEs or the MAC algorithms
(with the exception of HMAC). To better understand, compare the usage of these
with MD5 on the above link.

  Parameters such as salt, message and hashes can be specified with a prefix
of: hex, base64, base64urlsafe, utf8.

positional arguments:
  format       Hash format specification, e.g. "md5($p)" or something much
               more complex such as
               "sha3_384(md5($s).keccak_512(blake2b_224($p)))".

               Any of the algorithm names can be given the suffix with "_raw",
               which does not convert the resulting hash back into base16
               before the next hash. E.g. "sha256(sha256_raw($p))" will hash
               the resulting 32 bytes of the first hash (instead of turning
               them into hex first, i.e. 64 chars).

               It is possible to prefix algorithm names with "hmac_". This
               will use the password value as the secret and value passed in
               between the parameters as the message. E.g. "hmac_sha256($m)"
               or even "sha256(hmac_md5($s.sha1($p)))" is possible. Be aware
               that not all possible combinations of hmac and digest
               algorithms are supported, this is especially true of sponge
               based algorithms (e.g. sha3, keccak, blake2b).

               The following is a list of hash functions available from the
               installed version of pycryptodome: BLAKE2b, BLAKE2s, CMAC,
               HMAC, MD2, MD4, MD5, Poly1305, RIPEMD, RIPEMD160, SHA, SHA1,
               SHA224, SHA256, SHA384, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
               SHA512, SHAKE128, SHAKE256, keccak.

  wordlist     Wordlist to use for cracking

  HASH         List of base16 (i.e. hex) hashes to attempt to crack. Caution,
               no validation is performed on the length.

               If a hash begins with "@" then it will be treated as a file and
               hashes read from it.


optional arguments:
  -h, --help   show this help message and exit

  --salt S     If needed, specify a salt value: $s

  --message M  If needed, specify a message value: $m

  --debug      Increase verbosity of print messages


  oddhash v0.0.3. Copyright (C) 2020 Karim Kanso. All Rights Reserved.
```

### `odd-crack` examples

While its possible to crack a simple `md5` hash as follows, there are
many other more efficient tools:

```
$ odd-crack 'md5($p)' rockyou.txt  482c811da5d5b4bc6d497ffa98491e38
[*] loading file...
[*] found password123=482c811da5d5b4bc6d497ffa98491e38
[*] all hashes found, shutdown requested
[*] done, tried 1384 passwords
```

```
$ odd-crack 'keccak_256(keccak_256_raw($p))' rockyou.txt 7e7471197b18c087ce6fd7abdcd1991481eb650e39cb0eeafc82cfb7186c0cfe
[*] loading file...
[*] found password123=7e7471197b18c087ce6fd7abdcd1991481eb650e39cb0eeafc82cfb7186c0cfe
[*] all hashes found, shutdown requested
[*] done, tried 1384 passwords
```

```
$ odd-crack 'hmac_sha256($m)' --message base64:t4ErHzCg4EaGujcalk2WWg== rockyou.txt base64:UmUuTPTBS3PaOkQGqvubvkYWUA1m2q1QmqUkk7Y/Nbw=
[*] loading file...
[*] found password123=52652e4cf4c14b73da3a4406aafb9bbe4616500d66daad509aa52493b63f35bc
[*] all hashes found, shutdown requested
[*] done, tried 1384 passwords
```


# Other bits

Source code can be found on [GitHub][oddhash].

Copyright (C) 2020 Karim Kanso. All Rights Reserved. Project licensed under GPLv3.


[john]: https://www.openwall.com/john/ "John the Ripper password cracker"
[hashcat]: https://hashcat.net/hashcat/ "hashcat: advanced password recovery"
[john-dynamic]: https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/doc/DYNAMIC "GitHub.com: John the Ripper Dynamic Mode Documentation"
[pycryptodome-hash]: https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html "pycryptodome.readthedocs.io: Crypto.Hash package documentation"
[oddhash]: https://github.com/kazkansouh/odd-hash "GitHub.com: odd-hash"
[pypi]: https://pypi.org/project/oddhash/ "PyPI: oddhash"
