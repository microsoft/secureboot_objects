# Secure Boot Objects

This repository is used to hold the secure boot objects recommended by
Microsoft to use as the default KEK, DB, and DBX variables. This repository
utilizes a script (`scripts/secure_boot_default_keys.py`) to generate the
binary blobs based off of the `keystore.toml` configuration file.

On a release github release, the script is run and the generated binaries are
bundled, zipped, and attached to the release so that they can be consumed by
platforms.

## Transparency

By Keeping the contents of the KeK, Db, and Dbx in a human readable form in
this repository, it enables developers to easily review the contents and make
changes as needed. This also enables an easy way for the KeK, Db, and (mainly)
the Dbx to be updated transparently and then consumed by any platform!

## Platform Consumption

The secure boot binary objects are formatted to the expected EDKII data
structures to enable simple integration into any platform. Please refer to
[SecureBootKeyStoreLibOem](https://github.com/microsoft/mu_oem_sample/tree/release/202302/OemPkg/Library/SecureBootKeyStoreLibOem)
to see one example on how to easily integrate these binaries into your
platform. The EDKII build system even supports easily appending to the default
values suggested by Microsoft!

This is just one suggested way of consuming the binary objects. There are of
course plenty of others, such as storing them as a Freeform Ffs file in an
FV.

## secure_boot_default_keys.py

This script ingests a configuration file and generates binary blobs for each
table specified in the configuration file.

``` cmd
usage: secure_boot_default_keys.py [-h] --keystore KEYSTORE [-o OUTPUT]

Build the default keys for secure boot.

options:
  -h, --help            show this help message and exit
  --keystore KEYSTORE   A json file containing the keys mapped to certificates and
                        hashes.
  -o OUTPUT, --output OUTPUT
                        The output directory for the default keys.
```

## Configuration File

A configuration file must be provided to the script to generate the binary
information. The script generates a binary blob for each table entry in the
toml file (a table is each `[]` in the toml file) and for each supported
architecture (Currently Intel, ARM). We also generate a readme for each
architecture to provide information about the files inside each binary blob

That is to say, if you define a toml file similar to this:

```toml
[MyCustomKek]

[MyCustomDb]

[MyCustomDbx]
```

Binary blobs will be created with the following folder structure:

``` cmd
Artifacts
├── Aarch64
│   ├── MyCustomKek.bin
│   ├── MyCustomDb.bin
│   ├── MyCustomDbx.bin
│   └── README.md
├── Arm
│   ├── MyCustomKek.bin
│   ├── MyCustomDb.bin
│   ├── MyCustomDbx.bin
│   └── README.md
├── Ia32
│   ├── MyCustomKek.bin
│   ├── MyCustomDb.bin
│   ├── MyCustomDbx.bin
│   └── README.md
└── X64
    ├── MyCustomKek.bin
    ├── MyCustomDb.bin
    ├── MyCustomDbx.bin
    └── README.md
```

For each table in the toml file, the script supports the following entries:

1. `help (Optional<str>)`: A short blob of information to be added to the
   readme for that table entry.
2. `arch (Optional<str>)`: The architecture (Intel, ARM) the blob should be
   generated for. Defaults to all.
3. `file (list<File>)`: A list of files to include in the binary blob (.crt,
   .csv). This has additional config described below
4. `signature_owner (Optional<str>)`: The GUID of the signature owner.

For each file in the toml file, the script supports the following entries:

1. `path (str)`: The local path to the file to include in the binary
2. `url (Optional<str>)`: The url to where the file was downloaded from.
   Included in the readme if provided
3. `sha1 (Optional<str>)`: The sha1 hash of the file. Included in the readme
   if provided.

## TODO

1. make `path` optional and add support for downloading the file from the url.
