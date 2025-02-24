# Secure Boot Objects

This repository is used to hold the secure boot objects recommended by
Microsoft to use as the default KEK, DB, and DBX variables. This repository
utilizes a script (`scripts/secure_boot_default_keys.py`) to generate the
binary blobs based off of the `FirmwareDefaults.toml` configuration file.

On a release github release, the script is run and the generated binaries are
bundled, zipped, and attached to the release so that they can be consumed by
platforms.

## Versioning

This repository follows [semantic versioning](https://semver.org/) `<major>.<minor>.<revision>`,
which is a versioning scheme that conveys meaning about the underlying changes.

### Version Components

* **Major**: Indicates an incompatible change between firmware secure boot versions.
This is a significant change that may require updates to the firmware or other
components. (Today there is only version 1)
* **Minor**: Represents additional revocations, usually the result of a security incident.
These changes should be documented in the release notes to inform users about the security updates.
* **Revision**: Generally a non-breaking change, such as script updates or minor improvements.
These changes do not affect the compatibility of the firmware secure boot.

### Release Forms

There are two forms of release that should generally stay in lock step:

* **Unsigned firmware-based secure boot payloads**: Denoted as (`<major>.<minor>.<revision>`). These payloads
are intended for use in firmware and are not signed.
* **Signed runtime-based secure boot payloads**: Denoted as (`<major>.<minor>.<revision>-signed`). These
payloads are signed and intended for use at runtime, providing an additional layer of security.

In a situation where a minor release is needed to be made for one release and not the other. Both will be
moved forward and the release notes will indicate no change was made.

By following this versioning scheme, we ensure that users can easily understand the nature of the changes in
each release and maintain compatibility with their systems.

## Transparency

By Keeping the contents of the KeK, Db, and Dbx in a human readable form in
this repository, it enables developers to easily review the contents and make
changes as needed. This also enables an easy way for the KeK, Db, and (mainly)
the Dbx to be updated transparently and then consumed by any platform!

## Platform Consumption

The secure boot binary objects are formatted to the expected EDKII data
structures to enable simple integration into an EDKII platform. Please refer to
[SecureBootKeyStoreLib](https://github.com/microsoft/mu_plus/tree/HEAD/MsCorePkg/Library/BaseSecureBootKeyStoreLib)
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
architecture (Currently Ia32, X64, Arm, Aarch64). We also generate a readme for
eacharchitecture to provide information about the files inside each binary blob

That is to say, if you define a toml file similar to this:

```toml
[MyCustomPk]

[MyCustomKek]

[MyCustomDb]

[MyCustomDbx]
```

Binary blobs will be created with the following folder structure:

``` cmd
Artifacts
├── Aarch64
│   ├── MyCustomPk.bin
│   ├── MyCustomKek.bin
│   ├── MyCustomDb.bin
│   ├── MyCustomDbx.bin
│   └── README.md
├── Arm
│   ├── MyCustomPk.bin
│   ├── MyCustomKek.bin
│   ├── MyCustomDb.bin
│   ├── MyCustomDbx.bin
│   └── README.md
├── Ia32
│   ├── MyCustomPk.bin
│   ├── MyCustomKek.bin
│   ├── MyCustomDb.bin
│   ├── MyCustomDbx.bin
│   └── README.md
└── X64
    ├── MyCustomPk.bin
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

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact `opencode@microsoft.com <mailto:opencode@microsoft.com>`_. with any additional questions or comments.

## License

Terms of Use for Microsoft Secure Boot Objects ("Secure Boot Objects")

By downloading the Secure Boot Objects, you agree to the following terms.
If you do not accept them, do not download or use the Secure Boot Objects.

These terms do not provide you with any legal rights to any intellectual
property in any Microsoft product.

You may copy and use the Secure Boot Objects for your internal, reference
purposes and to design, develop, and test your software, firmware or hardware,
as applicable; and you may distribute the Secure Boot Objects to end users
solely as part of the distribution of a software product, or
as part of the distribution of updates to a software product;
and you may distribute the Secure Boot Objects to end users or through your
distribution channels solely as embodied in a firmware product or hardware
product that embodies nontrivial additional functionality. Without limiting the
foregoing, copying or reproduction of the Secure Boot Objects to any other
server or location for further reproduction or redistribution on a standalone
basis is expressly prohibited.

If you are engaged in the business of developing and commercializing hardware
products that include the UEFI standard
(available at <https://uefi.org/specifications>), you may copy and use the Secure
Boot Objects for your internal, reference purposes and to design, develop, and
test your software; and you may distribute the Secure Boot Objects end users
solely as part of the distribution of a software product, or
as part of the distribution of updates to a software product.
Without limiting the foregoing, copying or reproduction of the Secure Boot
Objects to any other server or location for further reproduction or
redistribution on a standalone basis is expressly prohibited.
The Secure Boot Objects are provided “as-is.” The information contained in the
Secure Boot Objects may change without notice.  Microsoft does not represent
that the Secure Boot Objects is error free and you bear the entire risk of
using it.  NEITHER MICROSOFT NOR UEFI MAKES ANY WARRANTIES, EXPRESS OR IMPLIED,
WITH RESPECT TO THE SECURE BOOT OBJECTS, AND MICROSOFT AND UEFI EACH EXPRESSLY
DISCLAIMS ALL OTHER EXPRESS, IMPLIED, OR STATUTORY WARRANTIES.  THIS INCLUDES
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT.

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL MICROSOFT
OR UEFI BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER ARISING OUT OF OR IN CONNECTION WITH THE USE OR DISTRIBUTION
OF THE SECURE BOOT OBJECTS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION.

YOU AGREE TO RELEASE MICROSOFT (INCLUDING ITS AFFLIATES, CONTRACTORS, AGENTS,
EMPLOYEES, LICENSEES AND ASSIGNEES) AND UEFI (INCLUDING ITS AFFILIATES,
CONTRACTORS, AGENTS, EMPLOYEES, LICENSEES AND SUCCESSORS) FROM ANY AND ALL
CLAIMS OR LIABILITY ARISING OUT OF YOUR USE OR DISTRIBUTION OF THE SECURE
BOOT OBJECTS AND ANY RELATED INFORMATION.
