# Secure Boot Objects

This repository is used to hold the secure boot objects recommended by Microsoft.

For documentation visit our [Wiki](https://github.com/microsoft/secureboot_objects/wiki)!

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

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact `opencode@microsoft.com <mailto:opencode@microsoft.com>`_. with any additional questions or comments.

## License

The files in this repository are licensed under the [BSD-2-Clause-Patent](License.txt) license.
