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
