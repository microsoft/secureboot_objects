# Information

[!CAUTION]
This information is for Advanced Users. If you are unfamiliar with the Secure Boot Process it is highly
recommended that you allow your Operating System to service Secure Boot.

Listed are some common mistakes but may not document all possible outcomes.

> *In all assumptions Secure Boot is enabled*

| Assumption                                                                         | Effect                                                   |
|------------------------------------------------------------------------------------|----------------------------------------------------------|
| Boot media is not updated                                                          | System presents "EFI_SECURITY_VIOLATION" dialog to user  |
| Boot media is updated, but enforcement mechanism (e.g. bitlocker) is not suspended | System goes into "Bitlocker recovery"                    |
| Boot media is updated, but Cred Guard is not suspended                             | System loses access to stored creds                      |

See https://learn.microsoft.com/windows/security/identity-protection/credential-guard/

## edk2-2011-signed-secureboot-binaries

[!IMPORTANT]
Background:
    - These binaries are signed with a leaf certificate of the Microsoft UEFI CA 2011 KEK.
    - These binaries should be used for systems that trust the Microsoft UEFI CA 2011 KEK certificate
    - These binaries hashes are broken up by architecture
        - X64
        - Ia32
        - Arm
        - Aarch64
    - Purely hash based revocations. These do not contain the 2011 Windows CA nor do they contain SVNs.
    - These binaries are the most compatible with the most systems consult the
    `PreSignedObjects\DBX\dbx_info_msft_<date>.json` file for more information.

## edk2-2011-optional-signed-secureboot-binaries

[!IMPORTANT]
Background:
    - These binaries are considered optional because the ecosystem is undergoing a transition to new
    certificates. Not all platforms can be updated yet without a firmware update.
    - If a platform does take these optional updates, they will be unable to boot existing Windows boot
    media. More information to follow.
    - These binaries are signed with a leaf certificate of the Microsoft UEFI CA 2011 KEK.
    - These binaries should be used for systems that trust the Microsoft UEFI CA 2011 KEK certificate
    - They are broken up by:
        - DB
            - `DBUpdate2024` Contains a 2011 MSFT KEK Signed 2023 Windows CA DB update
        - DBX
            -  `DBXUpdate2024.bin` Contains a 2011 MSFT KEK Signed revocation that revokes 2011
            Windows CA and SVNs
            - `DBXUpdateSVN` Contains a 2011 MSFT KEK Signed revocation of SVNs
    - These binaries are the lease compatible and will break existing Windows boot media. Consult the
    `PreSignedObjects\DBX\dbx_info_msft_<date>.json` file for more information.