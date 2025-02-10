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

## edk2-<arch>-secureboot-binaries

[!IMPORTANT]
Background:
    - These binaries are unsigned
    - These binaries should be used for firmware or systems where Secure Boot is disabled
    - These binaries hashes are broken up by architecture
        - X64
        - Ia32
        - Arm
        - Aarch64
    - FirmwareDefaults.toml will describe the contents of each file found in the folders
    - Purely hash based revocations. These do not contain the 2011 Windows CA nor do they contain SVNs
    - These binaries are the most compatible with the most systems consult the
    `PreSignedObjects\DBX\dbx_info_msft_<date>.json` file for more information
