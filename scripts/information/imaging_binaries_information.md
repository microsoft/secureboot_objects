# Imaging Binaries

This folder contains the defaults in a format that may be used by imaging tools during imagine (such as tools that call
SetFirmwareVariableEx(..) like [WinPE](https://learn.microsoft.com/windows-hardware/manufacture/desktop/winpe-intro?view=windows-11))
to initialize the secure boot variables. These files have a authenticated variable header prepended to the
EFI Signature List. However the signature is not included. These variables are not signed but may be used to initialize
the secure on systems that support this feature.

The additional data appended is a empty [EFI_VARIABLE_AUTHENTICATION_2](https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html?highlight=efi_time#using-the-efi-variable-authentication-2-descriptor)
descriptor and is as follows:
[EFI_TIME](https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf#page=158) +
[WIN_CERTIFICATE_UEFI_GUID](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html?highlight=authenticated%20variable#win-certificate-uefi-guid) +
[PKCS7](https://tools.ietf.org/html/rfc2315#section-9.1) +
Data

Where the PKCS7 is a empty signature with the following ASN.1 structure:

```text
ContentInfo SEQUENCE (4 elem)
    contentType ContentType [?] INTEGER 1
    content [0] [?] SET (1 elem)
        ANY SEQUENCE (2 elem)
            OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
            NULL
    SEQUENCE (1 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
    SET (0 elem)
```

For some firmware implementations, the PK is required to be at-least self signed during the imaging process.
However [Project Mu has a relaxed implementation](https://github.com/microsoft/mu_tiano_plus/blob/5c96768c404d1e4e32b1fea6bfd83e588c0f5d67/SecurityPkg/Library/AuthVariableLib/AuthService.c#L656C13-L656C52)
that allows for the PK to use an empty signature.
