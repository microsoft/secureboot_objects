# Secure Boot Templates

Template Configuration files for building the Secure Boot Defaults.
These files are EFI Signature lists and are signed when secure boot updates are required to occur.

These files are the templates that will generate the EFI Signature Lists for the UEFI Secure Boot
following https://uefi.org/specs/UEFI/2.9_A/32_Secure_Boot_and_Driver_Signing.html#signature-database

## Technical information

The Signature Lists are used to store the signature database in the UEFI
Each entry must have a "SignatureOwner" GUID. While the GUID is not required to be unique,
the Microsoft HLK test will fail if the GUID overlaps with the Microsoft GUID.
It is recommended to use your own GUID for the SignatureOwner.

```c
  #pragma pack(1)

  typedef struct _EFI_SIGNATURE_DATA {
    EFI_GUID                 SignatureOwner;
    UINT8                    SignatureData [_];
  }   EFI_SIGNATURE_DATA;

  typedef struct _EFI_SIGNATURE_LIST {
    EFI_GUID                 SignatureType;
    UINT32                   SignatureListSize;
    UINT32                   SignatureHeaderSize;
    UINT32                   SignatureSize;
  //   UINT8                 SignatureHeader [SignatureHeaderSize];
  //   EFI_SIGNATURE_DATA    Signatures [__][SignatureSize];
  }   EFI_SIGNATURE_LIST;
  #pragma pack()
```

Each Variable may contain multiple EFI_SIGNATURE_LISTs, each with a different SignatureType.
Following is the structure of a EFI Signature List:
```txt
                             ---┌─────────────────────────┐
                            /   │  SIGNATURE LIST HEADER  │
                           /    │                         │
 ┌───────────────┐        /     │                         │
 │   SIGNATURE   │       /      ├─────────────────────────┤
 │     LIST #0   │      /       │    SIGNATURE HEADER     │
 │               │     /        │                         │
 │               │    /         ├─────────────────────────┤
 ├───────────────┤   /          │     SIGNATURE #0        │
 │   SIGNATURE   │  /           │                         │
 │     LIST #1   │ /            ├─────────────────────────┤
 ├───────────────┤/             │     SIGNATURE #1        │
 │   SIGNATURE   │              │                         │
 │     LIST #2   │              ├─────────────────────────┤
 │               │              │                         │
 │               │              │                         │
 │               │              │                         │
 │               │              │                         │
 │               │              │                         │
 │               │              ├─────────────────────────┤
 │               │              │     SIGNATURE #N        │
 └───────────────┘\             │                         │
                   \____________└─────────────────────────┘
```

## Helpful commands

* Powershell
  * Use the following command to compute the SHA1 hash of a file:
    > Get-FileHash -Algorithm SHA1 `<file>`
* Bash
  * Use the following command to compute the SHA1 hash of a file:
    > sha1sum `<file>`
