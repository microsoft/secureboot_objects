# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This module provides utility functions and classes for handling secure boot objects.

including SVN data, signature databases, and secure boot payloads.
"""

import hashlib
import pathlib
import struct
from dataclasses import dataclass
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiSignatureDatabase,
    EfiSignatureDataEfiCertSha256,
    EfiSignatureDataEfiCertX509,
    EfiVariableAuthentication2,
)
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules import rfc2315

# All SVNs will have this as the "signature_owner" and then map to a per app guid in the hash field
SVN_OWNER_GUID = svn_guid = UUID("9d132b6c-59d5-4388-ab1c-185cfcb2eb92")


@dataclass
class BootAppSvn:
    """BootAppSvn class represents a boot application security version number (SVN) with major and minor components.

    Attributes:
        major_svn (int): The major security version number.
        minor_svn (int): The minor security version number.
    Properties:
        as_uint32 (int): Converts the major_svn and minor_svn attributes to a single 32-bit unsigned integer.

    Methods:
        from_uint32(cls, value): Creates an instance of the class from a 32-bit unsigned integer.
    """

    major_svn: int
    minor_svn: int

    @property
    def as_uint32(self) -> int:
        """Converts the major_svn and minor_svn attributes to a single 32-bit unsigned integer.

        The major_svn is shifted left by 16 bits and combined with minor_svn using a bitwise OR operation.

        Returns:
            int: A 32-bit unsigned integer representing the combined major_svn and minor_svn.
        """
        return (self.major_svn << 16) | self.minor_svn

    @classmethod
    def from_uint32(cls, value: int) -> "BootAppSvn":
        """Create an instance of the class from a 32-bit unsigned integer.

        Args:
            cls: The class to create an instance of.
            value (int): A 32-bit unsigned integer containing the major_svn and minor_svn values.

        Returns:
            An instance of the class with the major_svn and minor_svn values extracted from the input integer.
        """
        minor_svn = value & 0xFFFF
        major_svn = (value >> 16) & 0xFFFF
        return cls(minor_svn=minor_svn, major_svn=major_svn)


@dataclass
class SvnData:
    """A data class representing SVN (Secure Version Number) data.

    Attributes:
        version (int): The version number.
        application_guid (UUID): The application GUID.
        svn (BootAppSvn): The SVN value.
        reserved (bytes): reserved bytes for future use.
    """

    version: int
    application_guid: UUID
    svn: BootAppSvn
    reserved: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SvnData":
        """Creates an instance of svnData from a bytes object.

        Args:
            data (bytes): The bytes object containing the SVN data.

        Returns:
            svnData: An instance of svnData populated with the data from the bytes object.
        """
        (version,) = struct.unpack_from("B", data, 0)
        application_guid = UUID(bytes_le=data[1:17])
        (svn_value,) = struct.unpack_from("I", data, 17)
        svn = BootAppSvn.from_uint32(svn_value)
        reserved = data[21:32]
        return cls(version=version, application_guid=application_guid, svn=svn, reserved=reserved)

    def to_bytes(self) -> bytes:
        """Converts the svnData instance to a bytes object.

        Returns:
            bytes: A bytes object representing the svnData instance.
        """
        data = struct.pack("B", self.version)
        data += self.application_guid.bytes
        data += struct.pack("I", self.svn.as_uint32)
        data += self.reserved
        return data


def get_latest_revocation_list(path: pathlib.Path) -> pathlib.Path:
    """Get the latest revocation list JSON file from the specified directory.

    Args:
        path (pathlib.Path): The directory path to search for JSON files.

    Returns:
        pathlib.Path: The path to the latest revocation list JSON file.

    Raises:
        FileNotFoundError: If no JSON files are found in the specified directory.
    """
    json_files = list(path.glob("*.json"))
    if not json_files:
        raise FileNotFoundError("No JSON files found in the specified directory.")

    latest_file = max(json_files, key=lambda f: list(map(int, f.stem.split("_")[-3:])))
    return latest_file


def describe_signature_list(signature_database: EfiSignatureDatabase) -> list:
    """Given a signature database, this function documents the contents.

    Args:
        signature_database (EfiSignatureDatabase): The signature database to describe.

    Returns:
        list: A list of dictionaries containing the signature information.
    """
    readable_signature_database = []

    for signature in signature_database.esl_list:
        for a in signature.signature_data_list:
            if type(a) is EfiSignatureDataEfiCertSha256:
                if a.signature_owner == SVN_OWNER_GUID:
                    signature = a.signature_data.hex().upper()
                    svn_data = SvnData.from_bytes(a.signature_data)
                    readable_signature_database.append(
                        {"authenticodeHash": signature, "signatureOwner": str(a.signature_owner), "svn": str(svn_data)}
                    )
                else:
                    signature = a.signature_data.hex().upper()
                    readable_signature_database.append(
                        {"authenticodeHash": signature, "signatureOwner": str(a.signature_owner)}
                    )
            elif type(a) is EfiSignatureDataEfiCertX509:
                cert = x509.load_der_x509_certificate(a.signature_data)

                thumbprint = hashlib.sha1(a.signature_data).hexdigest().upper()

                readable_signature_database.append(
                    {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "thumbprint": thumbprint,
                        "signatureOwner": str(a.signature_owner),
                    }
                )

    return readable_signature_database


class EmptyCertificate:
    """A class representing an empty certificate."""
    def __init__(self) -> None:
        """Initialize an EmptyCertificate instance."""
        self.subject = self
        self.issuer = self

    def rfc4514_string(self) -> str:
        """Return a string representation of the certificate in RFC 4514 format."""
        return "EMPTY PKCS7 SIGNATURE"

def get_certificates(auth_var: EfiVariableAuthentication2) -> list:
    """Get the certificates from the authenticated variable.

    Args:
        auth_var (EfiVariableAuthentication2): The authenticated variable.

    Returns:
        list: a list of certificates
    """
    asn1_signed_Data, _ = der_decode(auth_var.auth_info.cert_data, asn1Spec=rfc2315.SignedData())
    content_info = rfc2315.ContentInfo()
    content_info.setComponentByName("contentType", rfc2315.signedData)
    content_info.setComponentByName("content", asn1_signed_Data)

    signature = der_encode(content_info)

    try:
        certificates = pkcs7.load_der_pkcs7_certificates(signature)
    except ValueError:
        certificates = [EmptyCertificate()]

    return certificates

def get_signed_payload_receipt(signed_efi_sig_database: pathlib.Path) -> dict:
    """Parse a signed secure boot payload.

    Args:
        signed_efi_sig_database (pathlib.Path): The path to the secure boot payload file.

    Returns:
        None
    """
    receipt = {}

    with open(signed_efi_sig_database, "rb") as f:
        # Read the contents of the file
        contents = f.read()

        ## Now we can parse the SignatureDatabase
        f.seek(0)
        auth_var = EfiVariableAuthentication2(decodefs=f)

        certs = get_certificates(auth_var)

        receipt["fileName"] = signed_efi_sig_database.name
        receipt['fileHash'] = hashlib.sha256(contents).hexdigest().upper()
        auth_var_info = {
            "timeStamp": str(auth_var.time),
            "certificates": [{
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
            } for cert in certs]
        }
        receipt["authenticatedVariableInfo"] = auth_var_info

        signature_database = auth_var.sig_list_payload

        # Now we can parse the SignatureDatabase
        readable_signature_database = describe_signature_list(signature_database)

        receipt["signatureDatabase"] = readable_signature_database

    return receipt


def get_unsigned_payload_receipt(efi_sig_database: pathlib.Path) -> dict:
    """Parse a signed secure boot payload.

    Args:
        efi_sig_database (pathlib.Path): The path to the secure boot payload file.

    Returns:
        None
    """
    receipt = {}

    with open(efi_sig_database, "rb") as f:
        # Read the contents of the file
        contents = f.read()

        ## Now we can parse the SignatureDatabase
        f.seek(0)
        signature_database = EfiSignatureDatabase(filestream=f)

        receipt["fileName"] = efi_sig_database.name
        receipt['fileHash'] = hashlib.sha256(contents).hexdigest().upper()

        # Now we can parse the SignatureDatabase
        readable_signature_database = describe_signature_list(signature_database)

        receipt["signatureDatabase"] = readable_signature_database

    return receipt
