# Contents of the PostSigned Folder

The `PostSignedObjects` folder of the Secureboot objects repo contains the Microsoft KEK signed version of the secure boot objects' contents that are recommended by Microsoft to set as the default DB and DBX variables, as well as the Microsoft KEK and PK.
The DBX folder contains the list of revoked 3rd party UEFI applications. The bin folder contains the signed DB and DBX update packages and is broken down into subsections based on device architecture. The contents of the signed DBX folder should match the contents of the DBX folder in the Keystore folder. Please note, DB and DBX update packages generated from the keystore folder are unsigned by the Microsoft KEK.

The optional folder contains a set of DB and DBX update packages that are currently being shipped as optional servicing updates and would require extra precaution in its application to devices.
The DB2024 folder contains the Microsoft Windows UEFI 2023 CA. This DB update package was shipped as part of the February 13th, 2024, servicing and preview updates, as an optional update,  which can be manually applied to devices. Microsoft will also slowly roll out this DB update as we validate devices and firmware compatibility globally. Please refer to Updating Microsoft Secure Boot keys | Windows IT Pro blog to gain a proper understanding of this DB update package, its benefits and the potential risks with applying the package to your device.
The DBX2024 folder contains the Microsoft Windows Production PCA 2011 and SVN value to revoke all Windows boot managers signed with the Microsoft Windows Production PCA 2011. This update was shipped as part of the April 9th, 2024, servicing and preview updates as an optional update.


## Caution

**`DO NOT`** apply the DBX2024 update or DBXUpdateSVN.bin to a device without DB update through manual update, using set-securebootuefi, as the system will not boot. Specifically, this will bypass the safety checks included in the Microsoft servicing tool (Windows Updates) to guard against breaking issues. Please refer to [Revoking vulnerable Windows boot managers](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/revoking-vulnerable-windows-boot-managers/ba-p/4121735) to gain a proper understanding of this DBX update package, the threat landscape it addresses and the potential risks with applying the package to your device.

### Additional Resources

* For more detailed instructions on applying the DBX updates, please visit [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d?preview=true)
* For guidance on manually applying DB update, please visit [Updating Microsoft Secure Boot keys](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/updating-microsoft-secure-boot-keys/ba-p/4055324)
* In the case of errors while applying the DB update, please visit[KB5016061](https://support.microsoft.com/en-us/topic/kb5016061-secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69)
