This repo combine UEFI certificates from Debian and Microsoft to enroll in setup mode.
Certificates included are:

- PK: WindowsOEMDevicesPK.der
- KEK:
  1. microsoft corporation kek 2k ca 2023.der
  2. MicCorKEKCA2011_2011-06-24.der
  3. debian-uefi-ca.der (KEK)

- DB:
  1. debian-prod-2022-fwupdate.pem
  2. debian-prod-2022-shim.pem
  3. debian-prod-2022-fwupd.pem
  4. debian-prod-2024-systemd-boot.pem
  5. debian-prod-2022-grub2.pem
  6. debian-prod-2022-linux.pem
  7. microsoft uefi ca 2023.der
  8. MicWinProPCA2011_2011-10-19.der
  9. MicCorUEFCA2011_2011-06-27.der
  10. windows uefi ca 2023.der
  11. microsoft option rom uefi ca 2023.der


Included DBX hashes are sourced from [Unsigned Secure Boot Payloads v1.4.0](https://github.com/microsoft/secureboot_objects/releases/tag/v1.4.0) in Microsoft Secure Boot Objects github repository
