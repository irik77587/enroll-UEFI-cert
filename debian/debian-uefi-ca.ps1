$time = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

Format-SecureBootUEFI -Name db -SignatureOwner 0e2efec0-ac32-55f7-9eb1-2d2854c38d77 `
 -CertificateFilePath debian-uefi-ca.der -SignableFilePath debian-uefi-ca.bin `
 -Time 2025-06-08T19:22:14Z -AppendWrite

Set-SecureBootUEFI -Name db -ContentFilePath debian-uefi-ca.bin -Time $time