## About

PowerShell script that takes an encrypted VNC password value and decrypts it using a well known fixed key.

### Usage
Load into memory
```
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/VNC-Decrypt/main/VNC-Decrypt.ps1")
```
Decrypt supplied encrypted password value
```
VNC-Decrypt -Password FACBCF50C3BF1C08
```
