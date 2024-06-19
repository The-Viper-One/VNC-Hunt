## About

A small PowerShell script that hunts for local VNC encrypted passwords and decrypts them.

### Usage
Load into memory
```
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/VNC-Hunt/main/VNC-Hunt.ps1")
```
Hunt for VNC credentials
```
VNC-Hunt
```
Decrypt supplied encrypted password value
```
VNC-Decrypt -Password FACBCF50C3BF1C08
```

![image](https://github.com/The-Viper-One/VNC-Hunt/assets/68926315/8867a265-7afc-4ff2-a9d2-4f0894326199)

