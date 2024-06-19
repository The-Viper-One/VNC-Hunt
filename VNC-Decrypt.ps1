<#
.SYNOPSIS
    Decrypts a VNC password encrypted with DES using a fixed key.

.DESCRIPTION
    This PowerShell function decrypts a VNC password which is encrypted using the DES algorithm with a fixed key.
    The function performs the following steps:
    1. Converts the encrypted password from its hexadecimal representation to a byte array.
    2. Configures a DES decryptor with a fixed key and an all-zero initialization vector (IV).
    3. Uses CBC (Cipher Block Chaining) mode without padding.
    4. Decrypts the byte array using the configured DES decryptor.
    5. Converts the decrypted byte array back to an ASCII string and trims any trailing null characters.

.PARAMETER Password
    The VNC encrypted password in hexadecimal format.

.EXAMPLE
    VNC-Decrypt -Password FACBCF50C3BF1C08
#>

function VNC-Decrypt {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $encryptedBytes = [byte[]]::new($Password.Length / 2)
    for ($i = 0; $i -lt $Password.Length; $i += 2) {
        $encryptedBytes[$i / 2] = [Convert]::ToByte($Password.Substring($i, 2), 16)
    }

    try {

    $desKey = [byte[]](0xe8, 0x4a, 0xd6, 0x60, 0xc4, 0x72, 0x1a, 0xe0)
    $iv = [byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

    $des = [System.Security.Cryptography.DES]::Create()
    $des.Key = $desKey
    $des.IV = $iv
    $des.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $des.Padding = [System.Security.Cryptography.PaddingMode]::None

    $decryptor = $des.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    $decryptedPassword = ([System.Text.Encoding]::ASCII.GetString($decryptedBytes)).Trim([char]0)

    Write-Output "VNC Password: $decryptedPassword"

    }

    Catch {Write-Warning "Failure, bad data or insufficient key length supplied"}
}

