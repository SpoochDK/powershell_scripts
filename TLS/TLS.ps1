Function Disable-LegacyProtocol {

    $TLSArray = @(
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1"
    )

    Foreach ($item in $TLSArray) {
        ## Create the parent key for Server
        New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Server" -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Server" -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Server" -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    
        ## Create the parent key for Client
        New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Client" -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Client" -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Client" -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    }
}

Function Disable-WeakCipher {
    $insecureCiphers = @(
        'DES 56/56',
        'NULL',
        'RC2 128/128',
        'RC2 40/128',
        'RC2 56/128',
        'RC4 40/128',
        'RC4 56/128',
        'RC4 64/128',
        'RC4 128/128',
        'Triple DES 168'
    )

    $CipherPath = 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
    New-Item $CipherPath -Force | Out-Null
    foreach ($item in $insecureCiphers) {
        New-Item -Path "$cipherpath\$item"
        New-ItemProperty -Path "$cipherPath\$item" -Name Enabled -Value 0 -PropertyType 'DWord' -Force | Out-Null
    }
}

Function Enable-StrongCipher {
    $insecureCiphers = @(
        'AES 128/128',
        'AES 256/256'
    )

    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null

    foreach ($item in $insecureCiphers) {
        New-Item -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$item"
        New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$item" -Name Enabled -Value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
    }
}

Function Enable-ModernProtocol {

    $TLSArray = @(
        "TLS 1.2"
    )

    Foreach ($item in $TLSArray) {
        ## Create the parent key for Server
        New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Server" -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Server" -name Enabled -value "0xffffffff" -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Server" -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
    
        ## Create the parent key for Client
        New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Client" -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Client" -name Enabled -value "0xffffffff" -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$item\Client" -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
    }
}

Function Enable-SecureHash {
    $secureHashes = @(
        'SHA',
        'SHA256',
        'SHA384',
        'SHA512'
    )

    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes" -Force | Out-Null

    Foreach ($secureHash in $secureHashes) {
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
    }
}

Function Enable-SecureyKeyExchangeAlgorithm {
    $secureKeyExchangeAlgorithms = @(
        'Diffie-Hellman',
        'ECDH',
        'PKCS'
    )

    New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null

    Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null

    }
}

Function Enable-DiffieHellmanKeyExchange {
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ServerMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null  
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
}

Function Enable-TLSforDotNet {
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
    if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
        New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
    }
}

Function Enable-CipherSuiteOrder {
    $cipherSuitesOrder = @(
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
    )
    $cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
    # One user reported this key does not exists on Windows 2012R2. Cannot repro myself on a brand new Windows 2012R2 core machine. Adding this just to be save.
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue
    New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
 
}

Function Enable-TLSForWinHTTP {

    $file_version_winhttp_dll = (Get-Item $env:windir\System32\winhttp.dll).VersionInfo | 
    ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
    
    $file_version_webio_dll = (Get-Item $env:windir\System32\Webio.dll).VersionInfo | 
    ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
    
    if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
        Write-Error 'WinHTTP: Cannot enable TLS 1.2. Please see https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in for system requirements.'
    }
    else {
        New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
        if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
            # WinHttp key seems missing in Windows 2019 for unknown reasons.
            New-Item 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
        }
    }
 
    New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
 
}

function Get-SecurityProtocol {
    Param(
        [Parameter(Mandatory)]
        [ValidateSet(
            "SSL 2.0",
            "SSL 3.0",
            "TLS 1.0",
            "TLS 1.0",
            "TLS 1.1",
            "TLS 1.2"
        )]
        $Protocol,

        [String[]]
        $ComputerName
    )
    
    begin {
        $server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
        $client = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client"
    }
    
    process {
        ## Enabled key
        $server_enabled = Get-ItemProperty -Path $server -name 'Enabled' -ErrorAction SilentlyContinue
        $client_enabled = Get-ItemProperty -Path $client -name 'Enabled' -ErrorAction SilentlyContinue
        ## Disabled By Default Key

    }
    
    end {
        
    }
}

<#
$tls12 = try {
    $resp = (New-Object System.Net.WebClient).DownloadString("https://tls-v1-2.badssl.com:1012/")
    [bool] $resp.Contains("green")
}
catch {
    $false
}

$url ="https://stackoverflow.com/questions/51405489/what-is-the-difference-between-the-disabledbydefault-and-enabled-ssl-tls-registr"

$anotherurl = "https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#support-for-tls-12"
#>