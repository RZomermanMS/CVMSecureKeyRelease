Function Preqs(){
    #Check if running on proper Powershell version
    write-host "Powershell version " -NoNewline -ForegroundColor Blue
    If ($PSVersionTable.PSVersion.Major -lt "7"){
        write-host "invalid" -ForegroundColor Red
        throw "Did not find Powershell version 7 or higher"
    }else{
        write-host "ok" -ForegroundColor Green
    }
    
    
    # Check if AttestationClient* exists.
    write-host "AttestionClient Software " -NoNewline -ForegroundColor Blue
    [array]$fileExists=Get-Childitem –Path $pwd.path -Include *AttestationClientApp.exe -Recurse -ErrorAction SilentlyContinue
    if (!$fileExists) {
        write-host "trying to download it from 'https://github.com/Azure/confidential-computing-cvm-guest-attestation'." -ForegroundColor Yellow
        $validate=Invoke-WebRequest -uri "https://github.com/Azure/confidential-computing-cvm-guest-attestation/raw/refs/heads/main/cvm-platform-checker-exe/Windows/cvm_windows_attestation_client.zip" -OutFile "cvm_windows_attestation_client.zip"
        If ((!($validate))){
            throw "AttestationClient binary could not be downloaded"
        }
        if (test-path ".\cvm_windows_attestation_client.zip"){
            write-host " - expanding archive"
            Expand-Archive ".\cvm_windows_attestation_client.zip" -DestinationPath $pwd.path -force   
            $env:Path += (';'+ $pwd.path + '\cvm_windows_attestation_client')
        }else{
            throw "AttestationClient binary could not be found"
        }
    }else{
        $AttestationClientPath=$fileExists[0].DirectoryName
        Write-host "found " -NoNewline -ForegroundColor Green
        write-host $AttestationClientPath
        if ($env:path -split ';' -notcontains $AttestationClientPath){
            write-host " - added to environment variable" -ForegroundColor Yellow
            $env:Path += (';'+$AttestationClientPath)
        }
    }

    #Validate VC Redistributable
        Write-host "VC Redistributable " -NoNewline -ForegroundColor Blue
        # Define registry paths for 32-bit and 64-bit applications
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        # Search for Visual C++ Redistributables
        $vcRedists = foreach ($path in $regPaths) {
            Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like "*Visual C++*Redistributable*"
            } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }

        # Output results
        if ($vcRedists) {
            Write-Host "installed" -ForegroundColor Green
        } else {
            Write-Host "Not found. Installing" -ForegroundColor Yellow
            $vcProcess = Start-Process -FilePath ($pwd.path + '\cvm_windows_attestation_client\VC_redist.x64.exe') -ArgumentList "/install /passive /norestart" -Wait -PassThru
            
            # Check the exit code of the process
            if ($vcProcess.ExitCode -ne 0) {
                Write-Host "Error: VC redistributable installation failed with exit code $($vcProcess.ExitCode)" -ForegroundColor Red
                exit $vcProcess.ExitCode
            } else {
                Write-Host "VC redistributable installed successfully." -ForegroundColor Green
            }
        }


    $path=$pwd.path
    return $path
}

Function LoadJWTModule(){
    #Check JWT Module
    write-host "Checking JWT Details module " -ForegroundColor Blue -NoNewline
    $JWTInstalled=get-module -ListAvailable -Name "JWTDetails"
    If ($JWTInstalled){
        write-host "found " -ForegroundColor Green -NoNewline
        import-module -Name JWTDetails
        If (get-module -Name JWTDetails){
            write-host "loaded" -ForegroundColor Green
        }
    }else{
        write-host "not found - Installing " -ForegroundColor Yellow -NoNewline
        install-module -name JWTDetails -Force
        import-module -Name JWTDetails
        If (get-module -Name JWTDetails){
            write-host "loaded" -ForegroundColor Green
        }
    }
}

Function GetToken($keyURL){
    write-host "Retriving acces token for " -NoNewline -ForegroundColor Blue
    if ($KeyURL -match "vault.azure"){
            write-host "Keyvault" -NoNewline -ForegroundColor Green
            $imdsUrl = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
        }elseif($KeyURL -match ".managedhsm.azure.net"){
            $imdsUrl = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://managedhsm.azure.net'
        }else{
            throw "Wrong KeyURL"
        }  
    $kvTokenResponse = Invoke-WebRequest -Uri  $imdsUrl -Headers @{Metadata = "true" }
    if ($kvTokenResponse.StatusCode -ne 200) {
        throw "Unable to get access token. Ensure Azure Managed Identity is enabled."
    }
    $kvAccessToken = ($kvTokenResponse.Content | ConvertFrom-Json).access_token
    return $kvAccessToken
}
Function Attest($path,$attestationTenant){
    write-host "Attestation:" -ForegroundColor Blue -NoNewline
    #$attestedPlatformReportJwt = Invoke-Expression -Command $cmd
    $attestedPlatformReportJwt = & "$path\AttestationClientApp.exe" -o token -a $AttestationTenant
    if (!$attestedPlatformReportJwt.StartsWith("eyJ")) {
        throw "AttestationClient failed to get an attested platform report."
    }else{
        write-host " OK" -ForegroundColor Green -NoNewline 
        return $attestedPlatformReportJwt
    }
    
}

Function ValidateAZModule{
    #validate if the AZ module is available and if user is signed-in
    write-host "AZ.Accounts module " -NoNewline -ForegroundColor Blue
    $modules=Get-Module -ListAvailable -Name Az.Accounts
    if (!($Modules)){
        write-host "not found installing " -ForegroundColor Yellow -NoNewline
        Install-Module -Name AZ.Accounts -Force
        Install-Module -Name AZ.KeyVault -Force
        Import-Module -Name Az.Accounts
        Import-Module -Name Az.KeyVault
        If (get-module -Name Az.accounts){
            write-host "loaded" -ForegroundColor Green
        }
    }else{
        write-host "found " -ForegroundColor Green -NoNewline
        Import-Module -Name Az.Accounts
        If (get-module -Name Az.Accounts){
            write-host "loaded" -ForegroundColor Green
        }
    }
    write-host "AZ.KeyVault module " -NoNewline -ForegroundColor Blue
    $modules=Get-Module -ListAvailable -Name Az.KeyVault
    if (!($Modules)){
        write-host "not found installing " -ForegroundColor Yellow -NoNewline
        Install-Module -Name AZ.KeyVault -Force
        Import-Module -Name Az.KeyVault
        If (get-module -Name Az.KeyVault){
            write-host "loaded" -ForegroundColor Green
        }
    }else{
        write-host "found " -ForegroundColor Green -NoNewline
        Import-Module -Name Az.KeyVault
        If (get-module -Name Az.KeyVault){
            write-host "loaded" -ForegroundColor Green
        }
    }

    #Validating login info
    $Context=Get-AzContext
    If (!($Context)){
        #need to sign in to azure
        Connect-AzAccount
    }
    If ($Context){
        Write-host "Logged in to: "  -NoNewline -ForegroundColor Blue
        Write-host  $Context.Subscription.Name -NoNewline -ForegroundColor Green
        write-host (" " + $Context.Subscription.id) -ForegroundColor Green
    }else{
        throw "Could not sign-in"
    }
}

function Find-ClaimValueIterative {
    param (
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string]$ClaimKey
    )

    # Initialize stack as an array and create a hashset for visited items
    $stack = @($Object)
    $visited = @{}

    while ($stack.Count -gt 0) {
        # Remove the last item safely (simulate stack pop)
        $current = $stack[-1]
        $stack = if ($stack.Count -gt 1) { $stack[0..($stack.Count - 2)] } else { @() }

        # Generate a unique identifier for the current object (to track visited)
        $objectHash = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($current)

        # Skip if we've already visited this object
        if ($visited.ContainsKey($objectHash)) {
            continue
        }

        # Mark this object as visited
        $visited[$objectHash] = $true

        if ($current -is [PSCustomObject] -or $current -is [System.Collections.IDictionary]) {
            # Check for the desired claim
            if ($current.PSObject.Properties.Name -contains 'claim' -and $current.claim -eq $ClaimKey) {
                return $current.equals
            }

            # Add all object properties to the stack (using .Add())
            foreach ($value in $current.PSObject.Properties.Value) {
                if ($value) {
                    $stack = $stack + $value
                }
            }
        } elseif ($current -is [System.Collections.IEnumerable] -and -not ($current -is [string])) {
            # If it's an array, add its items to the stack
            foreach ($item in $current) {
                if ($item) {
                    $stack = $stack + $item
                }
            }
        }
    }

    # Return null if the claim isn't found
    return $null
}
function Get-Authority {
    param (
        [Parameter(Mandatory)]
        $JsonObject
    )

    $authorities = @()

    # If the object has 'authority', collect it
    if ($JsonObject.PSObject.Properties['authority']) {
        $authorities += $JsonObject.PSObject.Properties['authority'].Value
    }

    # Iterate through arrays or objects
    foreach ($property in $JsonObject.PSObject.Properties) {
        $value = $property.Value

        if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
            foreach ($item in $value) {
                $authorities += Get-Authority -JsonObject $item
            }
        } elseif ($value -is [PSCustomObject]) {
            $authorities += Get-Authority -JsonObject $value
        }
    }

    return $authorities
}
function Convert-ToClaimArray {
    param (
        [Parameter(Mandatory)]
        $JsonObject
    )

    # Initialize an array to hold the claim values
    $claims = @()

    # If the object is an array, iterate through each element
    if ($JsonObject -is [System.Collections.IEnumerable] -and $JsonObject -isnot [string]) {
        foreach ($item in $JsonObject) {
            $claims += Convert-ToClaimArray -JsonObject $item
        }
    }
    # If the object is a dictionary or PSCustomObject (or System.Object), check each property
    elseif ($JsonObject -is [System.Management.Automation.PSCustomObject] -or $JsonObject -is [System.Collections.IDictionary]) {
        Write-host "1"
        foreach ($key in $JsonObject.PSObject.Properties.Name) {
            $item = $JsonObject.$key

            # If we find a "claim", collect it along with the "equals" value
            if ($key -eq 'claim' -and $item) {
                $claimValue = $JsonObject.equals
                if ($claimValue) {
                    $claims += [PSCustomObject]@{
                        Claim = $item
                        Equals = $claimValue
                    }
                }
            }

            # If the item is an object or array, recurse into it
            if ($item -is [System.Management.Automation.PSCustomObject] -or $item -is [System.Collections.IEnumerable]) {
                $claims += Convert-ToClaimArray -JsonObject $item
            }
        }
    }
    # Check if the object is a System.Object (generic object)
    elseif ($JsonObject -is [System.Object]) {
        $properties = $JsonObject.PSObject.Properties
        foreach ($property in $properties) {
            $item = $property.Value
            if ($property.Name -eq 'claim' -and $item) {
                $claimValue = $JsonObject.equals
                if ($claimValue) {
                    $claims += [PSCustomObject]@{
                        Claim = $item
                        Equals = $claimValue
                    }
                }
            }

            # If the item is an object or array, recurse into it
            if ($item -is [System.Management.Automation.PSCustomObject] -or $item -is [System.Collections.IEnumerable]) {
                $claims += Convert-ToClaimArray -JsonObject $item
            }
        }
    }

    return $claims
}

function Get-AllClaims {
    param (
        [Parameter(Mandatory)]
        $JsonObject
    )

    # Initialize an array to hold the claim values
    $claims = @()

    # If the object is an array, iterate through each element
    if ($JsonObject -is [System.Collections.IEnumerable] -and $JsonObject -isnot [string]) {
        foreach ($item in $JsonObject) {
            $claims += Get-AllClaims -JsonObject $item
        }
    }
    # If the object is a dictionary or PSCustomObject, check each property
    elseif ($JsonObject -is [System.Management.Automation.PSCustomObject] -or $JsonObject -is [System.Collections.IDictionary]) {
        foreach ($key in $JsonObject.PSObject.Properties.Name) {
            $item = $JsonObject.$key

            # If we find a "claim", collect it along with the "equals" value
            if ($key -eq 'claim' -and $item) {
                $claimValue = $JsonObject.equals
                if ($claimValue) {
                    $claims += [PSCustomObject]@{
                        Claim = $item
                        Equals = $claimValue
                    }
                }
            }

            # If the item is an object or array, recurse into it
            if ($item -is [System.Management.Automation.PSCustomObject] -or $item -is [System.Collections.IEnumerable]) {
                $claims += Get-AllClaims -JsonObject $item
            }
        }
    }

    return $claims
}


function Find-ClaimValue {
    param (
        [Parameter(Mandatory)]
        $JsonObject,

        [Parameter(Mandatory)]
        [string]$ClaimKey
    )

    # If the object is an array, iterate through each element
    if ($JsonObject -is [System.Collections.IEnumerable] -and $JsonObject -isnot [string]) {
        foreach ($item in $JsonObject) {
            $result = Find-ClaimValue -JsonObject $item -ClaimKey $ClaimKey
            if ($result) { return $result }
        }
    }
    # If the object is a dictionary or PSCustomObject, check each property
    elseif ($JsonObject -is [System.Management.Automation.PSCustomObject] -or $JsonObject -is [System.Collections.IDictionary]) {
        foreach ($key in $JsonObject.PSObject.Properties.Name) {
            $item = $JsonObject.$key

            # Check if this property is the claim we're looking for
            if ($key -eq 'claim' -and $item -eq $ClaimKey) {
                return $JsonObject.equals
            }

            # If the item is an object or array, recurse into it
            if ($item -is [System.Management.Automation.PSCustomObject] -or $item -is [System.Collections.IEnumerable]) {
                $result = Find-ClaimValue -JsonObject $item -ClaimKey $ClaimKey
                if ($result) { return $result }
            }
        }
    }

    # Return null if no match is found
    return $null
}

Function GetKeyDetails($keyURL){
    #Determine based on URL is vault is MHSM or KeyVault
    write-host "Key stored in " -NoNewline -ForegroundColor Blue
    if ($KeyURL -match "vault.azure"){
            write-host "Keyvault" -NoNewline -ForegroundColor Green
            $akvtype = "KeyVault"
            $akvname = ($KeyURL -split ".vault.azure" -split "//")[1]
            $keyname=($KeyURL -split "/keys/" -split "/")[3]
        }elseif($KeyURL -match ".managedhsm.azure.net"){
            write-host "Managed HSM " -NoNewline -ForegroundColor Green
            $akvtype = "MHSM"
            $akvname = ($KeyURL -split ".managedhsm.azure.net" -split "//")[1]
            $keyname=($KeyURL -split "/keys/" -split "/")[3]
        }else{
            throw "Wrong KeyURL"
        }
    If ($akvtype -eq "MHSM"){
        write-host "retrieving key " -ForegroundColor Yellow -NoNewline
        $keyDetails=Get-AzKeyVaultKey -HsmName $akvname -Name $keyname
    }else{
        write-host "retrieving key " -ForegroundColor Yellow -NoNewline
        $keyDetails=Get-AzKeyVaultKey -VaultName $akvname -Name $keyname
    }
    #validating Key Release Policy
    If (!($keyDetails.ReleasePolicy)){
        throw "Key Policy does not exist - key will not be exportable"
    }else{
        write-host "ok" -ForegroundColor Green
        $PolicyContent=$keyDetails.ReleasePolicy.PolicyContent
        return $PolicyContent
    }
}

