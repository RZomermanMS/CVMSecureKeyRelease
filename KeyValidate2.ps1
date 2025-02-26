
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyURL,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$attestationTenant,

    [Parameter(Mandatory = $true)]
    [ValidateSet("full", "attest", "key")]
    [string]$Mode="attest"
)

# Conditional validation
if (($Mode -eq "full" -or $Mode -eq "key") -and [string]::IsNullOrEmpty($KeyURL)) {
    throw "Parameter -KeyURL is mandatory when -Mode is set to 'full' or 'key'."
}
if (($Mode -eq "full" -or $Mode -eq "attest") -and [string]::IsNullOrEmpty($attestationTenant)) {
    throw "Parameter -attestationTenant is mandatory when -Mode is set to 'full' or 'attest'."
}


    #Attest mode allows for either direct attestation of the VM
    #Key mode allows for extracting key release details
    #full mode combines both and validates claims and parameters 


#Loading PSM1 module
If (Get-Module -Name KeyValidate){
    Remove-Module -Name KeyValidate
}
Import-Module -Name .\KeyValidate.psm1


        #Cosmetic stuff
        write-host ""
        write-host ""
        write-host "                               _____        __                                " -ForegroundColor Green
        write-host "     /\                       |_   _|      / _|                               " -ForegroundColor Yellow
        write-host "    /  \    _____   _ _ __ ___  | |  _ __ | |_ _ __ __ _   ___ ___  _ __ ___  " -ForegroundColor Red
        write-host "   / /\ \  |_  / | | | '__/ _ \ | | | '_ \|  _| '__/ _' | / __/ _ \| '_ ' _ \ " -ForegroundColor Cyan
        write-host "  / ____ \  / /| |_| | | |  __/_| |_| | | | | | | | (_| || (_| (_) | | | | | |" -ForegroundColor DarkCyan
        write-host " /_/    \_\/___|\__,_|_|  \___|_____|_| |_|_| |_|  \__,_(_)___\___/|_| |_| |_|" -ForegroundColor Magenta
        write-host "     "
        write-host " This script validates your VM and KeyRelease Options" -ForegroundColor "Green"
    
        write-host ""
        write-host ""




If ($mode -eq "full" -or $mode -eq "attest"){
    write-host ""
    Write-host " ******************"
    Write-host " Attestation for VM"
    Write-host " ******************"
    #attesting the client 
    $Path=Preqs #loading prerequisits
    LoadJWTModule #loading the JWT modules
    $attestedPlatformReportJwt=Attest -Path $path -attestationTenant $attestationTenant
    $report = Get-JWTDetails($attestedPlatformReportJwt)  
    If ($Report){
        $xmsattestationtype=$Report.'x-ms-attestation-type'
        $xmsazurevmvmid=$Report.'x-ms-azurevm-vmid'
        $xmsisolationteexmsattestationtype=$Report.'x-ms-isolation-tee'.'x-ms-attestation-type'
        $xmsisolationteeXmscompliancestatus=$Report.'x-ms-isolation-tee'.'x-ms-compliance-status'
        Write-host "x-ms-attestation-type " -NoNewline -ForegroundColor blue
        write-host $xmsattestationtype
        Write-host "x-ms-azurevm-vmid " -NoNewline -ForegroundColor blue
        write-host $xmsazurevmvmid
        Write-host "x-ms-isolation-tee" -ForegroundColor blue
        Write-host " - x-ms-attestation-type' " -NoNewline -ForegroundColor blue
        write-host $xmsisolationteexmsattestationtype
        Write-host " - x-ms-compliance-status' " -NoNewline -ForegroundColor blue
        write-host $xmsisolationteeXmscompliancestatus       
        If  ($mode -eq "attest"){ 
        return $attestedPlatformReportJwt
        }
    }
}
if ($mode -eq "key" -or $mode -eq "full"){
    write-host ""
    Write-host " *********************"
    Write-host " Key Policy Validation"
    Write-host " *********************"
    #need to load preq's for key retrieval - including Az modules
    LoadJWTModule
    ValidateAZModule
    $Policy=GetKeyDetails -KeyURL $KeyURL
    write-host "Key Release Policy:" -ForegroundColor Blue
    $jsonObject = $Policy | ConvertFrom-Json
    $prettyJson = $jsonObject | ConvertTo-Json -Depth 10
    write-host $prettyJson
    If ($mode -eq "key"){
        return $Policy
    }
}

if ($mode -eq "full"){
    Write-host " ********************************************"
    Write-host " Key Policy to VM Attestion Report Validation"
    Write-host " ********************************************"
        #get all claims from the key policy and validate if those match with the VM attestation report
        [array]$allClaims=Get-AllClaims -JsonObject $jsonObject
        $match=$null
        Foreach ($claim in $allClaims){
            write-host "Validating: " -ForegroundColor Blue -NoNewline
            write-host $claim.Claim 
            #need to break if claims contains a .
            #x-ms-isolation-tee.x-ms-attestation-type
            If ($claim.claim -match "."){
                $splitClaim = $claim.claim -split '\.'
                if ($splitclaim.count -gt 2){
                    throw "too many levels deep - too complex"
                }elseif($splitclaim.count -eq 2){
                    if ($Report.($splitclaim[0].ToString()).($splitclaim[1].ToString())){    
                        if ($Report.($splitclaim[0].ToString()).($splitclaim[1].ToString()) -eq $claim.Equals) {
                            write-host "Claim:  "   -NoNewline -ForegroundColor Blue
                            write-host $claim.Equals  -ForegroundColor Green
                            write-host "Report: " -NoNewline -ForegroundColor Blue
                            write-host $Report.($splitclaim[0].ToString()).($splitclaim[1].ToString()) -ForegroundColor Green
                            If ($match -eq $null){
                                $match=$true
                            }
                        }else{
                            write-host "Claim:  "  -NoNewline -ForegroundColor Blue
                            Write-host $claim.Equals  -ForegroundColor Red
                            write-host "Report: " -NoNewline -ForegroundColor Blue
                            Write-host $Report.($splitclaim[0].ToString()).($splitclaim[1].ToString()) -ForegroundColor Red
                            If ($match -eq $true -or $match -eq $null){
                                $match=$false
                            }
                        }    
                    }else{
                        write-host "Claim:  "   -NoNewline -ForegroundColor Blue
                        write-host $claim.Equals  -ForegroundColor Green
                        write-host "Report: " -NoNewline -ForegroundColor Blue
                        write-host "<missing>" -NoNewline -ForegroundColor Red

                        If ($match -eq $true -or $match -eq $null){
                            $match=$false
                        }
                    }
                }else{
                    if ($Report.($claim.claim)){
                        if ($Report.($claim.claim) -eq $claim.Equals){
                            write-host "Claim:  "  -NoNewline -ForegroundColor Blue
                            Write-host $claim.Equals -ForegroundColor Green
                            write-host "Report: " -NoNewline -ForegroundColor Blue
                            Write-host $Report.($claim.claim) -ForegroundColor Green

                            If ($match -eq $null){
                                $match=$true
                            }
                        }else{
                            write-host "Claim:  "   -NoNewline -ForegroundColor Blue
                            write-host $claim.Equals -ForegroundColor Red
                            write-host "Report: "  -NoNewline -ForegroundColor Blue
                            write-host $Report.($claim.claim) -ForegroundColor Red
                            If ($match -eq $true -or $match -eq $null){
                                $match=$false
                            }
                        }
                    }else{
                        write-host "Claim:  "   -NoNewline -ForegroundColor Blue
                        write-host $claim.Equals -ForegroundColor Red
                        write-host "Report: "   -NoNewline -ForegroundColor Blue
                        write-host "<missing>" -ForegroundColor Red
                        If ($match -eq $true -or $match -eq $null){
                            $match=$false
                        }
                        
                    }

                }
            }

        }
        #Authority matching
        $authorityMatch=$false
        write-host "Validating " -ForegroundColor Blue -NoNewline
        write-host "authority"
        [array]$Authority=Get-Authority -JsonObject $jsonObject
        if ($Authority -eq $report.iss){
            write-host "Claim:  "   -NoNewline -ForegroundColor Blue
            write-host $Authority -ForegroundColor Green
            write-host "Report: "   -NoNewline -ForegroundColor Blue
            write-host $Report.iss -ForegroundColor Green
            $authorityMatch=$true
        }else{
            write-host "Claim:  "   -NoNewline -ForegroundColor Blue
            write-host $Authority -ForegroundColor Yellow
            write-host "Report: "   -NoNewline -ForegroundColor Blue
            write-host $Report.iss -ForegroundColor Yellow
        }
 
    if ($match) {
        Write-host ""
        Write-host "VM attestation fulfills key requirements, key release validated" -ForegroundColor Green
    }else{
        Write-host ""
        Write-host "VM attestation DOES NOT MEET key requirements" -ForegroundColor Red
    }
    if (!($authorityMatch)){
        Write-host "Validate the authority URL's they have a mismatch" -ForegroundColor Yellow
    }

    If ($match){
        $kvAccessToken=GetToken -KeyURL $KeyURL
        #decode the token to get to the identities
        $ATObject=Get-JWTDetails($kvAccessToken)
        Write-host "AppID: " -NoNewline -ForegroundColor Blue
        write-host $ATObject.appid

        $Key=($KeyURL -split "/")
        $vaultBaseUrl=($key[0] + "//" + $key[2])
        $KeyDetail=$keyUrl -split "/keys/" -split "/"
        $KeyName=$Keydetail[3]
        $KeyVersion=$KeyDetail[4]
        if ([string]::IsNullOrEmpty($keyVersion)) {
            $kvReleaseKeyUrl = "{0}/keys/{1}/release?api-version=7.3" -f $vaultBaseUrl, $keyName
        }else{
            $kvReleaseKeyUrl = "{0}/keys/{1}/{2}/release?api-version=7.3" -f $vaultBaseUrl, $keyName, $keyVersion
        }
        
        $kvReleaseKeyHeaders = @{
            Authorization  = "Bearer $kvAccessToken"
            'Content-Type' = 'application/json'
        }
        
        $kvReleaseKeyBody = @{
            target = $attestedPlatformReportJwt
        }
        $kvReleaseKeyResponse = Invoke-WebRequest -Method POST -Uri $kvReleaseKeyUrl -Headers $kvReleaseKeyHeaders -Body ($kvReleaseKeyBody | ConvertTo-Json)
        if ($kvReleaseKeyResponse.StatusCode -ne 200) {
            Write-Error -Message "Unable to perform release key operation."
            Write-Error -Message $kvReleaseKeyResponse.Content
        }
        else {
            $kvReleaseKeyResponse.Content | ConvertFrom-Json
            $retuenme=$kvReleaseKeyResponse.Content | ConvertFrom-Json
            if ($retuenme.count -gt 1){
                $returnValue=$retuenme[0].value
                $values=Get-JWTDetails($returnValue)
                $certInfo=$values.response.key.key
                $privKey=($values.response.key.key.key_hsm -replace '[^A-Za-z0-9+/=]', '')
                $padLength = 4 - ($cleanString.Length % 4)
                $privKey += '=' * $padLength
                $decodedBytes = [System.Convert]::FromBase64String($privKey)
                $decodedText = [System.Text.Encoding]::UTF8.GetString($decodedBytes)

            }
            return $retuenme
        }     
    }
}
  

