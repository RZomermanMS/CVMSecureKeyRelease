
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
    #attesting the client 
    $Path=Preqs #loading prerequisits
    LoadJWTModule #loading the JWT modules
    $report=Attest -Path $path -attestationTenant $attestationTenant
    Write-host " Validating Claims"
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
    }
}
if ($mode -eq "key" -or $mode -eq "full"){
    #need to load preq's for key retrieval - including Az modules
    LoadJWTModule
    ValidateAZModule
    $Policy=GetKeyDetails -KeyURL $KeyURL
    write-host "Key Release Policy:" -ForegroundColor Blue
    $jsonObject = $Policy | ConvertFrom-Json
    $prettyJson = $jsonObject | ConvertTo-Json -Depth 10
    write-host $prettyJson
}

if ($mode -eq "full"){

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
                            write-host "Report: " -NoNewline -ForegroundColor Blue
                            write-host $Report.($splitclaim[0].ToString()).($splitclaim[1].ToString()) -ForegroundColor Green
                            write-host "Claim:  "   -NoNewline -ForegroundColor Blue
                            write-host $claim.Equals  -ForegroundColor Green
                            If ($match -eq $null){
                                $match=$true
                            }
                        }else{
                            write-host "Report: " -NoNewline -ForegroundColor Blue
                            Write-host $Report.($splitclaim[0].ToString()).($splitclaim[1].ToString()) -ForegroundColor Red
                            write-host "Claim:  "  -NoNewline -ForegroundColor Blue
                            Write-host $claim.Equals  -ForegroundColor Red
                            If ($match -eq $true -or $match -eq $null){
                                $match=$false
                            }
                        }    
                    }
                }else{
                    if ($Report.($claim.claim)){
                        if ($Report.($claim.claim) -eq $claim.Equals){
                            write-host "Report: " -NoNewline -ForegroundColor Blue
                            Write-host $Report.($claim.claim) -ForegroundColor Green
                            write-host "Claim:  "  -NoNewline -ForegroundColor Blue
                            Write-host $claim.Equals -ForegroundColor Green
                            If ($match -eq $null){
                                $match=$true
                            }
                        }else{
                            write-host "Report: "  -NoNewline -ForegroundColor Blue
                            write-host $Report.($claim.claim) -ForegroundColor Red
                            write-host "Claim:  "   -NoNewline -ForegroundColor Blue
                            write-host $claim.Equals -ForegroundColor Red
                            If ($match -eq $true -or $match -eq $null){
                                $match=$false
                            }
                        }

                    }
                }
            }

        }
 
    if ($match) {
        Write-host ""
        Write-host "VM attestation fulfills key requirements, key release validated" -ForegroundColor Green
    }else{
        Write-host ""
        Write-host "VM attestation DOES NOT MEET key requirements" -ForegroundColor Red
    }

            

}
  

