The script has 3 modes (attest, key validation and full)

In full mode it runs through 3 steps (including attest and key) 

Attest
This functions validates if all perquisites for attestation are met, including installed software, modules etc. It is a direct derivative of the demo script provided by Microsoft.
It runs the attestation of the virtual machine using the Windows AttestationClient.exe software and ultimately returns the report of the VM attestation.
•	Returns attestation report in JWT format

Key
This functions validates if all perquisites for key policy validation are met, including installed AZ modules etc including AZ login.
This function validates the release policy of the provided key URL and ultimately spits out the key Policy itself in JSON format.
•	Returns KeyPolicy in JSON format

Full
Runs both Attest and Key functions of the script – then takes the key policy and tries to map the claims in that policy to the attestation report. If a match is found the output shows green. If a match is not found or a mismatch in values is found it comes back red. 

If all is green, the system will attempt to retrieve the key by performing
1.	Get an access token for either KeyVault or Managed HSM (http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://managedhsm.azure.net)
2.	Then invoking a webrequest to get the key released by invoking $kvReleaseKeyResponse = Invoke-WebRequest -Method POST -Uri $kvReleaseKeyUrl -Headers $kvReleaseKeyHeaders -Body ($kvReleaseKeyBody | ConvertTo-Json)
o	Where
	$kvReleaseKeyUrl = https://mhsmrcz01.managedhsm.azure.net/keys/SecureKey/adfc5183bd6246e18f21cdebf963b9dc  (built from vaultName + keyname + keyversion)
	$kvReleaseKeyHeaders = “Bearer AccessToken from step 1 – content-type = application/json
	$kvReleaseKeyBody =$kvReleaseBody (the attestion report from the “attest” function of the script
3.	The webrequest (if successful) provides a response with the retrieved key which we need to convert back to JSON – we clean it up a bit and then done
o	$kvReleaseKeyResponse.Content | ConvertFrom-Json
o	Which is then returned in as an object to the user

•	Returns ReleaseKeyResponse object


The supporting modules (loaded in KeyValidate.psm1 can also be used independently, this file is reloaded every time the main script runs:
•	PREQS – validates if all prerequisites for attestation are met. Including
o	PowerShell 7
o	Attestation Software to be found in current directory (recursive) and adding to path variable
o	VC Redistributable validates if installed or installs it for you
•	LoadJWTModule – validates if the required JWT Module (for decoding JWT text) is installed – or installs and loads it
•	DecodeBas64 – for decoding base64 text (and validating input text)
•	ValidateAZModule – validates if AZ.Accounts and AZ.Keyvault are installed and loaded – or installs and load them
•	Get-AllClaims – finds all claims and values in policy files
•	Get-Authority – finds the authority in key policy files
