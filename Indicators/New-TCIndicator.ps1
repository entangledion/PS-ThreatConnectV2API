function New-TCIndicator {
<#
.SYNOPSIS
	Creates a new indicator in Threat Connect.

.PARAMETER Host
	Host or domain name indicator to create.
	
.PARAMETER URL
	URL indicator to create.
	
.PARAMETER EmailAddress
	Email address indicator to create.

.PARAMETER Address
	IP address indicator to create.
	
.PARAMETER FileMD5, FileSHA1, & FileSHA256
	File hash indicator to create. Can use any combination of these parameters in the same command to associate multiple hashes to the same file indicator.
	
.EXAMPLE
	New-TCIndicator -Host malicious.badomain.com -Confidence "100" -Rating "4.0" -WhoisActive "true" -DnsActive "true"
	
.EXAMPLE
	New-TCIndicator -URL http://malicious.badomain.com/baduri
	
.EXAMPLE
	New-TCIndicator -EmailAddress hacker@badomain.com
	
.EXAMPLE
	New-TCIndicator -Address 1.1.1.1
	
.EXAMPLE (Creates a single file indicator containing an MD5 and a SHA1 hash for the same file)
	New-TCIndicator -FileMD5 "3ffade21da0dda18de71249c46164626" -FileSHA1 "d7bc2be9e80c5c8a9901034a8cc000f6ea8d9d00"
	
	#>
[CmdletBinding()]Param(
	[Parameter(Mandatory=$True,ParameterSetName='Hostname')]
		[ValidateNotNullOrEmpty()][String]$Hostname,
	[Parameter(Mandatory=$True,ParameterSetName='URL')]
		[ValidateNotNullOrEmpty()][String]$URL,
	[Parameter(Mandatory=$True,ParameterSetName='EmailAddress')]
		[ValidateNotNullOrEmpty()][String]$EmailAddress,
	[Parameter(Mandatory=$True,ParameterSetName='Address')]
		[ValidateNotNullOrEmpty()][String]$Address,
	[Parameter(Mandatory=$False,ParameterSetName='File')]
		[ValidateNotNullOrEmpty()][String]$FileMD5,
	[Parameter(Mandatory=$False,ParameterSetName='File')]
		[ValidateNotNullOrEmpty()][String]$FileSHA1,
	[Parameter(Mandatory=$False,ParameterSetName='File')]
		[ValidateNotNullOrEmpty()][String]$FileSHA256,
	[Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][String]$whoisActive,
	[Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][String]$dnsActive,
	[Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][String]$rating,
	[Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][String]$confidence
)

Try { 

# Switch to construct Child URL based on the parameters that were provided
switch ($PSCmdlet.ParameterSetName) {
	"Host" {
		# Create a Custom Object and add the provided Name and Value variables to the object
		$CustomObject = "" | Select-Object -Property  hostName, whoisActive, dnsActive, rating, confidence
		$CustomObject.hostName = $Hostname
		$CustomObject.whoisActive = $WhoisActive
		$CustomObject.dnsActive = $DnsActive
		$CustomObject.rating = $rating
		$CustomObject.confidence = $confidence
		$APIChildURL = ("/v2/indicators/hosts)
	}
	"URL" {
		$CustomObject = "" | Select-Object -Property  text, rating, confidence
		$CustomObject.text = $URL
		$CustomObject.rating = $Rating
		$CustomObject.confidence = $Confidence
		$APIChildURL = ("/v2/indicators/urls)
	}
	"EmailAddress" {
		$CustomObject = "" | Select-Object -Property  address, rating, confidence
		$CustomObject.address = $EmailAddress
		$CustomObject.rating = $Rating
		$CustomObject.confidence = $Confidence
		$APIChildURL = ("/v2/indicators/emailAddresses)
	}
	"Address" {
		$CustomObject = "" | Select-Object -Property  ip, rating, confidence
		$CustomObject.ip = $Address
		$CustomObject.rating = $Rating
		$CustomObject.confidence = $Confidence
		$APIChildURL = ("/v2/indicators/addresses)
	}
	"File" {
		$CustomObject = "" | Select-Object -Property  md5, sha1, sha256, rating, confidence
		$CustomObject.md5 = $FileMD5
		$CustomObject.sha1 = $FileSHA1
		$CustomObject.sha256 = $FileSHA256
		$CustomObject.rating = $Rating
		$CustomObject.confidence = $Confidence
		$APIChildURL = ("/v2/indicators/files)
	}
}

	# Convert the Custom Object to JSON format for use with the API
	$JSONData = $CustomObject | ConvertTo-Json
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeaders -RequestMethod "POST" -URL $APIChildURL
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = New-Object System.Uri ($Script:APIBaseURL + $APIChildURL)
	
	# Query the API
	$Response = Invoke-RestMethod -Method "POST" -Uri $URI -Headers $AuthorizationHeaders -Body $JSONData -ContentType "application/json" -ErrorAction SilentlyContinue
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success") {
		$Response.data | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "resultCount" } | Select-Object -ExpandProperty Name | ForEach-Object { $Response.data.$_ }		
	} else {
		Write-Verbose "API New Indicator Request failed with the following error:`n $($Response.Status)"
	}
} Catch {
	Write-Host -ForegroundColor Red $_.ErrorDetails

}
}