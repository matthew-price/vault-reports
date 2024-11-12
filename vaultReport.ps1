<#
.SYNOPSIS
    Generates reports from a CyberArk Vault
.DESCRIPTION
    Uses the officially-supported REST-ful API, provided by the PVWA
.NOTES
    Author : Matt Price (matt@mattprice.eu)
    This script is a community effort - it is not supported by CyberArk
.LINK
    No online documentation is currently available for this script
.EXAMPLE
    .\vaultReport.ps1 -PVWACreds $PVWACreds --runs automatically
    .\vaultReport.ps1 --prompts each time for credentials
#>



[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [pscredential]
    $PVWACreds,
    [Parameter(Mandatory = $true)][string]$PVWAUrl
)

#region Variables
#$PVWAUrl = "https://pvwa.basgiath.uk/PasswordVault/"
$PVWAAuthSuffix = "API/auth/Cyberark/Logon/"
$PVWALogonUrl= $PVWAUrl + $PVWAAuthSuffix
$PVWAGetAccountsSuffix = "API/Accounts"
$PVWAAccountsUrl = $PVWAUrl + $PVWAGetAccountsSuffix
$PVWAAccountActivitySuffix = "WebServices/PIMServices.svc/Accounts/"
$PVWAGetUsersSuffix = "API/Users?ExtendedDetails=true"
$PVWAGetUsersUrl = $PVWAUrl + $PVWAGetUsersSuffix
#$PVWACreds = Get-Credential
#endregion



#region Functions

function Request-PvwaAuthToken {
    param (
        [pscredential] $cred
    )
    $body = @{
        "username" = $cred.UserName
        "password" = $cred.GetNetworkCredential().Password
    } | ConvertTo-Json
    $AuthToken = (Invoke-WebRequest -Uri $PVWALogonUrl -Method Post -Body $body -ContentType "application/json").Content
    $AuthTrimmed = $AuthToken.Replace("`"","")
    Write-Output $AuthTrimmed
}

function Get-Accounts {
    (Invoke-WebRequest -Uri $PVWAAccountsUrl -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json").Content
}

# name,address,userName,platformId,safeName,createdTime

function Get-AccountDetails {
    param (
        [psobject]$Account
    )
    $AccountID =  $Account.id
    $uri = $PVWAAccountsUrl + "/$AccountID"
    Invoke-WebRequest -Uri $uri -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json"
    Add-Member -InputObject $Account -NotePropertyName "TestName" -NotePropertyValue "TestValue2"
}

function Get-Users{
    (Invoke-WebRequest -Uri $PVWAGetUsersUrl -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json").Content
}

#endregion



#region Run reports
$AuthTrimmed = Request-PvwaAuthToken -cred $PVWACreds
[psobject[]]$Accounts = (Get-Accounts | ConvertFrom-Json).value
foreach($Account in $Accounts){
    (Get-AccountDetails -Account $Account).Content | ConvertFrom-Json
}
$Accounts[0]
[psobject[]]$Users = (Get-Users | ConvertFrom-Json).Users
$Users
$Users.count
#endregion