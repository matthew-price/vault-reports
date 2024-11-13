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
$PVWAGetAccountsSuffix = 'API/Accounts'
$PVWAAccountsUrl = $PVWAUrl + $PVWAGetAccountsSuffix
$PVWAAccountActivitySuffix = "WebServices/PIMServices.svc/Accounts/"
$PVWAGetUsersSuffix = "API/Users?ExtendedDetails=true"
$PVWAGetUsersUrl = $PVWAUrl + $PVWAGetUsersSuffix
#$PVWACreds = Get-Credential
$accountsProcessed = 0
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
    param(
        $offset
    )
    $PaginatedPVWAAccountsURL = $PVWAAccountsUrl + '?offset=' + $offset + '&limit=50'
    (Invoke-WebRequest -Uri $PaginatedPVWAAccountsURL -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json").Content
}

# name,address,userName,platformId,safeName,createdTime
<#
function Get-AccountDetails {
    param (
        [psobject]$Account
    )
    $AccountID =  $Account.id
    $uri = $PVWAAccountsUrl + "/$AccountID"
    Invoke-WebRequest -Uri $uri -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json"
    Add-Member -InputObject $Account -NotePropertyName "TestName" -NotePropertyValue "TestValue2"
}
#>
function Get-Users{
    (Invoke-WebRequest -Uri $PVWAGetUsersUrl -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json").Content
}

#endregion



#region Run reports
$AuthTrimmed = Request-PvwaAuthToken -cred $PVWACreds
$MoreAccountsToProcess = $true
$offset = 0
$offsetIncrement = 50
while ($MoreAccountsToProcess){
    [psobject[]]$Accounts += (Get-Accounts -offset $offset | ConvertFrom-Json).value
    if ($offset -le $Accounts.Count){
    $offset = ($offset + $offsetIncrement)
    #Write-Host $offset "accounts processed so far"
    Write-Progress -Activity "Exporting accounts" -Status "$offset accounts processed so far" -PercentComplete -1
    }
    else {
        $MoreAccountsToProcess = $false
        Write-Host $offset "accounts processed in total"
    }
}
#foreach($Account in $Accounts){
#    (Get-AccountDetails -Account $Account).Content | ConvertFrom-Json
#}
$Accounts[0]

[psobject[]]$Users = (Get-Users | ConvertFrom-Json).Users
$Users.count
$Users[0] | Select-Object -Property name
$Accounts | Select-Object -Property name,address,userName,id,platformId,safeName,createdTime,secretManagement,platformAccountProperties | Export-Csv -Path .\output.csv


#endregion