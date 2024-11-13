<#
.SYNOPSIS
    Generates reports from a CyberArk Vault. Uses the officially-supported REST API provided by the PVWA.
.DESCRIPTION
    Capable of exporting lists of accounts, safes and users.
    The PVWA address must be entered strictly per this example: "https://pvwa.local/PasswordVault/", including 'https://' and the final '/'.
    This script may throw an error when reaching the last page of accounts - this is a known issue, the script should continue to run and export all accounts.

    Accounts will be exported with a default page size of 50, for each REST API request. This can be customised with the -AccountsPageSize parameter.

    When running this script, call the parameter switches for the report(s) you'd like to run - see examples.
    This script will accept a PSCredential option as an object parameter, rather than having to enter credentials each time. See examples.
    This script will accept a PVWA Address option as a string parameter, rather than having to enter credentials each time. See examples.
.NOTES
    Author : Matt Price (matt@mattprice.eu)
    This script is a community effort - it is not supported by CyberArk
.LINK
    No online documentation is currently available for this script
.EXAMPLE
    .\vaultReport.ps1 -PVWACreds $PVWACreds -PVWAURL "https://pvwa.local/PasswordVault/" -AccountsPageSize 100 -ReportAccounts -ReportUsers -ReportSafes
.EXAMPLE
    .\vaultReport.ps1 -ReportUsers
#>



[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [pscredential]
    $PVWACreds,
    [Parameter(Mandatory = $true)][string]$PVWAUrl,
    [switch]$ReportAccounts,
    [switch]$ReportUsers,
    [switch]$ReportSafes,
    [int]$AccountsPageSize = 50
)

#region Variables
$PVWAAuthSuffix = "API/auth/Cyberark/Logon/"
$PVWAGetAccountsSuffix = 'API/Accounts'
$PVWAGetUsersSuffix = "API/Users?ExtendedDetails=true"
$PVWAGetSafesSuffix = "API/Safes"

$PVWALogonUrl= $PVWAUrl + $PVWAAuthSuffix
$PVWAAccountsUrl = $PVWAUrl + $PVWAGetAccountsSuffix
$PVWAGetUsersUrl = $PVWAUrl + $PVWAGetUsersSuffix
$PVWAGetSafesUrl = $PVWAUrl + $PVWAGetSafesSuffix
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
        $offset,
        $offsetIncrement
    )
    $PaginatedPVWAAccountsURL = $PVWAAccountsUrl + '?offset=' + $offset + '&limit=' +$offsetIncrement
    (Invoke-WebRequest -Uri $PaginatedPVWAAccountsURL -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json").Content
}


function Get-Users{
    (Invoke-WebRequest -Uri $PVWAGetUsersUrl -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json").Content
}

function Get-Safes{
    param(
        $offset
    )
    $PaginatedPVWASafesURL = $PVWAGetSafesUrl + '?offset=' + $offset + '&limit=50'
    (Invoke-WebRequest -Uri $PaginatedPVWASafesURL -Method Get -Headers @{'Authorization' = "$AuthTrimmed"} -ContentType "application/json").Content
}

#endregion



#region Run reports
$AuthTrimmed = Request-PvwaAuthToken -cred $PVWACreds

if ($ReportAccounts){
    $MoreAccountsToProcess = $true
    $offset = 0
    if ($AccountsPageSize -gt 1000){
        Write-Warning "PVWA may not support page sizes greater than 1000!"
        Read-Host "Press ENTER if you're sure you want to continue, or ctrl+c to abort."
    }
    $offsetIncrement = $AccountsPageSize
    while ($MoreAccountsToProcess){
        [psobject[]]$Accounts += (Get-Accounts -offset $offset -offsetIncrement $offsetIncrement | ConvertFrom-Json).value
        if ($offset -le $Accounts.Count){
            $offset = ($offset + $offsetIncrement)
            Write-Progress -Activity "Exporting accounts" -Status "$offset accounts processed so far" -PercentComplete -1
        }
        else {
            $MoreAccountsToProcess = $false
            Write-Host $Accounts.Count "accounts processed in total"
        }
    }
    $Accounts | Select-Object -Property name,address,userName,id,platformId,safeName,createdTime,secretManagement,platformAccountProperties | Export-Csv -Path .\accounts-report.csv
}

if ($ReportUsers){
    $MoreUsersToProcess = $true
    $offset = 0
    $offsetIncrement = 25
    while ($MoreUsersToProcess){
        [psobject[]]$Users += (Get-Users | ConvertFrom-Json).Users
        if  ($offset -le $Users.Count){
            $offset = ($offset + $offsetIncrement)
            Write-Progress -Activity "Exporting users" -Status "$offset users processed so far" -PercentComplete -1
        }
        else {
            $MoreUsersToProcess = $false
            Write-Host $Users.Count "users processed in total"
        }
    }

    # Cast the vaultAuthorization parameter (only) from Object[] to String, to better allow Export-Csv to format the permissions
    foreach ($User in $Users){
        $User.vaultAuthorization = [String]$User.vaultAuthorization
    }
    $Users | Select-Object -Property username,id,source,userType,vaultAuthorization,suspended | Export-Csv -Path .\users-report.csv
}

if ($ReportSafes){
    $MoreSafesToProcess = $true
    $offset = 0
    $offsetIncrement = 50
    while ($MoreSafesToProcess){
        [psobject[]]$Safes += (Get-Safes -offset $offset | ConvertFrom-Json).value
        if ($offset -le $Safes.Count){
            $offset = ($offset + $offsetIncrement)
            Write-Progress -Activity "Exporting Safes" -Status "$offset Safes processed so far" -PercentComplete -1
        }
        else {
            $MoreSafesToProcess = $false
            Write-Host $Safes.Count "Safes processed in total"
        }
    }
    $Safes | Select-Object -Property safeName,safeNumber,description,managingCPM,numberOfDaysRetention,numberOfVersionsRetention,olacEnabled,creator,creationTime,lastModificationTime | Export-Csv -Path .\safes-report.csv
}


#endregion