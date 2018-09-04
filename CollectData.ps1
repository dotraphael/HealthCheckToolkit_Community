########################################################################################
# Name: CollectData.ps1
# Version: 1.2
# Author: Raphael Perez - raphael@perez.net.br
# Date: 01/05/2018
# Comment: This script will check the health of a System Center Configuration Manager
#          Infrastructure based on user's rights.
#
#          It uses the SCCM PowerShell modules, so the SCCM Console must be installed
#          and connected to the server to be able to run the tool
#
#          The tool supports only execution against a Primary Site. CAS is not supported
#
# Test: CM1702 Primary site installed on a WS2012R2
#       CM1702 Primary site installed on a WS2016
#       CM1710 Primary site installed on a WS2016
#       CM1802 Primary site installed on a WS2016
#       CM1806 Primary site installed on a WS2016
#
# Updates:
#        1.0 - Raphael Perez - 03/08/2018 - Initial Script
#
# Usage:
#		 Option 1: powershell.exe -ExecutionPolicy Bypass .\SCCM.ps1 [Parameters]
#        Option 2: Open Powershell and execute .\SCCM.ps1 [Parameters]
#
# Parameters:
#
# Examples:
#        .\CollectData.ps1 -AuthorizedSiteCodes '001' -MessageFilePath .\Messages.xml -RulesOverrideFilePath .\SCCMRulesOverride.xml -DefaultValuesOverrideFilePath .\SCCMDefaultValues.xml
########################################################################################
#>
#region param
[CmdletBinding()]param (
    [parameter(Mandatory=$true)][string]$AuthorizedSiteCodes,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path $_){$true}else{Throw "Invalid Message File Path given: $_"}})][string]$MessageFilePath,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path $_){$true}else{Throw "Invalid Rules Override File Path given: $_"}})][string]$RulesOverrideFilePath,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path $_){$true}else{Throw "Invalid Default Values Override File Path given: $_"}})][string]$DefaultValuesOverrideFilePath    
)
#endregion

#region Starting Script, Verbose variables
if ($Verbose) {
    $DebugPreference = 2
    $VerbosePreference = 2
    $WarningPreference = 2
}

$ErrorActionPreference = "Continue"
#endregion

#region Import class DLL
Add-Type -Path .\HealthCheckClasses.dll | Out-Null
Add-Type -Assembly System.IO.Compression.FileSystem | Out-Null
#endregion

#region Functions

#region Export-CEXMLFile
function Export-CEXMLFile {
    param (
        [Parameter(Position=1, Mandatory=$true)][string]$VariableName
    )
    $VarInfo = Get-Variable $VariableName -ErrorAction SilentlyContinue
    if ($VarInfo -eq $null) {
        Write-CELog -logtype "WARNING" -logmessage "Exporting $($VariableName) ignored as it is empty"
    } else {
        Write-CELog -logtype "INFO" -logmessage "Exporting $($VarInfo.Name)"
        $VarInfo.Value | Export-Clixml -Path "$($SaveToFolder)\$($VarInfo.Name).xml"
    }
}
#endregion

#region Extract-ZipFiles
function Extract-ZipFiles {
    param (
        [string]$zipfilename,
        [string]$destinationdir
    )
    Write-CELog -logtype "Info" -logmessage "Extracting Zip File $($zipfilename) to $($destinationdir)"
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfilename, $destinationdir)
}
#endregion

#region Write-ZipFiles
function Write-ZipFiles {
    param (
        [string]$zipfilename,
        [string]$sourcedir
    )
    Write-CELog -logtype "Info" -logmessage "Creating Zip File $($zipfilename)"
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir, $zipfilename, $compressionLevel, $false)
}
#endregion

#region Test-CEUrl
function Test-CEUrl {
    param (
        [int]$InfoMessageID,
        [string]$url,
        [int]$MessageIDNameSuccess,
        [int]$MessageIDError,
        [string]$ServerName,
        [int]$CommentIDError,
        [int]$CommentIDException,
        [switch]$UserCredentials,
        $RuleIDInfo
    )
    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage $InfoMessageID $url)
    try {
        if ($UserCredentials) {
            $WebRequest = Invoke-WebRequest -Uri $url -UseDefaultCredentials -UseBasicParsing
        } else {
            $WebRequest = Invoke-WebRequest -Uri $url -UseBasicParsing
        }

        $Script:ServerHTTPAccessInformation += New-Object -TypeName PSObject -Property @{'CommentIDError' = $CommentIDError; 'MessageIDError' = $MessageIDError; 'RuleInfo' = $RuleIDInfo; 'ServerName' = $ServerName; 'StatusCode' = "$($WebRequest.StatusCode)" }
    } catch {
        Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
        $Script:ServerHTTPAccessInformation += New-Object -TypeName PSObject -Property @{'CommentIDError' = $CommentIDException; 'MessageIDError' = $MessageIDError; 'RuleInfo' = $RuleIDInfo; 'ServerName' = $ServerName; 'StatusCode' = 'Unable to connect' }
    }
}
#endregion

#region Get-CEHealthCheckCategory
function Get-CEHealthCheckCategory {
    param (
        [Parameter(Position=1, Mandatory=$true)][int]$MessageID
    )

    $return = ($Script:HealthCheckCategoryData.Categories.Category | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'SCCM')}).Name
    if ($return -eq $null) {
        $Return = "Unknown Category with message ID $($MessageID)"
    }
    return $return
}
#endregion

#region Get-CEHealthCheckIssue
function Get-CEHealthCheckIssue {
    param (
        [Parameter(Position=1, Mandatory=$true)][int]$MessageID,
        [Parameter(Position=2, Mandatory=$false)][object[]]$MessageParameters
    )

    $return = ($Script:HealthCheckIssuesData.Issues.issue | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'SCCM')}).Name
    if ($return -eq $null) {
        $Return = "Unknown Issue with message ID $($MessageID)"
    } else {
        if (($MessageParameters.Count -gt 0) -and ($return.IndexOf('{0}') -ge 0)) {
            try {
                $return = $return -f $MessageParameters
            } catch {
                Write-CELog -LogType 'ERROR' -LogMessage "Message with Error: $MessageID"
                throw $_
            }
        }
    }
    #return "something $messageID - $return"
    return $return
}
#endregion

#region Get-CEHealthCheckRecommendation
function Get-CEHealthCheckRecommendation {
    param (
        [Parameter(Position=1, Mandatory=$true)][int]$MessageID,
        [Parameter(Position=2, Mandatory=$false)][object[]]$MessageParameters
    )

    $return = ($Script:HealthCheckRecommendationData.Recommendations.Recommendation | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'SCCM')}).Name
    if ($return -eq $null) {
        $Return = "Unknown Recommendation with message ID $($MessageID)"
    } else {
        if (($MessageParameters.Count -gt 0) -and ($return.IndexOf('{0}') -ge 0)) {
            try {
                $return = $return -f $MessageParameters
            } catch {
                Write-CELog -LogType 'ERROR' -LogMessage "Message with Error: $MessageID"
                throw $_
            }
        }
    }
    return $return
}
#endregion

#region Get-CEHealthCheckMessage
function Get-CEHealthCheckMessage {
    param (
        [Parameter(Position=1, Mandatory=$true)][int]$MessageID,
        [Parameter(Position=2, Mandatory=$false)][object[]]$MessageParameters
    )

    $return = ($Script:HealthCheckMessageData.Messages.Message | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'SCCM')}).Name
    if ($return -eq $null) {
        $Return = "Unknown message with message ID $($MessageID)"
    } else {
        if (($MessageParameters.Count -gt 0) -and ($return.IndexOf('{0}') -ge 0)) {
            try {
                $return = $return -f $MessageParameters
            } catch {
                Write-CELog -LogType 'ERROR' -LogMessage "Message with Error: $MessageID"
                throw $_
            }
        }
    }
    return $return
}
#endregion

#region Get-CECollectionNames
function Get-CECollectionNames {
    param (
        [Parameter(Position=1, Mandatory=$true)]$CollectionList
    )
    $return = ""
    $CollectionList | ForEach-Object {
        if (-not [string]::IsNullOrEmpty($return)) { $return += '; ' }
        $return += $_.Name
    }

    return $return;
}
#endregion

#region Set-CEHealthCheckDefaultValue
function Set-CEHealthCheckDefaultValue {
    param (
        [Parameter(Position=1, Mandatory=$true)][string]$ValueName,
        [Parameter(Position=2, Mandatory=$true)]$ValueNonExist
    )
    $ValueDetails = $Script:HealthCheckDefaultValueData.DefaultValues.DefaultValue | Where-Object {$_.Name -eq $ValueName}
    if ($ValueDetails -eq $null) {
        New-Variable -Name $ValueName -Value $ValueNonExist -Force -Option AllScope -Scope Script
        #Write-CELog -LogType 'INFO' -LogMessage "$ValueName is now set to default value of $((Get-Variable $ValueName).Value)"
    } else {
        if ($ValueDetails -is [array]) {
            $ValueDetails = $ValueDetails[0]
        }

        if ($ValueDetails.Type.tolower() -eq 'array') {
            New-Variable -Name $ValueName -Value $ValueDetails.value.Split(',') -Force -Option AllScope -Scope Script
        } else {
            New-Variable -Name $ValueName -Value $ValueDetails.value -Force -Option AllScope -Scope Script
        }
        Write-CELog -LogType 'INFO' -LogMessage "$ValueName is now set to custom default value of $((Get-Variable $ValueName).Value)"
    }
}
#endregion

#region Set-CEHealthCheckRulesOverride
function Set-CEHealthCheckRulesOverride {
    param (
        [Parameter(Position=1, Mandatory=$true)][int]$RuleID,
        [Parameter(Position=2, Mandatory=$true)][string]$RuleName,
        [Parameter(Position=3, Mandatory=$true)][int]$DefaultCategory,
        [Parameter(Position=4, Mandatory=$true)][string]$DefaultClassification
    )
    $ValueDetails = $Script:HealthCheckRulesOverrideData.Rules.Rule | Where-Object {$_.ID -eq $RuleID}
    $VariableName = "RuleID$($RuleID)"
    $objRule = new-object HealthCheckClasses.HealthCheck.CEClassRules($RuleID, $RuleName, $DefaultCategory, $DefaultClassification, $true)
    $ShowMsg = $false

    if ($ValueDetails -ne $null) {
        if ($ValueDetails -is [array]) {
            $ValueDetails = $ValueDetails[0]
        }
        $objRule.Category = $ValueDetails.Category
        $objRule.Classification = $ValueDetails.Classification
        $objRule.Enabled = [Convert]::ToBoolean($ValueDetails.Enabled)
        $ShowMsg = $true
    }
    New-Variable -Name $VariableName -Value $objRule -Force -Option AllScope -Scope Script
    if ($ShowMsg) {
        Write-CELog -LogType 'INFO' -LogMessage "Rule ID $($RuleID) information is set to custom values of Category: $((Get-Variable $VariableName).Value.Category), Classification: $((Get-Variable $VariableName).Value.Classification), Enabled: $((Get-Variable $VariableName).Value.Enabled)"
    }
}
#endregion

#region Write-CEHealthCheckData
function Write-CEHealthCheckData {
    PARAM (
        [Parameter(Mandatory=$true)][string]$Description,
        [Parameter(Mandatory=$false)][string]$Comment,
        [Parameter(Mandatory=$true)]$RuleIDInfo
    )
    $newRow = $Script:HealthCheckData.NewRow()
    $newRow.Category = Get-CEHealthCheckCategory $RuleIDInfo.Category
    $newRow.Classification = $RuleIDInfo.Classification
    $newRow.Description = "$($Description)"
    $newRow.Comment = " $($Comment) "
    $newRow.RuleID = $RuleIDInfo.ID
    $Script:HealthCheckData.Rows.Add($newRow)
    Write-CELog -logtype "$($newRow.Classification)" -logmessage "$($newRow.Category) - $Description"
}
#endregion

#region Test-CEHealthCheckCollectData
function Test-CEHealthCheckCollectData {
    param (
        [Parameter(Position=1, Mandatory=$true)][int[]]$Rules
    )

    $enabledRules = ""
    foreach($item in $Rules) {
        $RuleInfo = (Get-Variable "RuleID$($item)" -ErrorAction SilentlyContinue).Value
        if ($RuleInfo.Enabled -eq $true) {
            if (-not [string]::IsNullOrEmpty($enabledRules)) { $enabledRules += ', '}
            $enabledRules += $item
        }
    }

    if ([string]::IsNullOrEmpty($enabledRules)) {
        return $false
    } else {
        return $true
    }
}
#endregion

#region Write-CELog
function Write-CELog {
    PARAM (
        [Parameter(Mandatory=$true)][string]$LogType,
        [Parameter(Mandatory=$true)][string]$LogMessage
    )
    $DateTime = Get-Date

    $MessageToWrite = "$($LogType.ToUpper()): $($DateTime.ToString('dd/MM/yyyy HH:mm:ss')) - $($LogMessage)"
    switch ($LogType.ToUpper()) {
        "EXCEPTION" {
            write-Output $MessageToWrite
            #send analytics info
        }
        "ERROR" {
            write-Output $MessageToWrite
        }
        "WARNING" {
            write-Output $MessageToWrite
        }
        default {
            write-Output $MessageToWrite
        }
    }
}
#endregion

#endregion

#region Main Script
try {
    #region Temporary Folder
    #$SaveToFolder = "$($env:TEMP)\$((Get-Date).Ticks)"
    $SaveToFolder = 'C:\Temp\SCCMHealthCheck'
    New-Item -Path $SaveToFolder -Type Directory -Force | out-null
    #endregion

    #region XML files
        
    #region Recommendations ID's
    Write-CELog -logtype "Info" -logmessage "Message Database"
    $Script:HealthCheckMessageData = [xml](get-content -path $MessageFilePath)
    #endregion

    #region Rules Override
    Write-CELog -logtype "Info" -logmessage "Rules Override Database"
    $Script:HealthCheckRulesOverrideData = [xml](get-content $RulesOverrideFilePath)
    #endregion

    #region Default Values
    Write-CELog -logtype "Info" -logmessage "Default Values Database"
    $Script:HealthCheckDefaultValueData = [xml](get-content $DefaultValuesOverrideFilePath)
    #endregion
    
    #endregion

    #region Set Default Variables
    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1001)
    Set-CEHealthCheckDefaultValue -ValueName 'ExcludeServers' -ValueNonExist @()
    Set-CEHealthCheckDefaultValue -ValueName 'ProcessListSamplesMinutes' -ValueNonExist 1
    Set-CEHealthCheckDefaultValue -ValueName 'ProcessListSamplesWaitSeconds' -ValueNonExist 10
    Set-CEHealthCheckDefaultValue -ValueName 'MaxCollectionMembershipDirectRule' -ValueNonExist 500
    Set-CEHealthCheckDefaultValue -ValueName 'MinimumSCCMBuildVersion' -ValueNonExist 8498 #1702
    Set-CEHealthCheckDefaultValue -ValueName 'LatestSCCMBuildVersion' -ValueNonExist 8692 #1806 list can be found https://buildnumbers.wordpress.com/sccm/
    Set-CEHealthCheckDefaultValue -ValueName 'LatestWhatsNew' -ValueNonExist 'https://docs.microsoft.com/en-us/sccm/core/plan-design/changes/whats-new-in-version-1806'
    Set-CEHealthCheckDefaultValue -ValueName 'MinimumSQLVersion' -ValueNonExist '11.0.0.0'
    Set-CEHealthCheckDefaultValue -ValueName 'MinimumSQLMemory' -ValueNonExist '8192'
    Set-CEHealthCheckDefaultValue -ValueName 'MinSCCMModuleVersion' -ValueNonExist 5.1702
    Set-CEHealthCheckDefaultValue -ValueName 'MinSCCMVersion' -ValueNonExist '1702'
    Set-CEHealthCheckDefaultValue -ValueName 'MaximumNumberOfMPS' -ValueNonExist 15
    Set-CEHealthCheckDefaultValue -ValueName 'RolesThatMustBeInstalledPrimary' -ValueNonExist @('SMS Management Point', 'SMS Distribution Point', 'SMS Fallback Status Point', 'SMS SRS Reporting Point', 'SMS Software Update Point', 'SMS Application Web Service', 'SMS Portal Web Site')
    Set-CEHealthCheckDefaultValue -ValueName 'RulesThatMustBeInstalledSecondary' -ValueNonExist @('SMS Management Point', 'SMS Distribution Point', 'SMS Fallback Status Point', 'SMS Software Update Point')
    Set-CEHealthCheckDefaultValue -ValueName 'HiddenPackages' -ValueNonExist @('Configuration Manager Client Package', 'Configuration Manager Client Piloting Package')
    Set-CEHealthCheckDefaultValue -ValueName 'RolesThatMustNotBeInstalledPrimary' -ValueNonExist @()
    Set-CEHealthCheckDefaultValue -ValueName 'RolesThatMustNotBeInstalledSecondary' -ValueNonExist @()
    Set-CEHealthCheckDefaultValue -ValueName 'DDRMinScheduleInMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'DDRMaxScheduleInMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'ForestDiscoveryMinScheduleInMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'ForestDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinScheduleInMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinExpiredLogon' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxExpiredLogon' -ValueNonExist 90
    Set-CEHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinPasswordSet' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxPasswordSet' -ValueNonExist 90
    Set-CEHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinScheduleInMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinExpiredLogon' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxExpiredLogon' -ValueNonExist 90
    Set-CEHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinPasswordSet' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxPasswordSet' -ValueNonExist 90
    Set-CEHealthCheckDefaultValue -ValueName 'UserMinScheduleInMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'UserMaxScheduleInMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'MinCollectionMembershipEvaluation' -ValueNonExist 5
    Set-CEHealthCheckDefaultValue -ValueName 'MaxCollectionMembershipEvaluation' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'MaxCollectionIncrementalUpdateWarning' -ValueNonExist 125
    Set-CEHealthCheckDefaultValue -ValueName 'MaxCollectionIncrementalUpdateError' -ValueNonExist 200
    Set-CEHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsCleanUpInterval' -ValueNonExist 31
    Set-CEHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsCleanUpInterval' -ValueNonExist 90
    Set-CEHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsDDRInactiveInterval' -ValueNonExist 7
    Set-CEHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsDDRInactiveInterval' -ValueNonExist 21
    Set-CEHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsHWInactiveInterval' -ValueNonExist 7
    Set-CEHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsHWInactiveInterval' -ValueNonExist 21
    Set-CEHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsPolicyInactiveInterval' -ValueNonExist 7
    Set-CEHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsPolicyInactiveInterval' -ValueNonExist 21
    Set-CEHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsStatusInactiveInterval' -ValueNonExist 7
    Set-CEHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsStatusInactiveInterval' -ValueNonExist 21
    Set-CEHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsSWInactiveInterval' -ValueNonExist 7
    Set-CEHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsSWInactiveInterval' -ValueNonExist 21
    Set-CEHealthCheckDefaultValue -ValueName 'MinCacheSize' -ValueNonExist 5120
    Set-CEHealthCheckDefaultValue -ValueName 'MinPolicyRequestAssignmentTimeout' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'MaxPolicyRequestAssignmentTimeout' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'MinRebootLogoffNotificationCountdownDuration' -ValueNonExist 30
    Set-CEHealthCheckDefaultValue -ValueName 'MaxRebootLogoffNotificationCountdownDuration' -ValueNonExist 720
    Set-CEHealthCheckDefaultValue -ValueName 'MinRebootLogoffNotificationFinalWindow' -ValueNonExist 15
    Set-CEHealthCheckDefaultValue -ValueName 'MaxRebootLogoffNotificationFinalWindow' -ValueNonExist 90
    Set-CEHealthCheckDefaultValue -ValueName 'MinHardwareInventoryScheduleMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'MaxHardwareInventoryScheduleMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'MinSoftwareInventoryScheduleMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'MaxSoftwareInventoryScheduleMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'MinSoftwareDeploymentEvaluationScheduleMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'MaxSoftwareDeploymentEvaluationScheduleMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'MinSoftwareUpdateScanScheduleMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'MaxSoftwareUpdateScanScheduleMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'MinSoftwareUpdateReScanScheduleMinutes' -ValueNonExist 1440
    Set-CEHealthCheckDefaultValue -ValueName 'MaxSoftwareUpdateReScanScheduleMinutes' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'MinFallbackDPBoundaryGroupRelationship' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'MaxFallbackDPBoundaryGroupRelationship' -ValueNonExist 240
    Set-CEHealthCheckDefaultValue -ValueName 'MinFallbackMPBoundaryGroupRelationship' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'MaxFallbackMPBoundaryGroupRelationship' -ValueNonExist 240
    Set-CEHealthCheckDefaultValue -ValueName 'MinFallbackSMPBoundaryGroupRelationship' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'MaxFallbackSMPBoundaryGroupRelationship' -ValueNonExist 240
    Set-CEHealthCheckDefaultValue -ValueName 'MinFallbackSUPBoundaryGroupRelationship' -ValueNonExist 60
    Set-CEHealthCheckDefaultValue -ValueName 'MaxFallbackSUPBoundaryGroupRelationship' -ValueNonExist 240
    Set-CEHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMinWarningValueAlert' -ValueNonExist 2
    Set-CEHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMaxWarningValueAlert' -ValueNonExist 5
    Set-CEHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMinCriticalValueAlert' -ValueNonExist 2
    Set-CEHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMaxCriticalValueAlert' -ValueNonExist 3
    Set-CEHealthCheckDefaultValue -ValueName 'AntiMalwareLimitCPUUsageMax' -ValueNonExist 50
    Set-CEHealthCheckDefaultValue -ValueName 'AntiMalwareDeleteQuarantinedFilesMax' -ValueNonExist 120
    Set-CEHealthCheckDefaultValue -ValueName 'AntiMalwareDeleteQuarantinedFilesMin' -ValueNonExist 30
    Set-CEHealthCheckDefaultValue -ValueName 'ClientSettingsListName' -ValueNonExist @('BackgroundIntelligentTransfer', 'ClientCache', 'ClientPolicy', 'Cloud', 'ComplianceSettings', 'ComputerAgent', 'ComputerRestart', 'EndpointProtection', 'HardwareInventory', 'MeteredNetwork', 'MobileDevice', 'NetworkAccessProtection', 'PowerManagement', 'RemoteTools', 'SoftwareDeployment', 'SoftwareInventory', 'SoftwareMetering', 'SoftwareUpdates', 'StateMessaging', 'UserAndDeviceAffinity')
    Set-CEHealthCheckDefaultValue -ValueName 'AntiMalwarePolicySettingsListName' -ValueNonExist @('Advanced', 'DefaultActions', 'DefinitionUpdates', 'ExclusionSettings', 'MicrosoftActiveProtectionService', 'RealTimeProtection', 'ScanSettings', 'ScheduledScans', 'ThreatOverrides')
    Set-CEHealthCheckDefaultValue -ValueName 'TotalOfSites' -ValueNonExist 1
    Set-CEHealthCheckDefaultValue -ValueName 'RegExLDAPDiscovery' -ValueNonExist 'LDAP:\/\/DC=(.+[^,])'
    Set-CEHealthCheckDefaultValue -ValueName 'MinADKVersion' -ValueNonExist '10.0.15063.0'
    Set-CEHealthCheckDefaultValue -ValueName 'MaxUpdateInSUPGroupWarning' -ValueNonExist 750
    Set-CEHealthCheckDefaultValue -ValueName 'MaxUpdateInSUPGroupError' -ValueNonExist 1000
    Set-CEHealthCheckDefaultValue -ValueName 'MinSUPSummarizationTime' -ValueNonExist 720
    Set-CEHealthCheckDefaultValue -ValueName 'MaxSUPSummarizationTime' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'ADRLastRunMaxTime' -ValueNonExist 30
    Set-CEHealthCheckDefaultValue -ValueName 'MinSUPAlertTime' -ValueNonExist 4320
    Set-CEHealthCheckDefaultValue -ValueName 'MaxSUPAlertTime' -ValueNonExist 10080
    Set-CEHealthCheckDefaultValue -ValueName 'MaxADRSchedule' -ValueNonExist 43200
    Set-CEHealthCheckDefaultValue -ValueName 'MinADRSchedule' -ValueNonExist 240
    Set-CEHealthCheckDefaultValue -ValueName 'MinClientUpgradeDays' -ValueNonExist 3
    Set-CEHealthCheckDefaultValue -ValueName 'MaxClientUpgradeDays' -ValueNonExist 14
    Set-CEHealthCheckDefaultValue -ValueName 'ForestDiscoveryMaxDiscoveryTime' -ValueNonExist 14
    Set-CEHealthCheckDefaultValue -ValueName 'DatabaseReplicationMaxLagTime' -ValueNonExist 2
    Set-CEHealthCheckDefaultValue -ValueName 'MaxLinkDatabaseReplicationSchedule' -ValueNonExist 30
    Set-CEHealthCheckDefaultValue -ValueName 'MinLinkDatabaseReplicationSchedule' -ValueNonExist 10
    Set-CEHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization1' -ValueNonExist 720
    Set-CEHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization1' -ValueNonExist 30
    Set-CEHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization2' -ValueNonExist 2880
    Set-CEHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization2' -ValueNonExist 720
    Set-CEHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization3' -ValueNonExist 20160
    Set-CEHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization3' -ValueNonExist 5040
    Set-CEHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization1' -ValueNonExist 720
    Set-CEHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization1' -ValueNonExist 30
    Set-CEHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization2' -ValueNonExist 2880
    Set-CEHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization2' -ValueNonExist 720
    Set-CEHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization3' -ValueNonExist 20160
    Set-CEHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization3' -ValueNonExist 5040
    Set-CEHealthCheckDefaultValue -ValueName 'GroupsNotAllowed' -ValueNonExist @('Access Control Assistance Operators', 'Account Operators', 'Administrators', 'Backup Operators', 'Certificate Service DCOM Access', 'Cryptographic Operators', 'Distributed COM Users', 'Event Log Readers', 'Guests', 'Hyper-V Administrators', 'IIS_IUSRS', 'Incoming Forest Trust Builders', 'Network Configuration Operators', 'Performance Log Users', 'Performance Monitor Users', 'Pre-Windows 2000 Compatible Access', 'Print Operators', 'RDS Endpoint Servers', 'RDS Management Servers', 'RDS Remote Access Servers', 'Remote Desktop Users', 'Remote Management Users', 'Replicator', 'Server Operators', 'Storage Replica Administrators', 'System Managed Accounts Group', 'Terminal Server License Servers', 'Windows Authorization Access Group', 'Users', 'Allowed RODC Password Replication Group', 'Cert Publishers', 'Cloneable Domain Controllers', 'DHCP Administrators', 'DHCP Users', 'DnsAdmins', 'DnsUpdateProxy', 'Domain Admins', 'Domain Computers', 'Domain Controllers', 'Domain Guests', 'Enterprise Admins', 'Enterprise Key Admins', 'Enterprise Read-only Domain Controllers', 'Group Policy Creator Owners', 'Key Admins', 'Protected Users', 'RAS and IAS Servers', 'Read-only Domain Controllers', 'Schema Admins')
    Set-CEHealthCheckDefaultValue -ValueName 'MaxFullAdminWarning' -ValueNonExist 3
    Set-CEHealthCheckDefaultValue -ValueName 'MaxFullAdminError' -ValueNonExist 5
    Set-CEHealthCheckDefaultValue -ValueName 'WarningCPUAverageUsage' -ValueNonExist 50
    Set-CEHealthCheckDefaultValue -ValueName 'ErrorCPUAverageUsage' -ValueNonExist 75
    Set-CEHealthCheckDefaultValue -ValueName 'WarningPercentageFreeSpace' -ValueNonExist 20
    Set-CEHealthCheckDefaultValue -ValueName 'ErrorPercentageFreeSpace' -ValueNonExist 10
    Set-CEHealthCheckDefaultValue -ValueName 'InboxFolderCountWarning' -ValueNonExist 30
    Set-CEHealthCheckDefaultValue -ValueName 'InboxFolderCountError' -ValueNonExist 50
    Set-CEHealthCheckDefaultValue -ValueName 'ApplicationFailurePercentageWarning' -ValueNonExist 25
    Set-CEHealthCheckDefaultValue -ValueName 'ApplicationFailurePercentageError' -ValueNonExist 50
    Set-CEHealthCheckDefaultValue -ValueName 'ComponentStatusMessageDateOld' -ValueNonExist 7
    Set-CEHealthCheckDefaultValue -ValueName 'MaxDPContentValudationSchedule' -ValueNonExist 20160
    Set-CEHealthCheckDefaultValue -ValueName 'MinDPContentValudationSchedule' -ValueNonExist 4320
    Set-CEHealthCheckDefaultValue -ValueName 'IgnoreCloudDP' -ValueNonExist $false
    Set-CEHealthCheckDefaultValue -ValueName 'AddMultipleComponentStatusMessage' -ValueNonExist $false
    Set-CEHealthCheckDefaultValue -ValueName 'MaxApprovalRequestDate' -ValueNonExist 7
    Set-CEHealthCheckDefaultValue -ValueName 'MinMDTVersion' -ValueNonExist '6.3.8450.1000'
    #endregion

    #region set Override Rules
    Set-CEHealthCheckRulesOverride -RuleID 9999 -RuleName 'Unknown' -DefaultCategory 0 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 1 -RuleName 'Server Down' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 2 -RuleName 'Minimum SCCM Build Version' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 3 -RuleName 'Latest SCCM Build Version' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 4 -RuleName 'Enforce Enhanced Hash Algorithm' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 5 -RuleName 'Enforce Message Signing' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 6 -RuleName 'Use Encryption' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 7 -RuleName 'Site Alert' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 8 -RuleName 'Database Free Space Warning (Higher)' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 9 -RuleName 'Database Free Space Warning (Lower)' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 10 -RuleName 'Database Free Space Error (Higher)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 11 -RuleName 'Database Free Space Error (Lower)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 12 -RuleName 'List Roles Installed' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 13 -RuleName 'List Roles Not Installed' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 14 -RuleName 'Test MP (MPList) URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 15 -RuleName 'Test MP (MPCert) URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 16 -RuleName 'Test MP (SiteSign Cert) URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 17 -RuleName 'MP Count' -DefaultCategory 6 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 18 -RuleName 'Application Catalog Web Service URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 19 -RuleName 'Application Catalog Web Site URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 20 -RuleName 'SUP (SimpleAuth) URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 21 -RuleName 'SUP (Registration) URL' -DefaultCategory 6 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 22 -RuleName 'Application Catalog Integration' -DefaultCategory 7 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 23 -RuleName 'SQL Server Reporting Services (Reports) URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 24 -RuleName 'SQL Server Reporting Services (ReportServer) URL' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 25 -RuleName 'Minimum SQL Server' -DefaultCategory 3 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 26 -RuleName 'Minimum SQL Memory' -DefaultCategory 3 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 27 -RuleName 'Maximum SQL Memory' -DefaultCategory 3 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 28 -RuleName 'SQL Compatibility Level' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 29 -RuleName 'SQL Server Installation Folder' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 30 -RuleName 'SQL Server Data Folder' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 31 -RuleName 'SQL Server Log Folder' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 32 -RuleName 'SQL Server Data Folder (Install)' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 33 -RuleName 'SQL Server Log Folder (Install)' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 34 -RuleName 'SQL Server Data Folder (Log)' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 35 -RuleName 'Account Usage' -DefaultCategory 8 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 36 -RuleName 'Account Usage (Software Distribution)' -DefaultCategory 8 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 37 -RuleName 'Account Usage (Admin)' -DefaultCategory 8 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 38 -RuleName 'Client Status (Clean Up) (Higher)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 39 -RuleName 'Client Status (Clean Up) (Lower)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 40 -RuleName 'Client Status (Heartbeat) (Higher)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 41 -RuleName 'Client Status (Heartbeat) (Lower)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 42 -RuleName 'Client Status (Hardware) (Higher)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 43 -RuleName 'Client Status (Hardware) (Lower)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 44 -RuleName 'Client Status (Client Policy) (Higher)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 45 -RuleName 'Client Status (Client Policy) (Lower)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 46 -RuleName 'Client Status (Status Message) (Higher)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 47 -RuleName 'Client Status (Status Message) (Lower)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 48 -RuleName 'Client Status (Software) (Higher)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 49 -RuleName 'Client Status (Software) (Lower)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 50 -RuleName 'Enabled Heartbeat Discovery' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 51 -RuleName 'Heartbeat Discovery Schedule (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 52 -RuleName 'Forest Discovery' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 53 -RuleName 'Forest Discovery Schedule (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 54 -RuleName 'Forest Discovery AD Boundary' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 55 -RuleName 'Forest Discovery Subnet Boundary' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 56 -RuleName 'Network Discovery' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 57 -RuleName 'Security Group Discovery' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 58 -RuleName 'Security Group Discovery Schedule (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 59 -RuleName 'Security Group Discovery Schedule (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 60 -RuleName 'Security Group Discovery Expired Logon' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 61 -RuleName 'Security Group Discovery Expired Logon Days (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 62 -RuleName 'Security Group Discovery Expired Logon Days (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 63 -RuleName 'Security Group Discovery Expired Password' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 64 -RuleName 'Security Group Discovery Expired Password Days (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 65 -RuleName 'Security Group Discovery Expired Password Days (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 66 -RuleName 'Security Group Discovery LDAP Count' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 67 -RuleName 'Security Group Discovery LDAP Root' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 68 -RuleName 'System Discovery' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 69 -RuleName 'System Discovery Schedule (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 70 -RuleName 'System Discovery Schedule (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 71 -RuleName 'System Discovery Expired Logon' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 72 -RuleName 'System Discovery Expired Logon Days (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 73 -RuleName 'System Discovery Expired Logon Days (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 74 -RuleName 'System Discovery Expired Password' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 75 -RuleName 'System Discovery Expired Password Days (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 76 -RuleName 'System Discovery Expired Password Days (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 77 -RuleName 'System Discovery LDAP Count' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 78 -RuleName 'System Discovery LDAP Root' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 79 -RuleName 'User Discovery' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 80 -RuleName 'User Discovery Schedule (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 81 -RuleName 'User Discovery Schedule (Lower)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 82 -RuleName 'User Discovery LDAP Count' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 83 -RuleName 'User Discovery LDAP Root' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 84 -RuleName 'DP Group Has Members' -DefaultCategory 12 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 85 -RuleName 'DP Group Content In Sync' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 86 -RuleName 'Collection Membership Evaluation Schedule (Higher)' -DefaultCategory 11 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 87 -RuleName 'Collection Membership Evaluation Schedule (Lower)' -DefaultCategory 11 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 88 -RuleName 'Device Collection Membership Rules Count' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 89 -RuleName 'Device Collection Membership Count' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 90 -RuleName 'Device Collection Limited by' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 91 -RuleName 'Device Collection Incremental Warning' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 92 -RuleName 'Device Collection Incremental Error' -DefaultCategory 11 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 93 -RuleName 'Device Collection Direct Membership Rule Count' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 94 -RuleName 'User Collection Membership Rules Count' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 95 -RuleName 'User Collection Membership Count' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 96 -RuleName 'User Collection Limited By' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 97 -RuleName 'User Collection Incremental Warning' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 98 -RuleName 'User Collection Incremental Error' -DefaultCategory 11 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 99 -RuleName 'User Collection Direct Membership Rule Count' -DefaultCategory 11 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 100 -RuleName 'Deployment Empty Collection' -DefaultCategory 21 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 101 -RuleName 'Deployment to Root Collection' -DefaultCategory 21 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 102 -RuleName 'Active Alerts' -DefaultCategory 18 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 103 -RuleName 'Alert Subscription Count' -DefaultCategory 18 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 104 -RuleName 'Alert Subscription' -DefaultCategory 18 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 105 -RuleName 'Device List - Non Client' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 106 -RuleName 'Device List - Active Status' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 107 -RuleName 'Device List - Blocked' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 108 -RuleName 'Device List - Approved' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 109 -RuleName 'Device List - Obsolete' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 110 -RuleName 'Device List - Windows XP' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 111 -RuleName 'Device List - WIndows XP x64' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 112 -RuleName 'Device List - WIndows Vista' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 113 -RuleName 'Device List - Windows 7' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 114 -RuleName 'Device List - Windows 2003' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 115 -RuleName 'Device List - Windows 2008' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 116 -RuleName 'Device List - Windows 2008 R2' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 117 -RuleName 'Device List - Windows Server 2012' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 118 -RuleName 'Client Version Lower Site Server' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 119 -RuleName 'Endpoint Protection - Unmanaged' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 120 -RuleName 'Endpoint Protection - To Be Installed' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 121 -RuleName 'Endpoint Protection - Install with Error' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 122 -RuleName 'Endpoint Protection - Pending Reboot' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 123 -RuleName 'Endpoint Protection - Infection Status Error' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 124 -RuleName 'Endpoint Protection - Infection Status Pending' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 125 -RuleName 'Endpoint Protection - Infection Status Unknown' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 126 -RuleName 'Endpoint Protection - Policy Status Error' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 127 -RuleName 'Endpoint Protection - Product Status Service Not Started' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 128 -RuleName 'Endpoint Protection - Product Status Pending Full Scan' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 129 -RuleName 'Endpoint Protection - Product Status Pending reboot' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 130 -RuleName 'Endpoint Protection - Product Status Pending manual steps' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 131 -RuleName 'Endpoint Protection - Product Status AV Signature Out to Date' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 132 -RuleName 'Endpoint Protection - Product Status AS Signature Out to Date' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 133 -RuleName 'Endpoint Protection - Product Status Missing quick scan' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 134 -RuleName 'Endpoint Protection - Product Status Missing full scan' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 135 -RuleName 'Endpoint Protection - Product Status Cleaning in progress' -DefaultCategory 24 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 136 -RuleName 'Endpoint Protection - Product Status non-genuine windows' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 137 -RuleName 'Endpoint Protection - Product Status expired' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 138 -RuleName 'Endpoint Protection - Product Status offline scan required' -DefaultCategory 24 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 139 -RuleName 'Client Settings - Deployments' -DefaultCategory 9 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 140 -RuleName 'Client Settings - Use New Software Center' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 141 -RuleName 'Client Settings - Client Cache Size' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 142 -RuleName 'Client Settings - Policy Request Schedule (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 143 -RuleName 'Client Settings - Policy Request Schedule (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 144 -RuleName 'Client Settings - User Policy' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 145 -RuleName 'Client Settings - Reboot Logoff Notification Countdown Duration (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 146 -RuleName 'Client Settings - Reboot Logoff Notification Countdown Duration (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 147 -RuleName 'Client Settings - Reboot Logoff Notification Final Countdown (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 148 -RuleName 'Client Settings - Reboot Logoff Notification Final Countdown (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 149 -RuleName 'Client Settings - Hardware Inventory' -DefaultCategory 9 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 150 -RuleName 'Client Settings - Hardware Inventory Schedule (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 151 -RuleName 'Client Settings - Hardware Inventory Schedule (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 152 -RuleName 'Client Settings - Software Inventory' -DefaultCategory 9 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 153 -RuleName 'Client Settings - Software Inventory Schedule (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 154 -RuleName 'Client Settings - Software Inventory Schedule (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 155 -RuleName 'Client Settings - Software Reevaluation (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 156 -RuleName 'Client Settings - Software Reevaluation (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 157 -RuleName 'Client Settings - Software Updates' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 158 -RuleName 'Client Settings - Software Update Scan Schedule (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 159 -RuleName 'Client Settings - Software Update Scan Schedule (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 160 -RuleName 'Client Settings - Software Update Reevaluation Schedule (Higher)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 161 -RuleName 'Client Settings - Software Update Reevaluation Schedule (Lower)' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 162 -RuleName 'Client Settings - Software Update Reevaluation and Scan Schedule' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 163 -RuleName 'Client Settings - Endpoint Protection' -DefaultCategory 9 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 164 -RuleName 'Maintenance Task - Backup SMS Site Server' -DefaultCategory 4 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 165 -RuleName 'Maintenance Task - Rebuild Indexes' -DefaultCategory 4 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 166 -RuleName 'Boundary Group - Site System Count' -DefaultCategory 13 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 167 -RuleName 'Boundary Group - Boundary Count' -DefaultCategory 13 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 168 -RuleName 'Boundary Group - Fallback DP Relationship (Higher)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 169 -RuleName 'Boundary Group - Fallback DP Relationship (Lower)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 170 -RuleName 'Boundary Group - Fallback MP Relationship (Higher)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 171 -RuleName 'Boundary Group - Fallback MP Relationship (Lower)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 172 -RuleName 'Boundary Group - Fallback SMP Relationship (Higher)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 173 -RuleName 'Boundary Group - Fallback SMP Relationship (Lower)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 174 -RuleName 'Boundary Group - Fallback SUP Relationship (Higher)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 175 -RuleName 'Boundary Group - Fallback SUP Relationship (Lower)' -DefaultCategory 13 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 176 -RuleName 'Endpoint Protection - Malware Detected' -DefaultCategory 14 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 177 -RuleName 'Endpoint Protection - Antimalware Policy Deployment Count' -DefaultCategory 14 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 178 -RuleName 'Endpoint Protection - Antimalware Policy Limit CPU' -DefaultCategory 14 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 179 -RuleName 'Endpoint Protection - Antimalware Policy Delete Quarantined Files Schedule (Higher)' -DefaultCategory 14 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 180 -RuleName 'Endpoint Protection - Antimalware Policy Delete Quarantined Files Schedule (Lower)' -DefaultCategory 14 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 181 -RuleName 'Endpoint Protection - Firewall Policy Deployment Count' -DefaultCategory 14 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 182 -RuleName 'Endpoint Protection - Firewall Policy Settings' -DefaultCategory 14 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 183 -RuleName 'Software Metering - Auto Create Rules' -DefaultCategory 15 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 184 -RuleName 'Software Metering - Disabled Rules' -DefaultCategory 15 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 185 -RuleName 'Boot Images - F8' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 186 -RuleName 'Boot Images - Default Boot Image Usage' -DefaultCategory 15 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 187 -RuleName 'Boot Images - Boot Image Usage' -DefaultCategory 15 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 188 -RuleName 'Boot Images - PXE Architecture Count' -DefaultCategory 15 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 189 -RuleName 'Boot Images - Default Boot Image Binary Delta Replication' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 190 -RuleName 'Boot Images - Default Boot Image Drivers' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 191 -RuleName 'Boot Images - Binary Delta Replication' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 192 -RuleName 'Boot Images - ADK Version' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 193 -RuleName 'Software Update - Summarization (Higher)' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 194 -RuleName 'Software Update - Summarization (Lower)' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 195 -RuleName 'Software Update - Superseded' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 196 -RuleName 'Software Update - Expired' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 197 -RuleName 'Software Update - Missing Content' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 198 -RuleName 'Software Update - Content not Deployed' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 199 -RuleName 'Software Update Group - Deployments' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 200 -RuleName 'Software Update Group - Warning COunt' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 201 -RuleName 'Software Update Group - Error Count' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 202 -RuleName 'Software Update Group - Member Count' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 203 -RuleName 'Software Update Group - Expired Updates' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 204 -RuleName 'Software Update Group - Superseded Updates' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 205 -RuleName 'Software Update Group - Missing Content' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 206 -RuleName 'Software Update Group - Content not Deployed' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 207 -RuleName 'Software Update Deployment' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 208 -RuleName 'Software Update Deployment - Root Collection' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 209 -RuleName 'Software Update Deployment - State Message' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 210 -RuleName 'Software Update - ADR Deployment' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 211 -RuleName 'Software Update - ADR Last Run Error' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 212 -RuleName 'Software Update - ADR Last Run Date and Time' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 213 -RuleName 'Software Update - ADR Deployment Count' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 214 -RuleName 'Software Update - ADR Root Collection' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 215 -RuleName 'Software Update - ADR Schedule (Higher)' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 216 -RuleName 'Software Update - ADR Schedule (Lower)' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 217 -RuleName 'Software Update - ADR No Schedule' -DefaultCategory 17 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 218 -RuleName 'Software Update - ADR State Message' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 219 -RuleName 'Software Update - ADR Alert' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 220 -RuleName 'Software Update - ADR Alert Schedule (Higher)' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 221 -RuleName 'Software Update - ADR Alert Schedule (Lower)' -DefaultCategory 17 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 222 -RuleName 'Hierarchy Settings - Auto Upgrade Client' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 223 -RuleName 'Hierarchy Settings - Auto Upgrade Client Schedule (Higher)' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 224 -RuleName 'Hierarchy Settings - Auto Upgrade Client Schedule (Lower)' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 225 -RuleName 'Hierarchy Settings - Email Notification' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 226 -RuleName 'Hierarchy Settings - Email Notification Account' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 227 -RuleName 'Hierarchy Settings - Email Notification Security' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 228 -RuleName 'Active Directory Forests - Publishing Enabled' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 229 -RuleName 'Active Directory Forests - Last Discovery Error (Discovery - Access Denied)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 230 -RuleName 'Active Directory Forests - Last Discovery Error (Discovery - Failed)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 231 -RuleName 'Active Directory Forests - Last Discovery Error (Publishing - Failed)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 232 -RuleName 'Active Directory Forests - Last Discovery Error (Publishing - Unknown)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 233 -RuleName 'Active Directory Forests - Last Discovery Schedule' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 234 -RuleName 'Database Replication Status (Failed)' -DefaultCategory 19 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 235 -RuleName 'Database Replication Status (Degraded)' -DefaultCategory 19 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 236 -RuleName 'Database Replication Status (Unknown)' -DefaultCategory 19 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 237 -RuleName 'Database Replication Status - Site1 To Site2 Global Sync' -DefaultCategory 19 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 238 -RuleName 'Database Replication Status - Site2 To Site1 Global Sync' -DefaultCategory 19 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 239 -RuleName 'Database Replication Status - Enforce Enhanced Hash Algorithm' -DefaultCategory 19 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 240 -RuleName 'Database Replication Status - Link Schedule (Higher)' -DefaultCategory 19 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 241 -RuleName 'Database Replication Status - Link Schedule (Lower)' -DefaultCategory 19 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 242 -RuleName 'Status Summarization - Application Deployment 1st Interval (Higher)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 243 -RuleName 'Status Summarization - Application Deployment 1st Interval (Lower)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 244 -RuleName 'Status Summarization - Application Deployment 2nd Interval (Higher)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 245 -RuleName 'Status Summarization - Application Deployment 2nd Interval (Lower)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 246 -RuleName 'Status Summarization - Application Deployment 3rd Interval (Higher)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 247 -RuleName 'Status Summarization - Application Deployment 3rd Interval (Lower)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 248 -RuleName 'Status Summarization - Application Statistics 1st Interval (Higher)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 249 -RuleName 'Status Summarization - Application Statistics 1st Interval (Lower)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 250 -RuleName 'Status Summarization - Application Statistics 2nd Interval (Higher)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 251 -RuleName 'Status Summarization - Application Statistics 2nd Interval (Lower)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 252 -RuleName 'Status Summarization - Application Statistics 3rd Interval (Higher)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 253 -RuleName 'Status Summarization - Application Statistics 3rd Interval (Lower)' -DefaultCategory 5 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 254 -RuleName 'Account - Admin (RBAC)' -DefaultCategory 8 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 255 -RuleName 'Account  - Service Account' -DefaultCategory 8 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 256 -RuleName 'Account - Full Admin Warning' -DefaultCategory 8 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 257 -RuleName 'Account - Full Admin Error' -DefaultCategory 8 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 258 -RuleName 'Account - Group Membership' -DefaultCategory 8 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 259 -RuleName 'CPU Usage - Error' -DefaultCategory 1 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 260 -RuleName 'CPU Usage - Warning' -DefaultCategory 1 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 261 -RuleName 'Short file name creation' -DefaultCategory 1 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 262 -RuleName 'SCCM Installation on Root Drive' -DefaultCategory 1 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 263 -RuleName 'Distribution Point - Drive Free Space Error' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 264 -RuleName 'Distribution Point - Drive Free Space Warning' -DefaultCategory 12 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 265 -RuleName 'Distribution Point - Group Membership Count' -DefaultCategory 12 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 266 -RuleName 'Distribution Point - Boundary Group Count' -DefaultCategory 12 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 267 -RuleName 'Distribution Point - Multicast' -DefaultCategory 12 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 268 -RuleName 'Distribution Point - PXE Password' -DefaultCategory 12 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 269 -RuleName 'Distribution Point - Responding to PXE' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 270 -RuleName 'Distribution Point - PXE Unknown Machines' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 271 -RuleName 'Distribution Point - Content Evaluation' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 272 -RuleName 'Distribution Point - Content Evaluation Schedule (Higher)' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 273 -RuleName 'Distribution Point - Content Evaluation Schedule (Lower)' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 274 -RuleName 'Distribution Point - Content Evaluation Priority' -DefaultCategory 12 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 275 -RuleName 'Distribution Status - Default Boot Image' -DefaultCategory 20 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 276 -RuleName 'Distribution Status - Targeted Count' -DefaultCategory 20 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 277 -RuleName 'Distribution Status - Errors' -DefaultCategory 20 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 278 -RuleName 'Application - Hidden' -DefaultCategory 22 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 279 -RuleName 'Application - Devices with Failure (Error)' -DefaultCategory 22 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 280 -RuleName 'Application - Devices with Failure (Warning)' -DefaultCategory 22 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 281 -RuleName 'Application - Users with Failure (Error)' -DefaultCategory 22 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 282 -RuleName 'Application - Users with Failure (Warning)' -DefaultCategory 22 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 283 -RuleName 'Application - Deployment Count not used by TS' -DefaultCategory 22 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 284 -RuleName 'Application - Deployment Count used by TS' -DefaultCategory 22 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 286 -RuleName 'Application - DT Folder does not exist' -DefaultCategory 22 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 287 -RuleName 'Application - DT allow User Interaction' -DefaultCategory 22 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 288 -RuleName 'Distribution Point Content - Not on DP Group' -DefaultCategory 22 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 289 -RuleName 'Distribution Point Content - Not on All DPs' -DefaultCategory 22 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 290 -RuleName 'Packages - Source Path does not exist' -DefaultCategory 23 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 291 -RuleName 'Packages - Source Path Local' -DefaultCategory 23 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 292 -RuleName 'Packages - Deployment Count not used by TS' -DefaultCategory 23 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 293 -RuleName 'Packages - Deployment Count used by TS' -DefaultCategory 23 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 294 -RuleName 'Operating System - Source File Exist' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 295 -RuleName 'Operating System - Used by TS' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 296 -RuleName 'Operating System Installer - Source Exist' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 297 -RuleName 'Operating System Installer - Used by TS' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 298 -RuleName 'Task Sequence - Enabled' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 299 -RuleName 'Task Sequence - Deployment Count' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 300 -RuleName 'Task Sequence - Reboot to WinPE' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 301 -RuleName 'Task Sequence - Boot Image' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 302 -RuleName 'Task Sequence - Content Distributed' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 303 -RuleName 'Task Sequence - Content Distributed with Error' -DefaultCategory 16 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 304 -RuleName 'Inbox - Count (Error)' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 305 -RuleName 'Inbox- Count (Warning)' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 306 -RuleName 'Driver Package' -DefaultCategory 16 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 307 -RuleName 'Component Status - Summarization' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 308 -RuleName 'Component Message' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 309 -RuleName 'Heartbeat Discovery Schedule (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 310 -RuleName 'Forest Discovery Schedule (Higher)' -DefaultCategory 10 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 311 -RuleName 'SQL Server 2016 SP1' -DefaultCategory 3 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 312 -RuleName 'WSUS Windows Internal Database' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 313 -RuleName 'NO_SMS_ON_DRIVE.SMS on SystemDrive' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 285 -RuleName 'NO_SMS_ON_DRIVE.SMS on SQL Drive' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 314 -RuleName 'Multiple Software Update Point (WSUS) using same SQL Server' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 315 -RuleName 'Pending Approval Request' -DefaultCategory 22 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 316 -RuleName 'Hierarchy Settings - Auto Upgrade Client Excluded specified clients from update' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 317 -RuleName 'Hierarchy Settings - Auto Upgrade Client Exclude Servers' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 318 -RuleName 'Hierarchy Settings - Auto Upgrade Client Automatically distribute client installation package' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 319 -RuleName 'Software Update - Windows 10 Express Update' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 320 -RuleName 'Software Update - WSUS Cleanup' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 321 -RuleName 'Software Update - Synchronisation Alert' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 322 -RuleName 'Site Hierarchy - Conflicting Client Record' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 323 -RuleName 'Site Hierarchy - Client Approval Method - Manual' -DefaultCategory 2 -DefaultClassification 'ERROR'
    Set-CEHealthCheckRulesOverride -RuleID 324 -RuleName 'Site Hierarchy - Client Approval Method - Automatically all' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 325 -RuleName 'Site Hierarchy - Script authors require approver' -DefaultCategory 2 -DefaultClassification 'WARNING'    
    Set-CEHealthCheckRulesOverride -RuleID 326 -RuleName 'Site Hierarchy - Clients prefer to use management point specified in boundary group' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 327 -RuleName 'ADK Version' -DefaultCategory 2 -DefaultClassification 'WARNING'
    Set-CEHealthCheckRulesOverride -RuleID 328 -RuleName 'MDT Version' -DefaultCategory 2 -DefaultClassification 'WARNING' 
    Set-CEHealthCheckRulesOverride -RuleID 329 -RuleName 'SCCM Services on Site Server' -DefaultCategory 2 -DefaultClassification 'ERROR'
    #endregion

    #region Script default variables
    $Script:ServerDown = @()
    $Script:ServiceAccountDoesNotExist = @()
    $Script:AdminDoesNotExist = @()

    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1002)
    $Script:HealthCheckData = New-Object system.Data.DataTable "HealthCheck"
    $newCol = New-Object system.Data.DataColumn "Category",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Classification",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Description",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Comment",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "RuleID",([int])
    $Script:HealthCheckData.Columns.Add($newCol)
    #endregion

    #region Host IP Address
    #Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1003)
    #$HostIpAddressList = @()
    #$HostIpAddressList += (Get-NetIPConfiguration | Where-Object { ($_.IPv4DefaultGateway -ne $null) -and ($_.NetAdapter.Status -ne "Disconnected") }).IPv4Address.IPAddress
    #endregion

    #region check SMS Provider Info
    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1007)
    $SMSProviderServer = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\ConfigMgr10\AdminUI\Connection" -ErrorAction SilentlyContinue).Server
    if ([string]::IsNullOrEmpty($SMSProviderServer)) {
        Write-CELog -logtype "Error" -logmessage (Get-CEHealthCheckMessage 1008)
        return
    } else {
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1009 $SMSProviderServer)
    }
    #endregion

    #region HealthCheck
    try {
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1010)
        #region Import PowerShell Modules
        $CurrentDriveLetter = (get-location).Drive.Name
        $ModulePath = $env:SMS_ADMIN_UI_PATH
        if ($ModulePath -eq $null) {
	        $ModulePath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").SMS_ADMIN_UI_PATH
        }
        if ($ModulePath -eq $null) {
            Write-CELog -logtype "Error" -logmessage (Get-CEHealthCheckMessage 1011)
            return
        }

        #region Start PInvoke Code
        #based on code from https://smsagent.wordpress.com/2015/07/22/retrieving-configmgr-status-messages-with-powershell/
        $sigFormatMessage = @'
[DllImport("kernel32.dll")]
public static extern uint FormatMessage(uint flags, IntPtr source, uint messageId, uint langId, StringBuilder buffer, uint size, string[] arguments);
'@

        $sigGetModuleHandle = @'
[DllImport("kernel32.dll")]
public static extern IntPtr GetModuleHandle(string lpModuleName);
'@

        $sigLoadLibrary = @'
[DllImport("kernel32.dll")]
public static extern IntPtr LoadLibrary(string lpFileName);
'@

        $Win32FormatMessage = Add-Type -MemberDefinition $sigFormatMessage -name "Win32FormatMessage" -namespace Win32Functions -PassThru -Using System.Text
        $Win32GetModuleHandle = Add-Type -MemberDefinition $sigGetModuleHandle -name "Win32GetModuleHandle" -namespace Win32Functions -PassThru -Using System.Text
        $Win32LoadLibrary = Add-Type -MemberDefinition $sigLoadLibrary -name "Win32LoadLibrary" -namespace Win32Functions -PassThru -Using System.Text
        #endregion

        #region import SCCM DLL's
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1043 'srvmsgs.dll')
        $ptrSrvFoo = $Win32LoadLibrary::LoadLibrary("$($ModulePath)\00000409\srvmsgs.dll")
        $ptrSrvModule = $Win32GetModuleHandle::GetModuleHandle("$($ModulePath)\00000409\srvmsgs.dll")

        #Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1043 'provmsgs.dll')
        #$ptrPrvFoo = $Win32LoadLibrary::LoadLibrary("$($ModulePath)\00000409\provmsgs.dll")
        #$ptrPrvModule = $Win32GetModuleHandle::GetModuleHandle("$($ModulePath)\00000409\provmsgs.dll")

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1043 'climsgs.dll')
        $ptrCliFoo = $Win32LoadLibrary::LoadLibrary("$($ModulePath)\00000409\climsgs.dll")
        $ptrCliModule = $Win32GetModuleHandle::GetModuleHandle("$($ModulePath)\00000409\climsgs.dll")

        $sizeOfBuffer = [int]16384
        $stringArrayInput = {"%1","%2","%3","%4","%5", "%6", "%7", "%8", "%9"}
        $flags = 0x00000800 -bor 0x00000200
        $stringOutput = New-Object System.Text.StringBuilder $sizeOfBuffer
        #endregion

        #region Import SCCM Certificate for powershell
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1012 $ModulePath)
        $ModulePath = $ModulePath.Replace("bin\i386","bin\ConfigurationManager.psd1")

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1013)
        $Certificate = Get-AuthenticodeSignature -FilePath "$ModulePath" -ErrorAction SilentlyContinue
        $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher")
        try {
            $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
            $Certexist = ($CertStore.Certificates | Where-Object {$_.thumbprint -eq $Certificate.SignerCertificate.Thumbprint}) -ne $null

            if ($Certexist -eq $false) {
                $CertStore.Add($Certificate.SignerCertificate)
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1014)
            }
        } catch {
            Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1015)
            Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
            return
        } finally {
            $CertStore.Close()
        }
        #endregion

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1016)
        import-module $ModulePath -force
        $PSDriveCount = (get-psdrive -PSProvider CMSite -erroraction SilentlyContinue | Measure-Object).Count
        if ($PSDriveCount -lt 1) {
            $PSDriveCreated = $false
            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1017)
            foreach($item in $AuthorizedSiteCodes.Split(',')) {
                try {
                    new-psdrive -Name $item -PSProvider "AdminUI.PS.Provider\CMSite" -Root $SMSProviderServer | Out-Null
                    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1018 @($item,$SMSProviderServer) )
                    $PSDriveCreated = $true
                    break
                } catch {
                    Write-CELog -logtype "Error" -logmessage (Get-CEHealthCheckMessage 1019 @($item,$SMSProviderServer))
                }
            }
            if ($PSDriveCreated -eq $false) {
                Write-CELog -logtype "Error" -logmessage (Get-CEHealthCheckMessage 1020)
                return
            }
        } elseif ($PSDriveCount -gt 1) {
            Write-CELog -logtype "Error" -logmessage (Get-CEHealthCheckMessage 1021)
            return
        }

        $ModuleSCCM = Get-Module -Name ConfigurationManager
        $ModuleSCCMVersionBuild = $ModuleSCCM.Version.Minor
        if ($ModuleSCCM.Version -lt $script:MinSCCMModuleVersion) {
            if ($ModuleSCCMVersionBuild -lt $script:MinSCCMVersion) {
                Write-CELog -logtype "WARNING" -logmessage (Get-CEHealthCheckMessage 1022 @($ModuleSCCM.Version, $script:MinSCCMVersion))
                $script:ClientSettingsListName = @('BackgroundIntelligentTransfer', 'ClientPolicy', 'Cloud', 'ComplianceSettings', 'ComputerAgent', 'ComputerRestart', 'EndpointProtection', 'HardwareInventory', 'MeteredNetwork', 'MobileDevice', 'NetworkAccessProtection', 'PowerManagement', 'RemoteTools', 'SoftwareDeployment', 'SoftwareInventory', 'SoftwareMetering', 'SoftwareUpdates', 'StateMessaging', 'UserAndDeviceAffinity')
            }
        }

        $PSDriveName = "$((get-psdrive -PSProvider CMSite -erroraction SilentlyContinue).Name)"

        if ($PSDriveName -notin $AuthorizedSiteCodes.Split(',')) {
            Write-CELog -logtype "ERROR" -logmessage (Get-CEHealthCheckMessage 1023 @($PSDriveName, $AuthorizedSiteCodes))
            return
        }

        Set-Location -Path "$($PSDriveName):"
        $CMPSSuppressFastNotUsedCheck = $true

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1024)
        #endregion

        #region Collecting Data
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1025)

        #region Site Information
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Site'))
        $SiteList = Get-CMSite

        #getting the main SCCM Site (Primary Site) - There is no CAS here
        $MainSiteCode = ($SiteList | Where-Object {$_.Type -eq 2}).SiteCode

        #check if there is cas, if yes, stop
        if (($SiteList | Where-Object {$_.Type -eq 4} | Measure-Object).Count -gt 0) {
            Write-CELog -logtype "Error" -logmessage (Get-CEHealthCheckMessage 1027)
            return
        }
        #endregion

        #region Site Role List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Site Role'))
        $SiteRoleList = @()
        $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1028 @('Getting', 'Site Role List', $_.SiteCode))
            Get-CMSiteRole -SiteCode $_.SiteCode | ForEach-Object {
                $item = $_ 
                $Servername = ($item.NetworkOSPath.Replace('\\',''))
                if ($script:ExcludeServers -notcontains $Servername) {
                    $SiteRoleList += $item
                }
            }
        }
        #endregion

        #region SQL Server Primary Site
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Primary Site SQL Server'))
        $arrRuleID = @(29, 30, 31 ,32, 33, 34, 285)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SQLServerPrimarySiteList = @()
            $SiteList | Where-Object {$_.Type -eq 2} | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                $item = $_
                $SQLServerPrimarySiteList += $SiteRoleList | Where-Object {($_.SiteCode -eq $item.SiteCode) -and ($_.RoleName -eq 'SMS SQL Server')}
            }

            $SQLServerInformationList = @()
            $SQLServerPrimarySiteList | ForEach-Object {
                $item = $_
                $SQLServerName = $item.PropLists.values.Split(',')[1].Trim()

                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $SQLServerName)
                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion")
                    $ProgramFiles = $RegKey.GetValue("ProgramFilesDir")

                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server")
                    $InstanceName = $RegKey.GetValue("InstalledInstances")

                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL")
                    $InstanceID = $RegKey.GetValue($InstanceName)

                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\$($InstanceID)\Setup")
                    $SQLProgramDir = $RegKey.GetValue("SqlProgramDir")

                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\$($InstanceID)\MSSQLServer\Parameters")
                    $Arguments = @()
                    $RegKey.GetValueNames() | ForEach-Object  {
                        $Arguments += $RegKey.GetValue($_)
                    }

                    $SQLData = ''
                    $SQLLogs = ''

                    $Arguments | ForEach-Object {
                        $subItem = $_
                        $paramID = $subItem.Substring(0, 2).Tolower()
                        switch ($paramID) {
                            '-d' { $SQLData = $subItem.Replace($paramID,'').Replace('\master.mdf','') }
                            '-l' { $SQLLogs = $subItem.Replace($paramID,'').Replace('\mastlog.ldf','') }
                        }
                    }

                    $SQLDataRoot = $SQLData.Split('\')[0].Replace(':','$')
                    $SQLLogsRoot = $SQLLogs.Split('\')[0].Replace(':','$')

                    if (Test-Path -Path "filesystem::\\$($RemoteComputer)\$($SQLDataRoot)\NO_SMS_ON_DRIVE.SMS" -ErrorAction SilentlyContinue) {
                        $bPathExistDataRoot = $true
                    } else {
                        $bPathExistDataRoot = $false
                    }

                    if (Test-Path -Path "filesystem::\\$($RemoteComputer)\$($SQLLogsRoot)\NO_SMS_ON_DRIVE.SMS" -ErrorAction SilentlyContinue) {
                        $bPathExistLogRoot = $true
                    } else {
                        $bPathExistLogRoot = $false
                    }

                    $SQLServerInformationList += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $SQLServerName; 'ProgramFiles' = $ProgramFIles; 'InstallationFolder' = $SQLProgramDir; 'DataFolder' = $SQLData; 'LogFolder' = $SQLLogs; 'NOSMSONData' = $bPathExistDataRoot; 'NOSMSONLog' = $bPathExistLogRoot }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $SQLServerName; 'ConnectionType' = 'SQL Server Remote Registry (RRP/RPC)' }
                }
            }
        }
        #endregion

        #region NO_SMS_ON_DRIVE.SMS
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('NO_SMS_ON_DRIVE.SMS'))
        $arrRuleID = @(313)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $ServerNOSMSONDriveInformation = @()
            $SiteRoleList | Where-Object {$_.NetworkOSPath -notlike "manage.microsoft.com"} | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                $item = $_
                $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1047 @('NO_SMS_ON_DRIVE.SMS on SystemDrive', $RemoteComputer))
                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteComputer)
                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    
                    $SystemRoot = $RegKey.GetValue("SystemRoot").Split('\')[0].Replace(':','$')
                    if (Test-Path -Path "filesystem::\\$($RemoteComputer)\$($SystemRoot)\NO_SMS_ON_DRIVE.SMS" -ErrorAction SilentlyContinue) {
                        $bPathExist = $true
                    } else {
                        $bPathExist = $false
                    }

                    $ServerNOSMSONDriveInformation += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $RemoteComputer; 'FileExist' = $bPathExist; 'Folder' = 'C:\' }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $RemoteComputer; 'ConnectionType' = 'NO_SMS_ON_DRIVE.SMS' }

                }
            }
        }
        #endregion

        #region Collecting Short file name creation information
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Short file name creation'))

        $arrRuleID = @(261, 262)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $ServerRegistryInformation = @()
            $SiteRoleList | Where-Object {$_.NetworkOSPath -notlike "manage.microsoft.com"} | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                $item = $_
                $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1042 @('Short file name creation', $RemoteComputer))
                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteComputer)
                    $RegKey= $Reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\FileSystem")
                    if ($RegKey -eq $Null) {
                        $RegKey= $Reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\File System") #2008 format
                    }

                    $ShortNameCreation = $RegKey.GetValue("NtfsDisable8dot3NameCreation")

                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion")
                    $ProgramFiles = $RegKey.GetValue("ProgramFilesDir")

                    $ServerRegistryInformation += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $RemoteComputer; 'ShortNameCreation' = $ShortNameCreation; 'ProgramFiles' = $ProgramFiles }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $RemoteComputer; 'ConnectionType' = 'Short file name creation Remote Registry (RRP/RPC)' }

                }
            }
        }
        #endregion

        #region Collecting Processor Information
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Process CPU Utilisation'))
        $arrRuleID = @(259, 260)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $NumberOfSamples = [math]::Round([int]$Script:ProcessListSamplesMinutes * 60 / [int]$Script:ProcessListSamplesWaitSeconds)
            $ProcessInfoList = @()
            $ProcessAverageTimeList = @()
            $SiteRoleList | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                $item = $_
                $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                For ($i=1; $i -le $NumberOfSamples; $i++) {
                    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1030 @($RemoteComputer, $i, $NumberOfSamples))
                    try {
                        $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\cimv2" -class "Win32_PerfFormattedData_PerfProc_Process" -ErrorAction SilentlyContinue) | Where-Object { ($_.name -inotmatch '_total|idle') }
                        if ($itemReturn -ne $null) {
                            $ProcessInfoList += $itemReturn
                        } else {
                            $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2)' }
                            break
                        }
                    } catch {
                        Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2)' }
                        break
                    }
                    if ($i -lt $NumberOfSamples) { start-sleep $Script:ProcessListSamplesWaitSeconds }
                }

                $ProcessInfoList | Select-Object PSComputerName | Get-Unique -AsString | ForEach-Object {
                    $Item = $_
                    $ProcessAverageTimeList += $ProcessInfoList | Where-Object {$_.PSComputerName -eq $item.PSComputerName} | Group-Object Name | Select-Object -Property  @{ Name = 'ComputerName'; Expression = { $item.PSComputerName }}, Name, @{ Name = 'Average'; Expression = { ($_.Group | Measure-Object -Property PercentProcessorTime -Sum).Sum / $NumberOfSamples } }
                }
            }
        }
        #endregion

        #region Site Component List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Site Component'))
        $SiteComponentList = @()
        $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1028 @('Getting', 'Site Component List', $_.SiteCode))
            $SiteComponentList += Get-CMSiteComponent -SiteCode $_.SiteCode
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Management Point'))
        $arrRuleID = @(14, 15, 16, 170, 171)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $MPList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Management Point'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('SQL Server'))
        $arrRuleID = @(25, 26, 27, 28, 311)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SQLList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS SQL Server'}

            $SQLConfigurationList = @()
            $SQLList | Where-Object {$_.Type -eq 2} | ForEach-Object { #only looking for SQL Server on Primary Servers
                $item = $_
                $arrPropList = $item.PropLists[0].values.split(',').Trim()
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1029 @('Getting', 'SQL Server', $arrPropList[1]))

                #connect to SQL
                $SQLOpen = $false
                $conn = New-Object System.Data.SqlClient.SqlConnection
                try {
                    $conn.ConnectionString = "Data Source=$($arrPropList[1]);Initial Catalog=$($arrPropList[2]);trusted_connection = true;"
                    $conn.Open()
                    $SQLOpen = $true
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($item.NetworkOSPath.Replace('\\','')); 'ConnectionType' = 'SQL Server (SQL TCP)' }
                }

                if ($SQLOpen -eq $true) {
                    try {
                        $SqlCommand = $Conn.CreateCommand()
                        $SqlCommand.CommandTimeOut = 0
                        $SqlCommand.CommandText = "SELECT SERVERPROPERTY ('productversion'),SERVERPROPERTY ('productlevel'), SERVERPROPERTY ('edition')"
                        $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand
                        $dataset = new-object System.Data.Dataset
                        $DataAdapter.Fill($dataset) | Out-Null
                    } catch {
                        Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($item.NetworkOSPath.Replace('\\','')); 'ConnectionType' = 'SQL Server (SERVERPROPERTY) (SQL TCP)' }
                    }

                    try {
                        $SqlCommand2 = $Conn.CreateCommand()
                        $SqlCommand2.CommandTimeOut = 0
                        if (([int]$dataset.Tables[0].Column1.Split('.')[0]) -le 10) { #2008 r2 or lower\
                            $SqlCommand2.CommandText = "select (select value FROM sys.configurations WHERE name = 'max server memory (MB)') as committed_kb, (select value FROM sys.configurations WHERE name = 'min server memory (MB)') as committed_target_kb"
                        } else { #2012+
                            $SqlCommand2.CommandText = "select committed_kb, committed_target_kb from sys.dm_os_sys_info"
                        }
                        $DataAdapter2 = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand2
                        $dataset2 = new-object System.Data.Dataset
                        $DataAdapter2.Fill($dataset2) | Out-Null
                    } catch {
                        Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($item.NetworkOSPath.Replace('\\','')); 'ConnectionType' = 'SQL Server (DM_OS_SYS_INFO) (SQL TCP)' }
                    }

                    try {
                        $SqlCommand3 = $Conn.CreateCommand()
                        $SqlCommand3.CommandTimeOut = 0
                        $SqlCommand3.CommandText = "SELECT compatibility_level FROM sys.databases WHERE name = '$($arrPropList[2])'"
                        $DataAdapter3 = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand3
                        $dataset3 = new-object System.Data.Dataset
                        $DataAdapter3.Fill($dataset3) | Out-Null

                        $SQLConfigurationList += New-Object -TypeName PSObject -Property @{'ServerName' = $arrPropList[1]; 'Version' = $dataset.Tables[0].Column1; 'MinMemory' = $dataset2.Tables[0].committed_kb; 'MaxMemory' = $dataset2.Tables[0].committed_target_kb; 'CompLevel' = $dataset3.Tables[0].compatibility_level; 'Database' = $arrPropList[2] }
                    } catch {
                        Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($item.NetworkOSPath.Replace('\\','')); 'ConnectionType' = 'SQL Server (COMPATIBILITY_LEVEL) (SQL TCP)' }
                    } finally {
                        $conn.Close()
                    }
                }
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Distribution Point'))
        $arrRuleID = @(168, 169)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            if ([Convert]::ToBoolean($script:IgnoreCloudDP) -eq $true) {
                $DPList = $SiteRoleList | Where-Object {($_.RoleName -eq 'SMS Distribution Point') -and ($_.NetworkOSPath -notlike '*manage.microsoft.com')}
            } else {
                $DPList = $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Distribution Point'}
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('State Migration Point'))
        $arrRuleID = @(172, 173)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SMPList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS State Migration Point'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('MP Control Manager'))
        $arrRuleID = @(14,15,16)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $MPComponentList = $SiteComponentList | where-object {$_.ComponentName -eq 'SMS_MP_CONTROL_MANAGER'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Site Component Manager'))
        $arrRuleID = @(4,5,239)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SiteComponentManagerList = $SiteComponentList | where-object {$_.ComponentName -eq 'SMS_SITE_COMPONENT_MANAGER'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('SMS Provider'))
        $arrRuleID = @(6)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SMSPolProvComponentList = $SiteComponentList | where-object {$_.ComponentName -eq 'SMS_POLICY_PROVIDER'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Application Catalog Web Service'))
        $arrRuleID = @(18, 22)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $AppCatalogWebServiceList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Application Web Service'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Application Catalog Web Site'))
        $arrRuleID = @(19, 22)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $AppCatalogWebSiteList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Portal Web Site'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Endpoint Protection Point'))
        $arrRuleID = @(119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,163,176,177,178,179,180,181,182)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $EndpointProtectionList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Endpoint Protection Point'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Point'))
        $arrRuleID = @(20,21,157,158,159,160,161,162,174,175,312,314)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Software Update Point'}
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Point WID'))
        $arrRuleID = @(312)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPWIDList = @()
            $SUPList | ForEach-Object {
                $item = $_
                $WSUSServerName = ($item.NetworkOSPath.Replace('\\',''))

                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $WSUSServerName)
                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Update Services\Server\Setup\Installed Role Services")
                    $WIDExist = -not [String]::IsNullOrEmpty(($RegKey.GetValueNames() | Where-Object {$_ -eq 'UpdateServices-WidDatabase'}))

                    if ($WIDExist) {
                        $SUPWIDList += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $WSUSServerName;  }
                    }

                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $WSUSServerName; 'ConnectionType' = 'WID Remote Registry (RRP/RPC)' }
                }
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Point SQL Server'))
        $arrRuleID = @(314)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPSQL = @()
            $SUPList | ForEach-Object {
                $item = $_
                $WSUSServerName = ($item.NetworkOSPath.Replace('\\',''))

                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $WSUSServerName)
                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Update Services\Server\Setup")
                    $WSUSSQL = $RegKey.GetValue('SqlServerName').ToString()

                    $SUPSQL += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $WSUSServerName; 'SQLServer' = $WSUSSQL }

                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $WSUSServerName; 'ConnectionType' = 'WSUS Remote Registry (RRP/RPC)' }
                }
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('SQL Reporting Service Point'))
        $arrRuleID = @(23,24)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SRSList =  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS SRS Reporting Point'}
        }
        #endregion

        #region test MP URL
        $Script:ServerHTTPAccessInformation = @()
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Test URL'))
        $arrRuleID = @(14)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $MPList | ForEach-Object {
                $item = $_
                $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISPortsList'}).Value1
                $MPProtocol = 'HTTP'
                if ($_.sslState -in (1,3)) {
                    $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISSSLPortsList'}).Value1
                    $MPProtocol = 'HTTPS'
                }
                $servername = $_.NetworkOSPath -replace '\\', ''

                $url = "$($MPProtocol)://$($servername):$($MPPort)/sms_mp/.sms_aut?mplist"
                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url $url -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004
            }
        }

        $arrRuleID = @(15)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $MPList | ForEach-Object {
                $item = $_
                $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISPortsList'}).Value1
                $MPProtocol = 'HTTP'
                if ($_.sslState -in (1,3)) {
                    $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISSSLPortsList'}).Value1
                    $MPProtocol = 'HTTPS'
                }
                $servername = $_.NetworkOSPath -replace '\\', ''

                $url = "$($MPProtocol)://$($servername):$($MPPort)/sms_mp/.sms_aut?mpcert"
                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url $url -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004
            }
        }

        $arrRuleID = @(16)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $MPList | ForEach-Object {
                $item = $_
                $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISPortsList'}).Value1
                $MPProtocol = 'HTTP'
                if ($_.sslState -in (1,3)) {
                    $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISSSLPortsList'}).Value1
                    $MPProtocol = 'HTTPS'
                }
                $servername = $_.NetworkOSPath -replace '\\', ''

                $url = "$($MPProtocol)://$($servername):$($MPPort)/sms_mp/.sms_aut?SITESIGNCERT"
                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url $url -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004
            }
        }
        #endregion

        #region Application Catalog Web Service URL
        $arrRuleID = @(18)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $AppCatalogWebServiceList | ForEach-Object {
                $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'ServicePort' }).Value
                $ServiceName = ($_.Props | Where-Object {$_.PropertyName -eq 'ServiceName' }).Value1
                $HTTPProtocol = 'HTTP'
                if ($_.sslState -in (1,3)) {
                    $HTTPProtocol = 'HTTPS'
                }
                $servername = $_.NetworkOSPath -replace '\\', ''

                $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/$($ServiceName)/ApplicationOfferService.svc"
                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url $url -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004
            }
        }
        #endregion

        #region Application Catalog Web Site URL
        $arrRuleID = @(19)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $AppCatalogWebSiteList | ForEach-Object {
                $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'PortalPort' }).Value
                $ServiceName = ($_.Props | Where-Object {$_.PropertyName -eq 'PortalPath' }).Value1
                if ([string]::IsNullOrEmpty($ServiceName)) {
                    $ServiceName = 'CMApplicationCatalog'
                }

                $HTTPProtocol = 'HTTP'
                if ($_.sslState -in (1,3)) {
                    $HTTPProtocol = 'HTTPS'
                    $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'PortalSslPort' }).Value
                }
                $servername = $_.NetworkOSPath -replace '\\', ''

                $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/$($ServiceName)"
                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url $url -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004 -UserCredentials
            }
        }
        #endregion

        #region SUP Web Site URL
        $arrRuleID = @(20)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPList | ForEach-Object {
                $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'WSUSIISPort' }).Value
                $HTTPProtocol = 'HTTP'
                if ($_.sslState -in (1,3)) {
                    $HTTPProtocol = 'HTTPS'
                    $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'WSUSIISSSLPort' }).Value
                }
                $servername = $_.NetworkOSPath -replace '\\', ''

                $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/SimpleAuthWebService/SimpleAuth.asmx"
                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url $url -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004 -UserCredentials
            }
        }

        ##check registration
        $arrRuleID = @(21)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPList | ForEach-Object {
                try {
                    $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'WSUSIISPort' }).Value
                    $HTTPProtocol = 'HTTP'
                    if ($_.sslState -in (1,3)) {
                        $HTTPProtocol = 'HTTPS'
                        $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'WSUSIISSSLPort' }).Value
                    }
                    $servername = $_.NetworkOSPath -replace '\\', ''
                    $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/SimpleAuthWebService/SimpleAuth.asmx"

                    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1038 @($url, "GetAuthorizationCookie"))
                    $SUPProxy = New-WebServiceProxy -Uri $url -UseDefaultCredential
                    $SUPProxy.GetAuthorizationCookie('SCCMHealthCheckID', $null, 'CreatedBySCCMHealthCheck') | out-null
                    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1036)
                } catch {
                    $RuleID = 21
                    $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
                    $Script:ServerHTTPAccessInformation += New-Object -TypeName PSObject -Property @{'CommentIDError' = 5004; 'MessageIDError' = 3128; 'RuleInfo' = $RuleIDInfo; 'ServerName' = $ServerName; 'StatusCode' = "$_" }
                }
            }
        }
        #endregion

        #region SRS Reporting Point Web Site URL
        $arrRuleID = @(23)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SRSList | ForEach-Object {
                $servername = $_.NetworkOSPath -replace '\\', ''
                $RootFolder = ($_.Props | Where-Object {$_.PropertyName -eq 'RootFolder' }).Value2
                $ReportsURI = ($_.Props | Where-Object {$_.PropertyName -eq 'ReportManagerUri' }).Value2
                $ReportServerURI = ($_.Props | Where-Object {$_.PropertyName -eq 'ReportServerUri' }).Value2

                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url ("$($ReportsURI)/$($RootFolder)") -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004 -UserCredentials
            }
        }

        $arrRuleID = @(24)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SRSList | ForEach-Object {
                $servername = $_.NetworkOSPath -replace '\\', ''
                $RootFolder = ($_.Props | Where-Object {$_.PropertyName -eq 'RootFolder' }).Value2
                $ReportsURI = ($_.Props | Where-Object {$_.PropertyName -eq 'ReportManagerUri' }).Value2
                $ReportServerURI = ($_.Props | Where-Object {$_.PropertyName -eq 'ReportServerUri' }).Value2

                Test-CEUrl -RuleIDInfo $RuleIDInfo -InfoMessageID 1035 -url ("$($ReportServerURI)/$($RootFolder)") -MessageIDNameSuccess 1036 -MessageIDError 3128 -ServerName $servername -CommentIDError 5004 -CommentIDException 5004 -UserCredentials
            }
        }
        #endregion

        #region Account Information
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Account'))
        $arrRuleID = @(35,36,37, 258)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $ServiceAccountList = Get-CMAccount
        }
        #endregion

        #region Administrative Account List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Administrative Account'))
        $arrRuleID = @(37, 256, 257, 258)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $AdminAccountList = Get-CMAdministrativeUser
        }
        #endregion

        #region Getting Groups
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Account Group Membership'))
        $arrRuleID = @(35,36,37,257,258)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $Root = [ADSI]"LDAP://RootDSE"
            $oForestConfig = $Root.Get("configurationNamingContext")
            $oSearchRoot = [ADSI]("LDAP://CN=Partitions," + $oForestConfig)
            $AdSearcher = [adsisearcher]"(&(objectcategory=crossref)(netbiosname=*))"
            $AdSearcher.SearchRoot = $oSearchRoot
            $domains = $AdSearcher.FindAll()

            $GroupMembershipList = @()
            $ServiceAccountList | ForEach-Object {
                $itemAccount = $_
                #todo: need to get information about @ user, how the filter will be?
                if ($itemAccount.UserName.Indexof('@') -lt 0) {
                    Write-CELog -logtype "INFO" -logmessage "Checking group membership for $($itemAccount.UserName)"
                    $arrAccountInfo = $itemAccount.UserName.Split('\')
                    $domainNC = ($domains | Where-Object {$_.Properties.cn -eq $arrAccountInfo[0]}).Properties.ncname

                    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$($domainNC)")
                    $objSearcher.PageSize = 1000
                    $objSearcher.Filter = "samaccountname=$($arrAccountInfo[1])" #$strFilter
                    $objSearcher.SearchScope = "Subtree"
                    $objDN = ($objSearcher.FindAll()).Properties.distinguishedname

                    if ($objDN -eq $null) {
                        $Script:ServiceAccountDoesNotExist += $itemAccount.UserName
                    } else {
                        $objSearcher.Filter = "(member:1.2.840.113556.1.4.1941:=$objDN)"
                        ($objSearcher.FindAll()) | ForEach-Object {
                            $GroupMembershipList += new-object HealthCheckClasses.SCCM.CEAccountMembership($arrAccountInfo[0], $domainNC, $arrAccountInfo[1], $false, $objDN, $_.Properties.distinguishedname, $_.Properties.name)
                        }
                    }
                }
            }

            $AdminAccountList | ForEach-Object {
                $itemAccount = $_
                if ($itemAccount.LogonName.Indexof('@') -lt 0) {
                    Write-CELog -logtype "INFO" -logmessage "Checking group membership for $($itemAccount.LogonName)"
                    $arrAccountInfo = $itemAccount.LogonName.Split('\')
                    $domainNC = ($domains | Where-Object {$_.Properties.cn -eq $arrAccountInfo[0]}).Properties.ncname

                    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$($domainNC)")
                    $objSearcher.PageSize = 1000
                    $objSearcher.Filter = "samaccountname=$($arrAccountInfo[1])" #$strFilter
                    $objSearcher.SearchScope = "Subtree"
                    $objDN = ($objSearcher.FindAll()).Properties.distinguishedname

                    if ($objDN -eq $null) {
                        $Script:AdminDoesNotExist = $itemAccount.LogonName
                    } else {
                        $objSearcher.Filter = "(member:1.2.840.113556.1.4.1941:=$objDN)"
                        ($objSearcher.FindAll()) | ForEach-Object {
                            $GroupMembershipList += new-object HealthCheckClasses.SCCM.CEAccountMembership($arrAccountInfo[0], $domainNC, $arrAccountInfo[1], $false, $objDN, $_.Properties.distinguishedname, $_.Properties.name)
                        }
                    }
                }
            }
        }
        #endregion

        #region Client Status Information
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Client Status'))
        $arrRuleID = @(38,39,40,41,42,43,44,45,46,47,48,49)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $ClientStatusSettings = Get-CMClientStatusSetting
        }
        #endregion

        #region Discovery Methods
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Discovery'))
        $arrRuleID = @(50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,309,310)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $DiscoveryMethodList = Get-CMDiscoveryMethod
        }
        #endregion

        #region Distribution Point Group
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Distribution Point Group'))
        $arrRuleID = @(84,85,289)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $DPGroupList = Get-CMDistributionPointGroup
        }
        #endregion

        #region Collection Membership Evaluation
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Collection Membership Evaluation'))
        $arrRuleID = @(86,87)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $CollectionMembershipEvaluation = Get-CMCollectionMembershipEvaluationComponent
        }
        #endregion

        #region Device Collection List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Device Collection'))
        $arrRuleID = @(88,89,90,91,92,93)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $DeviceCollectionList = Get-CMDeviceCollection
        }

        $arrRuleID = @(93) #using if for the sccm version because lower than 1702 does not have the cmdlet
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            if ($ModuleSCCMVersionBuild -lt 1702) {
                $CollectionDeviceFilterCount = ($DeviceCollectionList | ForEach-Object {
                    $item = $_
                    #cade
                    $MembershipRules = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_Collection WHERE Name = '$($item.Name)'"
                    $MembershipRules.Get()

                    if (($MembershipRules.CollectionRules | Where-Object {$_.__CLASS -eq 'SMS_CollectionRuleDirect'} | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ }
                } | Measure-Object).Count
            } else {
                $CollectionDeviceFilterCount = ($DeviceCollectionList | ForEach-Object {if ((Get-CMCollectionDirectMembershipRule -CollectionName $_.Name | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ } } | Measure-Object).Count
            }
        }
        #endregion

        #region User Collection List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('User Collection'))
        $arrRuleID = @(94,95,96,97,98,99,100)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $UserCollectionList = Get-CMUserCollection
        }

        $arrRuleID = @(99) #using if for the sccm version because lower than 1702 does not have the cmdlet
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            if ($ModuleSCCMVersionBuild -lt 1702) {
                $CollectionUserFilterCount = ($UserCollectionList | ForEach-Object {
                    $item = $_
                    $MembershipRules = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_Collection WHERE Name = '$($item.Name)'"
                    $MembershipRules.Get()

                    if (($MembershipRules.CollectionRules | Where-Object {$_.__CLASS -eq 'SMS_CollectionRuleDirect'} | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ }
                } | Measure-Object).Count
            } else {
                $CollectionUserFilterCount = ($UserCollectionList | ForEach-Object {if ((Get-CMCollectionDirectMembershipRule -CollectionName $_.Name | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ } } | Measure-Object).Count
            }
        }
        #endregion

        #region Deployment List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Deployment'))
        $arrRuleID = @(100,101,284,292,293,299)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $DeploymentList = Get-CMDeployment
        }
        #endregion

        #region Alert List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Alert'))
        $arrRuleID = @(7,8,9,10,11,102,104,320)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $AlertList = Get-CMAlert
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Alert Subscription'))
        $arrRuleID = @(103,104)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $AlertSubscriptionList = Get-CMAlertSubscription
        }
        #endregion

        #region Active Directory Forests
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Active Directory Forest'))
        $arrRuleID = @(228,229,230,231,232,233)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $ADForestist = Get-CMActiveDirectoryForest

            $ADForestDiscoveryStatusList = @()
            $ADForestist | ForEach-Object {
                $item = $_

                #cade
                $StatusList = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_ADForestDiscoveryStatus WHERE ForestID = $($item.ForestID)"
                $StatusList | ForEach-Object {
                    $dt1 = Get-Date -Date "01/01/1970"
                    $dt2 = Get-Date -Date "01/01/1970"
                    if (-not [string]::IsNullOrEmpty($_.LastDiscoveryTime)) {
                        $dt1 = [datetime]::parseexact($_.LastDiscoveryTime.split('.')[0],"yyyyMMddHHmmss",[System.Globalization.CultureInfo]::InvariantCulture)
                    }

                    if (-not [string]::IsNullOrEmpty($_.LastPublishingTime)) {
                        $dt2 = [datetime]::parseexact($_.LastPublishingTime.split('.')[0],"yyyyMMddHHmmss",[System.Globalization.CultureInfo]::InvariantCulture)
                    }

                    $ADForestDiscoveryStatusList += new-object HealthCheckClasses.SCCM.CEADForestDiscoveryStatus($_.DiscoveryEnabled, $_.DiscoveryStatus, $item.ForestFQDN, $dt1, $dt2, $_.PublishingEnabled, $_.PublishingStatus, $_.SiteCode)
                }
            }
        }
        #endregion

        #region Database Replication Status
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Database Replication Status'))
        $DatabaseReplicationScheduleList = @()
        $arrRuleID = @(234,235,236,237,238)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            if (($SiteList | Measure-Object).Count -gt 1) {
                $DatabaseReplicationStatusList = Get-CMDatabaseReplicationStatus
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Database Replication Schedule'))
        $arrRuleID = @(240,241)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            if (($SiteList | Measure-Object).Count -gt 1) {
                #cade
                $DatabaseReplicationScheduleList += Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -class SMS_RcmSqlControl
            }
        }
        #endregion

        #region Device List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Device'))
        $arrRuleID = @(105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,279,280,281,282)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            #not using get-cmdevice anymore. on 1806 some properties have been removed and still on the wmi query
            #if ($ModuleSCCMVersionBuild -lt 1702) {
                $DeviceList = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_CM_RES_COLL_SMS00001"
            #} else {
            #    $DeviceList = Get-CMDevice
            #}

            $ManagedDeviceCount = ($DeviceList | Where-Object {$_.IsClient -eq $true}).Count
        }
        #endregion

        #region Client Settings List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Client Setting'))
        $arrRuleID = @(139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $ClientSettingsList = Get-CMClientSetting
            $ClientSettingsSettingsList = @()
            $ClientSettingsList | ForEach-Object {
                $item = $_
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1031 @('Getting', 'Client Setting', $item.Name))
                foreach ($itemName in $script:ClientSettingsListName) {
                    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1032 @('Getting', 'Client Setting', $itemName))
                    try {
                        Get-CMClientSetting -Name $item.Name -Setting $itemName | ForEach-Object {
                            $_.GetEnumerator() | ForEach-Object { $ClientSettingsSettingsList += new-object HealthCheckClasses.SCCM.CEClassPolicySettings($item.Name, $itemName, $_.Key, $_.Value) }
                        }
                    } catch {
                        #write error on log and continue. This is required if the $itemname does not exist (running it against an old site)
                        Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    }
                }
            }
        }
        #endregion

        #region Maintenance Task List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Maintenance Task'))
        $arrRuleID = @(164,165)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            if ($ModuleSCCMVersionBuild -lt 1702) {
                $MaintenanceTaskList = @()
                $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1028 @('Getting', 'Site Role List', $_.SiteCode))
                    $MaintenanceTaskList += Get-CMSiteMaintenanceTask -SiteCode $_.SiteCode
                }
            } else {
                $MaintenanceTaskList = Get-CMSiteMaintenanceTask
            }
        }

        #endregion

        #region Boundary Group List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Boundary Group'))
        $arrRuleID = @(166,167,168,169,170,171,172,173,174,175)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $BoundaryGroupList = Get-CMBoundaryGroup

            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Boundary Group Relationship'))
            if ($ModuleSCCMVersionBuild -lt 1702) {
                $BoundaryGroupRelationshipList = @()
            } else {
                $BoundaryGroupRelationshipList = Get-CMBoundaryGroupRelationship
            }
        }
        #endregion

        #region Malware Detection List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Malware Detected'))
        $arrRuleID = @(176)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            if ($EndpointProtectionList -ne $null) {
                $MalwareDetectedList = Get-CMDetectedMalware -CollectionId 'SMS00001'
            }
        }
        #endregion

        #region Endpoint Protection Policies & Firewall List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Anti-Malware Policy'))
        $arrRuleID = @(177,178,179,180,181,182)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            if ($EndpointProtectionList -ne $null) {
                $MalwarePolicyList = Get-CMAntimalwarePolicy

                $MalwarePolicySettingsList = @()
                $MalwarePolicyList | ForEach-Object {
                    $item = $_
                    Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1031 @('Getting', 'Malware Policy', $item.Name))

                    foreach ($itemName in $script:AntiMalwarePolicySettingsListName) {
                        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1032 @('Getting', 'Anti-Malware Policy', $itemName))
                        try {
                            Get-CMAntimalwarePolicy -Name $item.Name -Policy $itemName | ForEach-Object {
                                $_.GetEnumerator() | ForEach-Object { $MalwarePolicySettingsList += new-object HealthCheckClasses.SCCM.CEClassPolicySettings($item.Name, $itemName, $_.Key, $_.Value) }
                            }
                        } catch {
                            #write error on log and continue. This is required if the $itemname does not exist
                            Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                        }
                    }
                }
            }

            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Firewall Policy'))
            $CMPSSuppressFastNotUsedCheck = $true
            $FirewallPolicyList = Get-CMWindowsFirewallPolicy
        }
        #endregion

        #region Software Metering List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Metering Settings'))
        $arrRuleID = @(183)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SwMeteringSettingsList = Get-CMSoftwareMeteringSetting
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Metering Rules'))
        $arrRuleID = @(184)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SwMeteringRuleList = Get-CMSoftwareMeteringRule
        }
        #endregion

        #region Boot Image
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Boot Image'))
        $arrRuleID = @(185,186,187,188,189,190,191,192,275,301)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $BootList = Get-CMBootImage
        }
        #endregion

        #region Software Update Group
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Group'))
        $arrRuleID = @(200,201,202,203,204,205,206,207,208,209,210)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SoftwareUpdateGroupList = Get-CMSoftwareUpdateGroup
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Group Deployment'))
        $arrRuleID = @(207,208,209)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            if ($ModuleSCCMVersionBuild -lt 1702) {
                $SoftwareUpdateGroupDeploymentList = @()
                $SoftwareUpdateGroupList | ForEach-Object {
                    $SoftwareUpdateGroupDeploymentList = Get-CMUpdateGroupDeployment -UpdateGroup $_
                }
            } else {
                $SoftwareUpdateGroupDeploymentList = Get-CMUpdateGroupDeployment
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Deployment'))
        $arrRuleID = @(199)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            if ($ModuleSCCMVersionBuild -lt 1702) {
                #todo: test with gmi query: SELECT * FROM SMS_DeploymentSummary WHERE FeatureType = 5 and AssignmentType = 1
                $SoftwareUpdateDeploymentList = @()
            } else {
                $SoftwareUpdateDeploymentList = Get-CMSoftwareUpdateDeployment | Where-Object {$_.AssignmentType -eq 1}
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update'))
        $arrRuleID = @(195,196,197,198)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            if ($ModuleSCCMVersionBuild -lt 1702) {
                $SoftwareUpdateList = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT ci.* FROM SMS_SoftwareUpdate ci WHERE ci.CI_ID NOT IN ( SELECT CI_ID FROM SMS_CIAllCategories WHERE CategoryInstance_UniqueID='UpdateClassification:3689bdc8-b205-4af4-8d4a-a63924c5e9d5') AND ci.CI_ID NOT IN (SELECT CI_ID FROM SMS_CIAllCategories WHERE CategoryInstance_UniqueID='Product:30eb551c-6288-4716-9a78-f300ec36d72b') ORDER BY DateRevised DESC"
            } else {
                $SoftwareUpdateList = Get-CMSoftwareUpdate -Fast
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Summarization'))
        $arrRuleID = @(193,194)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SoftwareUpdateSummarizationList = Get-CMSoftwareUpdateSummarizationSchedule
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Automatic Deployment Rule'))
        $arrRuleID = @(210,211,212,213,214,215,216,217,218,219,220,221)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SoftwareUpdateADRList = Get-CMSoftwareUpdateAutoDeploymentRule
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Automatic Deployment Rule Deployment'))
        $arrRuleID = @(213,214,218,219,220,221)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            if ($ModuleSCCMVersionBuild -lt 1702) {
                $SoftwareUpdateADRDeploymetList = @() #cade Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_AutoDeployment"
            } else {
                $SoftwareUpdateADRDeploymetList = Get-CMAutoDeploymentRuleDeployment
            }
        }
        #endregion

        #region Hierarchy Settings List
        $arrRuleID = @(222,223,224,316,317,318)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $AutoUpgradeConfigs = @()
            $AutoUpgradeConfigsError = @()
            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Client Auto-Upgrade Configuration'))
            ($SiteList | Where-Object {$_.Type -eq 2}) | ForEach-Object {
                $Class = [wmiclass]""
                $class.psbase.path = "\\$($SMSProviderServer)\root\sms\site_$($_.SiteCode):SMS_Site"
                try {
                    $AutoUpgradeConfigs += $Class.InvokeMethod("GetAutoUpgradeConfigs", $null, $null)
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $AutoUpgradeConfigsError += $SiteList
                }
            }
        }
        #endregion

        #region Email Notification Component List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('E-mail notification Component'))
        $arrRuleID = @(225,226,227)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $EmailNotificationList = Get-CMEmailNotificationComponent
        }
        #endregion

        #region Status Summarization for Primary Site
        $arrRuleID = @(242,243,244,245,246,247,248,249,250,251,252,253)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SiteSummarizationList = @()
            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Status Summarization'))
            ($SiteList | Where-Object {$_.Type -eq 2}) | ForEach-Object {
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1028 @('Getting', 'Status Summarization List', $_.SiteCode))
                $Class = [wmiclass]""
                $class.psbase.path = "\\$($SMSProviderServer)\root\sms\site_$($MainSiteCode):sms_summarizationsettings"
                $method = "GetSummarizationSettings"
                $InParams = $class.GetMethodParameters($Method)
                $InParams.SiteCode = $_.SiteCode
                $InParams.SummarizationType = [uint32]2

                $returnSiteSummarization = $Class.InvokeMethod($method, $InParams, $null)
                $SiteSummarizationList += New-Object HealthCheckClasses.SCCM.CESummarizationInterval($_.SiteCode, "Application Deployment Summarizer", $returnSiteSummarization.FirstIntervalMins, $returnSiteSummarization.SecondIntervalMins, $returnSiteSummarization.ThirdIntervalMins)

                $InParams.SummarizationType = [uint32]3
                $returnSiteSummarization = $Class.InvokeMethod($method, $InParams, $null)

                $SiteSummarizationList += New-Object HealthCheckClasses.SCCM.CESummarizationInterval($_.SiteCode, "Application Statistics Summarizer", $returnSiteSummarization.FirstIntervalMins, $returnSiteSummarization.SecondIntervalMins, $returnSiteSummarization.ThirdIntervalMins)
            }
        }
        #endregion

        #region Distribution Point
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Distribution Point'))
        $arrRuleID = @(263,264,265,266,267,268,269,270,271,272,273,274)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $DistributionPointList = @()
            $DistributionPointInformationList = @()
            $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1028 @('Getting', 'Distribution Point', $_.SiteCode))
                $DistributionPointList += Get-CMDistributionPoint -SiteCode $_.SiteCode
            }

            $DistributionPointList | ForEach-Object {
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1029 @('Getting', 'Distribution Point', ($_.NetworkOSPath -replace '\\', '')))
                $DistributionPointInformationList += Get-CMDistributionPointInfo -InputObject $_
            }
            #cade
            $BoundarySiteSystemsList = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "select * from SMS_BoundaryGroupSiteSystems where Flags = 0"

            #cade
            $DistributionPointDriveInfo = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "select * from SMS_DistributionPointDriveInfo"
        }
        #endregion

        #region Distribution Status
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Distribution Status'))
        $arrRuleID = @(275,276,277)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            if ($ModuleSCCMVersionBuild -lt 1702) {
                $DistributionStatusList = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_ObjectContentExtraInfo"
            } else {
                $DistributionStatusList = Get-CMDistributionStatus
            }
        }
        #endregion

        #region Application List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Application'))
        $arrRuleID = @(278,279,280,281,282,283,284,285,286,287)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $ApplicationList = Get-CMApplication
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Deployment Type'))
        $arrRuleID = @(286,287)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $DeploymentTypeList = @()
            $ApplicationList | ForEach-Object {
                $DeploymentTypeList += Get-CMDeploymentType -InputObject $_
            }

            $PathDTInformationList = @()
            $ApplicationList | ForEach-Object {
                $item = $_

                $DeploymentTypeList | Where-Object {$_.AppModelName -eq $item.ModelName} | ForEach-Object {
                    $subItem = $_
                    #todo: needneed to ignore more?
                    #query for all technology
                    #SELECT distinct SDMPackageDigest.value('declare namespace p1="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest"; (p1:AppMgmtDigest/p1:DeploymentType/p1:Installer/@Technology)[1]','nvarchar(max)')AS DTTechnology FROM[v_ConfigurationItems] WHERE CIType_ID = 21 
                    if (@('iOSDeepLink', 'WinPhone8Deeplink', 'Deeplink') -contains $subitem.Technology)  {
                        #ignoring
                    } else {
                        if ([string]::IsNullOrEmpty($Item.SDMPackageXML) -eq $true) {
                            $arrItem = $subitem.ModelName.Split('/')
                            $itemxml = ([xml]$item.SDMPackageXML)
                            $subitemxml = $itemxml.AppMgmtDigest.DeploymentType | where-object {($_.AuthoringScopeId -eq $arrItem[0]) -and ($_.LogicalName -eq $arrItem[1])}
                            $folderName = $subitemxml.Installer.Contents.Content.Location
                        } else {
                            $subitemxml = [xml]$subItem.SDMPackageXML
                            $folderName = $subitemxml.AppMgmtDigest.DeploymentType.Installer.Contents.Content.Location
                        }
                        if ([string]::IsNullOrEmpty($folderName) -eq $false) {
                            if ($folderName -is [System.Array]) { $folderName = $FolderName[0] }
                            if (Test-Path -Path "filesystem::$($folderName)" -ErrorAction SilentlyContinue) {
                                $bPathExist = $true
                            } else {
                                $bPathExist = $false
                            }

                            $PathDTInformationList += New-Object -TypeName PSObject -Property @{'Application' = $Item.LocalizedDisplayName; 'DTName' = $subItem.LocalizedDisplayName; 'Folder' = $folderName; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                        }
                    }
                }
            }
        }
        #endregion

        #region Content List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Distribution Point Content List'))
        $arrRuleID = @(288,289)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $DPContentList = @()
            $sqlQuery = 'select * from SMS_DPContentInfo'
            if ([Convert]::ToBoolean($script:IgnoreCloudDP) -eq $true) {
                $sqlQuery += ' where NALPath not like "%manage.microsoft.com%"'
            }
            $DPContentList = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query $sqlQuery
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Distribution Point Group Content List'))
        $arrRuleID = @(288,289)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $DPGroupContentList = @()
            #cade
            $DPGroupContentList += Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query 'select * from SMS_DPGroupContentInfo'
        }
        #endregion

        #region Packages
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Package'))
        $arrRuleID = @(290,291,292,293)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $PackageList = Get-CMPackage
            $PathPkgInformationList = @()
            $PackageList | ForEach-Object {
                $Item = $_
                if (($item.Name -notin $Script:HiddenPackages) -and ($item.DefaultImageFlags -ne 2)) { #2=USMT package
                    if (-not [string]::IsNullOrEmpty($Item.PkgSourcePath)) {
                        if (Test-Path -Path "filesystem::$($Item.PkgSourcePath)" -ErrorAction SilentlyContinue) {
                            $bPathExist = $true
                        } else {
                            $bPathExist = $false
                        }
                        $PathPkgInformationList += New-Object -TypeName PSObject -Property @{'Name' = $Item.Name; 'ID' = $item.PackageID; 'Folder' = $Item.PkgSourcePath; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                    }
                }
            }
        }
        #endregion

        #region Operating System
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Operating System Image'))
        $arrRuleID = @(294,295)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $OperatingSystemImageList = Get-CMOperatingSystemImage
            $PathOSImgInformationList  = @()
            $OperatingSystemImageList | ForEach-Object {
                $Item = $_
                if (-not [string]::IsNullOrEmpty($Item.PkgSourcePath)) {
                    if (Test-Path -Path "filesystem::$($Item.PkgSourcePath)" -ErrorAction SilentlyContinue) {
                        $bPathExist = $true
                    } else {
                        $bPathExist = $false
                    }
                    $PathOSImgInformationList += New-Object -TypeName PSObject -Property @{'Name' = $Item.Name; 'ID' = $item.PackageID; 'Folder' = $Item.PkgSourcePath; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                }
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Operating System Installer'))
        $arrRuleID = @(296,297)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $OperatingSystemInstallerList = Get-CMOperatingSystemInstaller
            $PathOSInstallerInformationList = @()
            $OperatingSystemInstallerList | ForEach-Object {
                $Item = $_
                if (-not [string]::IsNullOrEmpty($Item.PkgSourcePath)) {
                    if (Test-Path -Path "filesystem::$($Item.PkgSourcePath)" -ErrorAction SilentlyContinue) {
                        $bPathExist = $true
                    } else {
                        $bPathExist = $false
                    }
                    $PathOSInstallerInformationList += New-Object -TypeName PSObject -Property @{'Name' = $Item.Name; 'ID' = $item.PackageID; 'Folder' = $Item.PkgSourcePath; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                }
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Task Sequence'))
        $arrRuleID = @(186,187,298,299,300,301,302,303)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $TaskSequenceList = Get-CMTaskSequence
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Task Sequence Reboot Step'))
        $arrRuleID = @(300)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $TaskSequenceRebootOptions = @()
            if ($ModuleSCCMVersionBuild -lt 1702) {
            } else {
                $TaskSequenceList | ForEach-Object {
                    $item = $_

                    Get-CMTaskSequenceStepReboot -TaskSequenceName $item.Name | Where-Object {($_.Enabled -eq $true) -and ($_.Target -eq 'WinPE')} | ForEach-Object {
                        $subItem = $_
                        $TaskSequenceRebootOptions += New-Object -TypeName PSObject -Property @{'Name' = $item.Name; 'StepName' = $subItem.Name}
                    }
                }
            }
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Task Sequence Reference'))
        $arrRuleID = @(186,283,284,292,293,295,297,301,302,303)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            #cade
            $TaskSequenceReferenceList = @()
            $TaskSequenceList | ForEach-Object {
                $item = $_
                $TaskSequenceReferenceList += Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT ts.*, content.* FROM SMS_ObjectContentExtraInfo content INNER JOIN SMS_TaskSequencePackageReference tspr ON tspr.RefPackageID = content.PackageID INNER JOIN SMS_TaskSequencePackage ts on ts.PackageID = tspr.PackageID where ts.PackageID = '$($item.PackageID)'"
            }
        }
        #endregion

        #region inbox monitor
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Inbox Folder'))
        $arrRuleID = @(304,305)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $inboxList = @()
            $SiteList | ForEach-Object {
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1028 @('Getting', 'Inbox Files', $_.SiteCode))
                $item = $_

                try {
                    if (Test-Path -Path "filesystem::\\$($item.ServerName)\SMS_$($item.SiteCode)\inboxes") {
                        $ChildFolders = Get-ChildItem "filesystem::\\$($item.ServerName)\SMS_$($item.SiteCode)\inboxes" -Recurse -ErrorAction Stop | Where-Object {$_.PSIsContainer}
                        foreach($subitem in $ChildFolders) {
                            if(Test-Path "filesystem::$($subitem.FullName)")
                            {
                                $fcount = (Get-ChildItem "filesystem::$($subitem.FullName)" | Where-Object {!$_.PSIsContainer} | Measure-Object).Count
                                $fsize = "{0:N2}" -f ((Get-ChildItem "filesystem::$($subitem.FullName)" | Where-Object {!$_.PSIsContainer} | Measure-Object).Sum / 1MB)
                                $inboxList += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $item.ServerName; 'FolderName' = $subitem.Name; 'FolderPath' = $subitem.FullName; 'FolderCount' = $fCount; 'FolderSize' = $fsize}
                            } else {
                                Write-CELog -logtype "ERROR" -logmessage (Get-CEHealthCheckMessage 1041 @($subitem.FullName))
                            }
                        }
                    } else {
                        Write-CELog -logtype "ERROR" -logmessage (Get-CEHealthCheckMessage 1041 @("$($item.ServerName)\SMS_$($item.SiteCode)\inboxes"))
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($item.ServerName); 'ConnectionType' = 'Folder Access (inbox) (SMB)' }
                    }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($item.ServerName); 'ConnectionType' = 'Folder Access (inbox) (SMB)' }
                }
            }
        }
        #endregion

        #region Driver Package List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Driver Package'))
        $arrRuleID = @(306)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $DriverPackageList = Get-CMDriverPackage
        }
        #endregion

        #region Component Status (Summarizer) List
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Component Status'))
        $arrRuleID = @(307)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            #Tally Interval = https://msdn.microsoft.com/en-us/library/cc144112.aspx
            #SMS_ComponentSummarizer = https://docs.microsoft.com/en-us/sccm/develop/reference/core/servers/manage/sms_componentsummarizer-server-wmi-class
            #Status = 0=green, 1=warning, 2=red
            $ComponentSummarizerList = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_ComponentSummarizer WHERE TallyInterval='0001128000100008'"
        }

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Component Status Message'))
        $arrRuleID = @(308)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $ComponentStatusMessageList = @()
            $ComponentStatusMessageList += Get-CMComponentStatusMessage -ViewingPeriod (Get-Date).AddDays(([int]$script:ComponentStatusMessageDateOld)*-1) -Severity Warning
            $ComponentStatusMessageList += Get-CMComponentStatusMessage -ViewingPeriod (Get-Date).AddDays([int]($script:ComponentStatusMessageDateOld)*-1) -Severity Error

            Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Component Status Message Details'))
            $ComponentStatusMessageCompletedList = @()
            $i=1
            $j=1
            $total = $ComponentStatusMessageList.Count
            $ComponentStatusMessageList | ForEach-Object {
                if ($i -eq 500) {
                    Write-CELog -logtype "Info" -logmessage "Analysing $([int]500*$j) out of $total"
	                $i=1
                    $J++
                } else { $i++ }

                $item = $_
                Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @("Component Status Message Details ID $($item.RecordID)"))
                try {
                    $msgIDCount = ($ComponentStatusMessageCompletedList | Where-Object {$_.MessageID -eq $item.MessageID} | Measure-Object).Count
                    if (($msgIDCount -eq 0) -or (($msgIDCount -gt 0) -and ($script:AddMultipleComponentStatusMessage -eq $true))) {
                        if ($item.ModuleName -eq 'SMS Client') {
                            $objMessageresult = $Win32FormatMessage::FormatMessage($flags, $ptrCliModule, $item.Severity -bor $item.MessageID, 0, $stringOutput, $sizeOfBuffer, $stringArrayInput)
                        } else {
                            $objMessageresult = $Win32FormatMessage::FormatMessage($flags, $ptrsrvModule, $item.Severity -bor $item.MessageID, 0, $stringOutput, $sizeOfBuffer, $stringArrayInput)
                        }
                        $objRecordID = Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "Select * from SMS_StatMsgInsStrings where recordid = $($item.RecordID)"
                        $objMessage = $stringOutput.toString().Replace("%11","").Replace("%12","").Replace("%3%4%5%6%7%8%9%10","")
                        $objRecordID | ForEach-Object {
                            $objMessage = $objMessage.Replace("%$($_.InsStrIndex+1)", $_.InsStrValue)
                        }

                        $Resolution = ""

                        if ($objMessage.tolower().indexof('possible cause') -ge 0) {
                            $arrMessage = $objMessage.Split([System.Environment]::NewLine)
                            $Message = $arrMessage[0]
                            for($i = 1; $i -lt $arrMessage.Count; $i++) {
                                if ([string]::IsNullOrEmpty($arrMessage[$i])) {
                                    continue
                                }
                                $intPossibleCause = $arrMessage[$i].tolower().indexof('possible cause:')
                                $intSolution = $arrMessage[$i].tolower().indexof('solution:')
                                if ($intPossibleCause -ge 0) {
                                    if (-not [String]::IsNullOrEmpty($Resolution)) {
                                        $Resolution += '[NL][NL]'
                                    }
                                    $Resolution += $arrMessage[$i].Substring($intPossibleCause).Trim().Replace('Possible cause: ','').trim()
                                } elseif ($intSolution -ge 0) {
                                    $Resolution += " $($arrMessage[$i].Substring($intSolution).Trim().Replace('Solution: ','').trim())"
                                }
                            }
                        } else {
                            $Message = $objMessage.Trim().Replace([System.Environment]::NewLine, ' ')
                        }
                        $ComponentStatusMessageCompletedList += New-Object -TypeName PSObject -Property @{'Component' = $item.Component; 'MachineName' = $item.MachineName; 'MessageID' = $item.MessageID; 'RecordID' = $item.RecordID; 'Message' = $Message; 'Resolution' = $Resolution; 'Time' = $item.Time }
                    } else {
                        Write-CELog -logtype "WARNING" -logmessage "Ignoring adding Message ID $($item.MessageID) to the report as it was already being added"
                    }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                }
            }
        }
        #endregion

        #region Approval Request
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Driver Package'))
        $arrRuleID = @(315)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $ApprovalRequestList = Get-CMApprovalRequest
        }
        #endregion

                #region sup component information
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Component - SyncManager'))
        $arrRuleID = @(319)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPComponentSyncManager = Get-CMSoftwareUpdatePointComponent -WsusSyncManager
        }

        #region sup component information
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Update Component'))
        $arrRuleID = @(321)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPComponent = Get-CMSoftwareUpdatePointComponent
        }
        #endregion

        #region site definition
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Site Definition'))
        $arrRuleID = @(325,326)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SiteDefinition =  Get-CMSiteDefinition
        }
        #endregion

        #region software version
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Software Version'))
        $SoftwareVersionList = @()
        $arrRuleID = @(327, 328)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SiteList | ForEach-Object {
                $item = $_
                $ServerName = $item.ServerName

                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ServerName)
                    $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                    $RegKey.GetSubKeyNames() | ForEach-Object {
                        $RegSubKey= $RegKey.OpenSubKey($_)
                        $SoftwareVersionList += New-Object -TypeName PSObject -Property @{'Key' = $_; 'Name' = $RegSubKey.GetValue("DisplayName"); 'Version' = $RegSubKey.GetValue("DisplayVersion"); 'Publisher' = $RegSubKey.GetValue("Publisher"); 'Architecture' = '64bit' }
                    }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $ServerName; 'ConnectionType' = 'Add/Remove Programs Remote Registry (64bit)' }

                }

                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ServerName)
                    $RegKey= $Reg.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
                    $RegKey.GetSubKeyNames() | ForEach-Object {
                        $RegSubKey= $RegKey.OpenSubKey($_)
                        $SoftwareVersionList += New-Object -TypeName PSObject -Property @{'Key' = $_; 'Name' = $RegSubKey.GetValue("DisplayName"); 'Version' = $RegSubKey.GetValue("DisplayVersion"); 'Publisher' = $RegSubKey.GetValue("Publisher"); 'Architecture' = '32bit' }
                    }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $ServerName; 'ConnectionType' = 'Add/Remove Programs Remote Registry (32bit)' }

                }
            }
        }
        #endregion

        #region service status
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1026 @('Service Status'))
        $ServiceList = @()
        $arrRuleID = @(329)
        if (-not (Test-CEHealthCheckCollectData -Rules $arrRuleID)) {
            Write-CELog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-CELog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $SiteList | ForEach-Object {
                $item = $_
                $RemoteComputer = $item.ServerName

                try {
                    $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\cimv2" -class "win32_Service" -ErrorAction SilentlyContinue) 
                    
                    if ($itemReturn -ne $null) {
                        $itemReturn | ForEach-Object {
                            $ServiceList += New-Object -TypeName PSObject -Property @{'ServerName' = $RemoteComputer; 'Name' = $_.Name; 'Caption' = $_.Caption; 'Started' = $_.Started; 'StartMode' = $_.StartMode; 'State' = $_.State; 'Status' = $_.Status }
                        }
                    } else {
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2)' }
                        break
                    }
                } catch {
                    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2)' }
                    break
                }
            }
        }
        #endregion

        #endregion

        #region Saving XML Files
        Write-CELog -logtype "INFO" -logmessage "Saving Information to Disk"
        $xmlList = @('SiteList', 'SiteRoleList', 'SQLServerPrimarySiteList', 'SQLServerInformationList', 'ServerRegistryInformation', 'ProcessAverageTimeList', 'SiteComponentList',
            'MPList', 'SQLList', 'SQLConfigurationList', 'ServerDown', 'DPList', 'SMPList', 'MPComponentList', 'SiteComponentManagerList', 'SMSPolProvComponentList', 'AppCatalogWebServiceList',
            'AppCatalogWebSiteList', 'EndpointProtectionList', 'SUPList', 'SRSList', 'ServiceAccountList', 'AdminAccountList', 'GroupMembershipList', 'ClientStatusSettings',
            'DiscoveryMethodList', 'DPGroupList', 'CollectionMembershipEvaluation', 'DeviceCollectionList', 'UserCollectionList', 'DeploymentList', 'AlertList', 'AlertSubscriptionList',
            'ADForestist', 'ADForestDiscoveryStatusList', 'DatabaseReplicationStatusList', 'DatabaseReplicationScheduleList', 'DeviceList', 'ClientSettingsList', 'ClientSettingsSettingsList',
            'MaintenanceTaskList', 'BoundaryGroupList', 'BoundaryGroupRelationshipList', 'MalwareDetectedList', 'MalwarePolicyList', 'MalwarePolicySettingsList', 'FirewallPolicyList',
            'SwMeteringSettingsList', 'SwMeteringRuleList', 'BootList', 'SoftwareUpdateGroupList', 'SoftwareUpdateGroupDeploymentList', 'SoftwareUpdateDeploymentList',
            'SoftwareUpdateList', 'SoftwareUpdateSummarizationList', 'SoftwareUpdateADRList', 'SoftwareUpdateADRDeploymetList', 'AutoUpgradeConfigs', 'AutoUpgradeConfigsError',
            'EmailNotificationList', 'SiteSummarizationList', 'DistributionPointList', 'DistributionPointInformationList', 'BoundarySiteSystemsList', 'DistributionPointDriveInfo',
            'DistributionStatusList', 'ApplicationList', 'DeploymentTypeList', 'DPContentList', 'DPGroupContentList', 'PackageList', 'OperatingSystemImageList', 'OperatingSystemInstallerList',
            'TaskSequenceList', 'TaskSequenceRebootOptions', 'TaskSequenceReferenceList', 'inboxList', 'DriverPackageList', 'ComponentSummarizerList', 'ComponentStatusMessageList',
            'ComponentStatusMessageCompletedList', 'ServerHTTPAccessInformation', 'PathDTInformationList', 'PathPkgInformationList', 'PathOSImgInformationList',
            'CollectionDeviceFilterCount', 'CollectionUserFilterCount', 'SUPWIDList', 'ServerNOSMSONDriveInformation', 'SUPSQL', 'ApprovalRequestList',
            'SUPComponent', 'SUPComponentSyncManager', 'SiteDefinition', 'SoftwareVersionList', 'ServiceList'
        )
        $xmlList | ForEach-Object {
            Export-CEXMLFile -VariableName $_
        }
        #endregion

        #region Create Zip File on Desktop
        $ZipFileName = "$([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop))\SCCMHealthCheck-$((Get-Date).ToString('yyyy-MM-dd HH-mm-ss')).zip"
        Write-ZipFiles -zipfilename $ZipFileName -sourcedir $SaveToFolder
        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1046 $ZipFileName)
        #endregion

        Write-CELog -logtype "Info" -logmessage (Get-CEHealthCheckMessage 1040)
    } finally {
        Set-Location -Path "$($CurrentDriveLetter):"
        Write-CELog -logtype "Info" -logmessage "Removing Folder $($SaveToFolder)"
        #Remove-Item -Path $SaveToFolder -Force -Recurse
    }
    #endregion
} catch {
    Write-CELog -logtype "EXCEPTION" -logmessage (Get-CEHealthCheckMessage 1000 $_)
    if ($Verbose) {
        Write-CELog -logtype "EXCEPTION" -logmessage "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
    }
} finally {

}
#endregion