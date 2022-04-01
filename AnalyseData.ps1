<#
    .SYNOPSIS
        Analyse ConfigMgr Data collected by the CollectData.ps1 and report health check

	.DESCRIPTION
		Analyse ConfigMgr Data collected by the CollectData.ps1 and report health check

	.PARAMETER SaveToFolder
        Folder that contains all the XML files used by the collect data script and where the HealthCheck.xml file will be saved

    .PARAMETER CategoriesFilePath
        Path for the Categories.xml file
        This file contain all the categories used by the tool

    .PARAMETER IssuesFilePath
        Path for the Issues.xml file
        This file contain all the text issues used by the tool

    .PARAMETER RecommendationsFilePath
        Path for the Recommendations.xml file
        This file contain all recommendations that the toll will provide for a fix.
        This file should contain:
            For any issue the tool identify and is aware, an ID starting with 5 should be used. ie 5001 - Upgrade ConfigMgr to the latest version.
            For any issue found by ConfigMgr (i.e. Component Staus errors or warning), a 99 should be added to the messageID. ie. if the messageID is 2388, a recommendation id 992388 should be created. This is only used by rules 308 and 363
<?xml version="1.0" encoding="utf-8" ?>
<Recommendations>
    <Recommendation id="5001" module="ConfigMgr" name="Issue the tool identified and I the solution want the user to see" />
    <Recommendation id="992388" module="ConfigMgr" name="Issue identified by ConfigMgr and the solution i want the user to see" />
</Recommendations>

	.PARAMETER RulesOverrideFilePath
        Path for the ConfigMgrRulesOverride.xml file
        This file contain all the overrides for the rules that can be changed from the default values (i.e. Enabled True/False, Category, Classifications and Criticality)
<?xml version="1.0" encoding="utf-8" ?>
<Rules>
    <Rule ID="0" Name="Default Rule" Category="1" Classification="ERROR" Criticality="High" Enabled="True" />
</Rules>

	.PARAMETER DefaultValuesOverrideFilePath
        Path for the ConfigMgrDefaultValues.xml file
        This file contain all the default values used by the tool and can be changed if required
        if there is no changes to the default values, a file with the following information should be used:
<?xml version="1.0" encoding="utf-8" ?>
<DefaultValues>
    <DefaultValue Name="DefaultValue" Type="int" value="1" />
</DefaultValues>

    .INPUTS
        None

    .OUTPUTS
        None

	.NOTES
        Author: Raphael Perez (raphael@perez.net.br)
        Website: http://www.endpointmanagers.com
        WebSite: https://github.com/dotraphael/HealthCheckToolkit_Community
        Twitter: @dotraphael

        DateCreated: 24/10/2013 (v0.1)
        Update: 05/11/2014 (v0.2)
        Update: 22/06/2015 (v0.3)
        Update: 04/02/2016 (v0.4)
        Update: 12/05/2017 (v0.5)
        Update: 03/08/2018 (v1.0)
        Update: 28/08/2018 (v1.1)
        Update: 10/09/2018 (v1.2)
        Update: 28/09/2018 (v1.3)
        Update: 14/12/2018 (v1.4)
        Update: 03/05/2019 (v1.5)
        Update: 01/10/2019 (v1.6)
        Update: 19/05/2020 (v1.7)
        Update: 26/02/2021 (v1.8)
        Update: 26/02/2021 (v1.9)
        Update: 17/02/2022 (v2.0)
        Update: 28/03/2022 (v2.1)
              - Removed need for HealthCheckClasses.dll
              - updated rule 286 addind Application & DTName information
              - Clean up Issues.xml

        Test:
            CM2111 Primary site installed on a WS2016
            CM2107 Primary site installed on a WS2019

        Requirements:
            ConfigMgr Console must be installed and connected to the ConfigMgr infrastructure to be able to run the tool
            ConfigMgr Primary Site environment. CAS is not supported

    .LINK
        http://www.endpointmanagers.com
        http://www.rflsystems.co.uk
        https://github.com/dotraphael/HealthCheckToolkit_Community

    .EXAMPLE
        Run the tool against files located into default location and use files Categories, Issues.xml, Recommendations.xml ConfigMgrrulesoverride.xml and ConfigMgrdefaultvalues.xml located on the same folder as the script
        and will save all the healthcheck.xml file into default location 'C:\Temp\ConfigMgrHealthCheck'

        .\AnalyseData.ps1 -CategoriesFilePath .\Categories.xml -IssuesFilePath .\Issues.xml -RecommendationsFilePath .\Recommendations.xml -RulesOverrideFilePath .\ConfigMgrRulesOverride.xml -DefaultValuesOverrideFilePath .\ConfigMgrDefaultValues.xml
    .EXAMPLE
        Run the tool against files located into 'C:\Temp\ConfigMgrHealthCheckNewLocation' and use files Categories, Issues.xml, Recommendations.xml ConfigMgrrulesoverride.xml and ConfigMgrdefaultvalues.xml located on the same folder as the script
        and will save all the healthcheck.xml file into default location 'C:\Temp\ConfigMgrHealthCheckNewLocation'

        .\AnalyseData.ps1 -CategoriesFilePath .\Categories.xml -IssuesFilePath .\Issues.xml -RecommendationsFilePath .\Recommendations.xml -RulesOverrideFilePath .\ConfigMgrRulesOverride.xml -DefaultValuesOverrideFilePath .\ConfigMgrDefaultValues.xml -SaveToFolder 'C:\Temp\ConfigMgrHealthCheckNewLocation'
#>
#region param
[CmdletBinding()]param (
    $SaveToFolder = 'C:\Temp\ConfigMgrHealthCheck',
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Message File Path given: $_"}})][string]$CategoriesFilePath,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Message File Path given: $_"}})][string]$IssuesFilePath,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Message File Path given: $_"}})][string]$RecommendationsFilePath,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Rules Override File Path given: $_"}})][string]$RulesOverrideFilePath,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Default Values Override File Path given: $_"}})][string]$DefaultValuesOverrideFilePath
)
#endregion

#region Starting Script, Verbose variables
$Global:ErrorCapture = @()
$Script:StartDateTime = get-date
if ($Verbose) {
    $DebugPreference = 2
    $VerbosePreference = 2
    $WarningPreference = 2
}
$Error.Clear()
$ErrorActionPreference = "Continue"
#endregion

#region Import class DLL
Add-Type -Assembly System.IO.Compression.FileSystem | Out-Null
#endregion

#region Functions
#region Test-RFLAdministrator
Function Test-RFLAdministrator {
<#
    .SYSNOPSIS
        Check if the current user is member of the Local Administrators Group

    .DESCRIPTION
        Check if the current user is member of the Local Administrators Group

    .NOTES
        Name: Test-RFLAdministrator
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Test-RFLAdministrator
#>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
#endregion

#region Add-RFLHealthCheckIssueList
Function Add-RFLHealthCheckIssueList
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]$RuleIDInfo,
        [Parameter(Mandatory=$false)][int]$IncrementValue = 1
    )
    [string]$Category = Get-RFLHealthCheckCategory $RuleIDInfo.Category
    [string]$Classification = $RuleIDInfo.Classification.ToUpper()
    $varName = "Cat$($RuleIDInfo.Category)$($RuleIDInfo.Classification.ToUpper())"
    $varInfo = (Get-Variable $varName -ErrorAction SilentlyContinue)
    if ($null -eq $varInfo) {
        $varValue = 0
    } else {
        $varValue = $varInfo.Value
    }
    $newValue = ($varValue + $IncrementValue)

    Set-Variable -Name "$varName" -Value ($newValue)
}
#endregion

#region Convert-CMSchedule
Function Convert-CMSchedule
{
    [cmdletbinding()]
    Param(
        [Parameter(
            ValueFromPipeline=$true,
            Mandatory=$True
        )]
        $ScheduleString
    )
    #source: https://tech.xenit.se/convert-sccm-schedule-readable-format/
    Begin{

    }
    Process{
        $Start = $ScheduleString.Substring(0,8)
        $Recurrence = $ScheduleString.Substring(8,8)
        If($Start -eq '00012000'){
            $Type = 'Simple'
        }
        Else{
            $Type = 'Custom'

            #Convert to binary string
            $BStart = [Convert]::ToString([int64]"0x$Start".ToString(),2)

            #Pad to 32 chars
            If($BStart.Length -lt 32){0..(31-$BStart.Length) | ForEach-Object{$Bstart = "0$BStart"}}

            #Collect timedata
            [String]$StartMinute = [Convert]::ToInt32($BStart.Substring(0,6),2)
            If($StartMinute.Length -eq 1){$StartMinute = "0$StartMinute"}
            [String]$StartHour   = [Convert]::ToInt32($BStart.Substring(6,5),2)
            If($StartHour.Length -eq 1){$StartHour = "0$StartHour"}
            [String]$StartDay    = [Convert]::ToInt32($BStart.Substring(11,5),2)
            If($StartDay.Length -eq 1){$StartDay = "0$StartDay"}
            [String]$StartMonth  = [Convert]::ToInt32($BStart.Substring(16,4),2)
            If($StartMonth.Length -eq 1){$StartMonth = "0$StartMonth"}
            [String]$StartYear   = [Convert]::ToInt32($BStart.Substring(20,6),2)+1970

            $StartString = "$StartYear-$StartMonth-$StartDay $StartHour`:$StartMinute`:00"
        }

        #Convert to binary string
        $BRec = [Convert]::ToString([int64]"0x$Recurrence".ToString(),2)

        #Pad to 32 chars
        If($BRec.Length -lt 32){0..(31-$BRec.Length) | ForEach-Object{$BRec = "0$BRec"}}

        [bool]$GMT = [Convert]::ToInt32($BRec.Substring(31,1),2)

        $DayDuration = 0
        $HourDuration = [Convert]::ToInt32($BRec.Substring(0,5),2)
        $MinuteDuration = [Convert]::ToInt32($BRec.Substring(5,5),2)
        If($HourDuration -gt 24){
            $h = $HourDuration % 24
            $DayDuration = ($HourDuration-$h)/24
            $HourDuration = $h
        }

        $RecurType = [Convert]::ToInt32($BRec.Substring(10,3),2)

        Switch($RecurType){
            1{
                $path = 'SMS_ST_NonRecurring'
                ##??
            }
            2{
                $path = 'SMS_ST_RecurInterval'
                $MinuteSpan = [Convert]::ToInt32($BRec.Substring(13,6),2)
                $HourSpan = [Convert]::ToInt32($BRec.Substring(19,5),2)
                $DaySpan = [Convert]::ToInt32($BRec.Substring(24,5),2)

                $Ret = '#TYPE IResultObject#SMS_ST_RecurInterval
                "SmsProviderObjectPath","DayDuration","DaySpan","HourDuration","HourSpan","IsGMT","MinuteDuration","MinuteSpan","StartTime","PSComputerName","PSShowComputerName"
                "SMS_ST_RecurInterval","{0}","{1}","{2}","{3}","{4}","{5}","{6}","1970-02-01 00:00:00","{7}","False"' -f $DayDuration,$DaySpan,$HourDuration,$HourSpan,$GMT,$MinuteDuration,$MinuteSpan,$env:COMPUTERNAME | ConvertFrom-Csv


            }
            3{
                $path = 'SMS_ST_RecurWeekly'

                $Day   = [Convert]::ToInt32($BRec.Substring(13,3),2)
                $ForNumberOfWeeks  = [Convert]::ToInt32($BRec.Substring(16,3),2)

                $ret = '#TYPE IResultObject#SMS_ST_RecurWeekly
                "SmsProviderObjectPath","Day","DayDuration","ForNumberOfWeeks","HourDuration","IsGMT","MinuteDuration","StartTime","PSComputerName","PSShowComputerName"
                "SMS_ST_RecurWeekly","{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","False"' -f $Day,$DayDuration,$ForNumberOfWeeks,$HourDuration,$GMT,$MinuteDuration,$StartString,$env:COMPUTERNAME | ConvertFrom-Csv

            }
            4{
                $path = 'SMS_ST_RecurMonthlyByWeekday'

                $Day   = [Convert]::ToInt32($BRec.Substring(13,3),2)
                $ForNumberOfMonths = [Convert]::ToInt32($BRec.Substring(16,4),2)
                $WeekOrder = [Convert]::ToInt32($BRec.Substring(20,3),2)

                $ret = '#TYPE IResultObject#SMS_ST_RecurMonthlyByWeekday
                "SmsProviderObjectPath","Day","DayDuration","ForNumberOfMonths","HourDuration","IsGMT","MinuteDuration","StartTime","WeekOrder","PSComputerName","PSShowComputerName"
                "SMS_ST_RecurMonthlyByWeekday","{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","False"' -f $Day,$DayDuration,$ForNumberOfMonths,$HourDuration,$GMT,$MinuteDuration,$StartString,$WeekOrder,$env:COMPUTERNAME | ConvertFrom-Csv

            }
            5{
                $path = 'SMS_ST_RecurMonthlyByDate'

                $MonthDay  = [Convert]::ToInt32($BRec.Substring(13,5),2)
                $ForNumberOfMonths = [Convert]::ToInt32($BRec.Substring(18,4),2)

                $Ret = '#TYPE IResultObject#SMS_ST_RecurMonthlyByDate
                "SmsProviderObjectPath","DayDuration","ForNumberOfMonths","HourDuration","IsGMT","MinuteDuration","MonthDay","StartTime","PSComputerName","PSShowComputerName"
                "SMS_ST_RecurMonthlyByDate","{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","False"' -f $DayDuration,$ForNumberOfMonths,$HourDuration,$GMT,$MinuteDuration,$MonthDay,$StartString,$env:COMPUTERNAME | ConvertFrom-Csv


            }
            6{
                $path = '???'
                ##??
            }
            Default{
                Write-RFLLog -LogType 'ERROR' -LogMessage "Invalid type $RecurType for $ScheduleString"
            }
        }

        $Ret
    }
    End{

    }
}
#endregion

#region Convert-CMscheduleToMinutes
Function Convert-CMScheduleObjectToMinutes
{
    [cmdletbinding()]
    Param(
        [Parameter(
            ValueFromPipeline=$true,
            Mandatory=$True
        )]
        $ScheduleObject
    )

    switch ($ScheduleObject.SmsProviderObjectPath) {
        'SMS_ST_RecurMonthlyByDate' { $scheduleToMinutes = ([int]($ScheduleObject.ForNumberOfMonths) * 30 * 24 * 60) }
        'SMS_ST_RecurMonthlyByWeekday' { $scheduleToMinutes = ([int]($ScheduleObject.ForNumberOfMonths) * 30 * 24 * 60) }
        'SMS_ST_RecurWeekly' { $scheduleToMinutes = ([int]($ScheduleObject.ForNumberOfWeeks) * 7 * 24 * 60) }
        'SMS_ST_RecurInterval' { $scheduleToMinutes = ([int]($ScheduleObject.DaySpan) * 24 * 60) + ([int]($ScheduleObject.HourSpan) * 60) + ([int]($ScheduleObject.MinuteSpan)) }
        'SMS_ST_NonRecurring' { $scheduleToMunites = [int]0 }
        Default{ Throw "Invalid type $($ScheduleObject.SmsProviderObjectPath)" }
    }
    $scheduleToMinutes
}
#endregion

#region Get-RFLHealthCheckCategory
function Get-RFLHealthCheckCategory {
    param (
        [Parameter(Mandatory=$true)][int]$MessageID
    )

    $return = ($Script:HealthCheckCategoryData.Categories.Category | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'ConfigMgr')}).Name
    if ($null -eq $return) {
        $Return = "Unknown Category with message ID $($MessageID)"
    }
    return $return
}
#endregion

#region Get-RFLHealthCheckIssue
function Get-RFLHealthCheckIssue {
    param (
        [Parameter(Mandatory=$true)][int]$MessageID,
        [Parameter(Mandatory=$false)][object[]]$MessageParameters
    )

    $return = ($Script:HealthCheckIssuesData.Issues.issue | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'ConfigMgr')}).Name
    if ($null -eq $return) {
        $Return = "Unknown Issue with message ID $($MessageID)"
    } else {
        if (($MessageParameters.Count -gt 0) -and ($return.IndexOf('{0}') -ge 0)) {
            try {
                $return = $return -f $MessageParameters
            } catch {
                $Global:ErrorCapture += $_
                Write-RFLLog -LogType 'ERROR' -LogMessage "Message with Error: $MessageID"
                throw $_
            }
        }
    }
    #return "something $messageID - $return"
    return $return
}
#endregion

#region Get-RFLHealthCheckRecommendation
function Get-RFLHealthCheckRecommendation {
    param (
        [Parameter(Mandatory=$true)][int]$MessageID,
        [Parameter(Mandatory=$false)][object[]]$MessageParameters
    )

    $return = ($Script:HealthCheckRecommendationData.Recommendations.Recommendation | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'ConfigMgr')}).Name

    if ([string]::IsNullOrEmpty($return)) {
        #$Return = ""
        $Return = "Unknown Recommendation with message ID $($MessageID)"
    } else {
        if (($MessageParameters.Count -gt 0) -and ($return.IndexOf('{0}') -ge 0)) {
            try {
                $return = $return -f $MessageParameters
            } catch {
                $Global:ErrorCapture += $_
                Write-RFLLog -LogType 'ERROR' -LogMessage "Message with Error: $MessageID"
                throw $_
            }
        }
    }
    return $return
}
#endregion

#region Get-RFLCollectionNames
function Get-RFLCollectionNames {
    param (
        [Parameter(Mandatory=$true)]$CollectionList
    )
    (($CollectionList | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
}
#endregion

#region Set-RFLHealthCheckDefaultValue
function Set-RFLHealthCheckDefaultValue {
    param (
        [Parameter(Mandatory=$true)][string]$ValueName,
        [Parameter(Mandatory=$true)]$ValueNonExist
    )
    $ValueDetails = $Script:HealthCheckDefaultValueData.DefaultValues.DefaultValue | Where-Object {$_.Name -eq $ValueName}
    if ($null -eq $ValueDetails) {
        New-Variable -Name $ValueName -Value $ValueNonExist -Force -Option AllScope -Scope Script
        #Write-RFLLog -LogType 'INFO' -LogMessage "$ValueName is now set to default value of $((Get-Variable $ValueName).Value)"
    } else {
        if ($ValueDetails -is [array]) {
            $ValueDetails = $ValueDetails[0]
        }

        if ($ValueDetails.Type.tolower() -eq 'array') {
            New-Variable -Name $ValueName -Value $ValueDetails.value.Split(',') -Force -Option AllScope -Scope Script
        } else {
            New-Variable -Name $ValueName -Value $ValueDetails.value -Force -Option AllScope -Scope Script
        }
        Write-RFLLog -LogType 'INFO' -LogMessage "$ValueName is now set to custom default value of $((Get-Variable $ValueName).Value)"
    }
}
#endregion

#region Set-RFLHealthCheckRulesOverride
function Set-RFLHealthCheckRulesOverride {
    param (
        [Parameter(Mandatory=$true)][int]$RuleID,
        [Parameter(Mandatory=$true)][string]$RuleName,
        [Parameter(Mandatory=$true)][int]$DefaultCategory,
        [Parameter(Mandatory=$true)][string]$Criticality,
        [Parameter(Mandatory=$true)][string]$DefaultClassification
    )
    $ValueDetails = $Script:HealthCheckRulesOverrideData.Rules.Rule | Where-Object {$_.ID -eq $RuleID}
    $VariableName = "RuleID$($RuleID)"

    $objRule = New-Object -TypeName PSObject -Property @{'ID' = $RuleID; 'Name' = $RuleName; 'Category' = $DefaultCategory; 'Classification' = $DefaultClassification;'Criticality'=$Criticality;'Enabled'=$true }
    #$objRule = new-object HealthCheckClasses.HealthCheck.CEClassRules($RuleID, $RuleName, $DefaultCategory, $DefaultClassification, $Criticality, $true)
    $ShowMsg = $false

    if ($null -ne $ValueDetails) {
        if ($ValueDetails -is [array]) {
            $ValueDetails = $ValueDetails[0]
        }
        $objRule.Category = $ValueDetails.Category
        $objRule.Classification = $ValueDetails.Classification
        $objRule.Criticality = $ValueDetails.Criticality
        $objRule.Enabled = [Convert]::ToBoolean($ValueDetails.Enabled)
        $ShowMsg = $true
    }
    New-Variable -Name $VariableName -Value $objRule -Force -Option AllScope -Scope Script
    if ($ShowMsg) {
        Write-RFLLog -LogType 'INFO' -LogMessage "Rule ID $($RuleID) information is set to custom values of Category: $((Get-Variable $VariableName).Value.Category), Classification: $((Get-Variable $VariableName).Value.Classification), Enabled: $((Get-Variable $VariableName).Value.Enabled)"
    }
}
#endregion

#region Write-RFLHealthCheckData
function Write-RFLHealthCheckData {
    PARAM (
        [Parameter(Mandatory=$true)][string]$Description,
        [Parameter(Mandatory=$false)][string]$Comment,
        [Parameter(Mandatory=$true)]$RuleIDInfo
    )
    $newRow = $Script:HealthCheckData.NewRow()
    $newRow.Category = Get-RFLHealthCheckCategory $RuleIDInfo.Category
    $newRow.Classification = $RuleIDInfo.Classification
    $newRow.Description = $Description.Trim()
    $newRow.Comment = $Comment.Trim()
    $newRow.RuleID = $RuleIDInfo.ID
    $newRow.CategoryID = $RuleIDInfo.Category
    $newRow.RuleName = $ruleIDInfo.Name
    $newRow.Criticality = $RuleIDInfo.Criticality
    switch ($RuleIDInfo.Criticality.ToUpper()) {
        "HIGH" {
            $newRow.CriticalityID = 1
        }
        "MEDIUM" {
            $newRow.CriticalityID = 2
        }
        default {
            $newRow.CriticalityID = 3
        }
    }

    $Script:HealthCheckData.Rows.Add($newRow)
    Write-RFLLog -logtype "$($newRow.Classification)" -logmessage "$($newRow.Category) - $Description"
}
#endregion

#region Test-RFLHealthCheckCollectData
function Test-RFLHealthCheckCollectData {
    param (
        [Parameter(Mandatory=$true)][int[]]$Rules
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

#region Clear-RFLLog
Function Clear-RFLLog {
<#
    .SYSNOPSIS
        Delete the log file if bigger than maximum size

    .DESCRIPTION
        Delete the log file if bigger than maximum size

    .NOTES
        Name: Clear-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Clear-RFLLog -maxSize 2mb
#>
param (
    [Parameter(Mandatory = $true)][string]$maxSize
)
    try  {
        if(Test-Path -Path $script:ScriptLogFilePath) {
            if ((Get-Item $script:ScriptLogFilePath).length -gt $maxSize) {
                Remove-Item -Path $script:ScriptLogFilePath
                Start-Sleep -Seconds 1
            }
        }
    }
    catch {
        Write-RFLLog -Message "Unable to delete log file." -LogLevel 3
    }    
}
#endregion

#region Get-ScriptDirectory
function Get-ScriptDirectory {
<#
    .SYSNOPSIS
        Get the directory of the script

    .DESCRIPTION
        Get the directory of the script

    .NOTES
        Name: ClearGet-ScriptDirectory
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
    Split-Path -Parent $PSCommandPath
}
#endregion

#region Set-RFLLogPath
Function Set-RFLLogPath {
<#
    .SYSNOPSIS
        Configures the full path to the log file depending

    .DESCRIPTION
        Configures the full path to the log file depending

    .NOTES
        Name: Set-RFLLogPath
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Set-RFLLogPath
#>
    if ([string]::IsNullOrEmpty($script:LogFilePath)) {
        $script:LogFilePath = $env:Temp
    }

    $script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
}
#endregion

#region Write-RFLLog
function Write-RFLLog {
<#
    .SYSNOPSIS
        Write the log file if the global variable is set

    .DESCRIPTION
        Write the log file if the global variable is set

    .PARAMETER LogMessage
        Message to write to the log

    .PARAMETER LogType
        Log Level Information, Warning, Error or Exception

    .NOTES
        Name: Write-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)
        Update: 23 February 2022 (v0.2)

    .EXAMPLE
        Write-RFLLog -LogMessage 'This is an information message' 

    .EXAMPLE
        Write-RFLLog -LogMessage 'This is a warning message' -LogType 'WARNING'

    .EXAMPLE
        Write-RFLLog -LogMessage 'This is an error message' -LogType 'ERROR'
#>

    PARAM (
        [Parameter(Mandatory=$false)]
        [ValidateSet('EXCEPTION', 'ERROR', 'WARNING', 'INFO')]
        [string]
        $LogType = 'INFO',

        [Parameter(Mandatory=$true)]
        [string]
        $LogMessage
    )
    $DateTime = Get-Date

    $MessageToWrite = "$($LogType.ToUpper()): $($DateTime.ToString('dd/MM/yyyy HH:mm:ss')) - $($LogMessage)"
    $MessageToWrite | Out-File -FilePath $script:ScriptLogFilePath -Append -NoClobber -Encoding default
    switch ($LogType.ToUpper()) {
        "EXCEPTION" {
            write-host $MessageToWrite -ForegroundColor Red -BackgroundColor White
            #send analytics info
        }
        "ERROR" {
            write-host $MessageToWrite -ForegroundColor Red
        }
        "WARNING" {
            Write-Host $MessageToWrite -ForegroundColor Yellow
        }
        default {
            write-Host $MessageToWrite
        }
    }
}
#endregion

#endregion

#region Variables
$script:ScriptVersion = '2.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'AnalyseData.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
#endregion


#region Main Script
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -logtype "Info" -logmessage "*** Starting ***"
    Write-RFLLog -logtype "Info" -logmessage "Script version $script:ScriptVersion"
    Write-RFLLog -logtype "Info" -logmessage "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"
    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -logtype "Info" -logmessage "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    #region Categories ID's
    Write-RFLLog -logtype "Info" -logmessage "Categories Database"
    $Script:HealthCheckCategoryData = [xml](get-content -path $CategoriesFilePath)
    #endregion

    #region Issues ID's
    Write-RFLLog -logtype "Info" -logmessage "Issues Database"
    $Script:HealthCheckIssuesData = [xml](get-content -path $IssuesFilePath)
    #endregion

    #region Recommendations ID's
    Write-RFLLog -logtype "Info" -logmessage "Recommendation Database"
    $Script:HealthCheckRecommendationData = [xml](get-content -path $RecommendationsFilePath)
    #endregion

    #region Default Values
    Write-RFLLog -logtype "Info" -logmessage "Default Values Database"
    $Script:HealthCheckDefaultValueData = [xml](get-content -path $DefaultValuesOverrideFilePath)
    #endregion

    #region Rules Override
    Write-RFLLog -logtype "Info" -logmessage "Rules Override Database"
    $Script:HealthCheckRulesOverrideData = [xml](get-content -path $RulesOverrideFilePath)
    #endregion

    #region Set Default Variables
    Write-RFLLog -logtype "Info" -logmessage "Setting Default Check Variables"
    1..25 | foreach {
        Set-RFLHealthCheckDefaultValue -ValueName "Cat$($_)ERROR" -ValueNonExist 0
        Set-RFLHealthCheckDefaultValue -ValueName "Cat$($_)WARNING" -ValueNonExist 0
    }
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumConfigMgrBuildVersion' -ValueNonExist 9040 #2010 https://docs.microsoft.com/en-us/mem/configmgr/core/servers/manage/updates#version-details
    Set-RFLHealthCheckDefaultValue -ValueName 'LatestConfigMgrBuildVersion' -ValueNonExist 9068 #2111 list can be found https://buildnumbers.wordpress.com/sccm/
    Set-RFLHealthCheckDefaultValue -ValueName 'LatestWhatsNew' -ValueNonExist 'https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/changes/whats-new-in-version-2111'
    Set-RFLHealthCheckDefaultValue -ValueName 'W10MinBuild' -ValueNonExist 18363 #1909. https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet - build can be found https://docs.microsoft.com/en-gb/windows/release-health/release-information
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSQLVersion' -ValueNonExist '12.0.6024.0' #2014 sp3 https://docs.microsoft.com/en-us/lifecycle/products/sql-server-2014, https://sqlserverbuilds.blogspot.com/ and https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/configs/support-for-sql-server-versions
    Set-RFLHealthCheckDefaultValue -ValueName 'MinADKVersion' -ValueNonExist '10.1.19041' #https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/configs/support-for-windows-10#windows-10-adk
    #ConfigMgr Build;W10ADK
    Set-RFLHealthCheckDefaultValue -ValueName 'ADKMatrix' -ValueNonExist @('9040;10.1.18362/10.1.19041', '9049;10.1.19041', '9058;10.1.19041/10.1.20348/10.1.22000', '9068;10.1.19041/10.1.20348/10.1.22000')
    Set-RFLHealthCheckDefaultValue -ValueName 'ClientSettingsListName' -ValueNonExist @('BackgroundIntelligentTransfer', 'ClientCache', 'ClientPolicy', 'Cloud', 'ComplianceSettings', 'ComputerAgent', 'ComputerRestart', 'EndpointProtection', 'HardwareInventory', 'MeteredNetwork', 'MobileDevice', 'NetworkAccessProtection', 'PowerManagement', 'RemoteTools', 'SoftwareDeployment', 'SoftwareInventory', 'SoftwareMetering', 'SoftwareUpdates', 'StateMessaging', 'UserAndDeviceAffinity', 'DeliveryOptimization', 'SoftwareCenter', 'WindowsAnalytics')
    Set-RFLHealthCheckDefaultValue -ValueName 'MinBootVersion' -ValueNonExist '10.0.18363'

    Set-RFLHealthCheckDefaultValue -ValueName 'ADPageSize' -ValueNonExist 2000
    Set-RFLHealthCheckDefaultValue -ValueName 'ExcludeServers' -ValueNonExist @()
    Set-RFLHealthCheckDefaultValue -ValueName 'ProcessListSamplesMinutes' -ValueNonExist 1
    Set-RFLHealthCheckDefaultValue -ValueName 'ProcessListSamplesWaitSeconds' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionMembershipDirectRule' -ValueNonExist 500
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSQLMemory' -ValueNonExist '8192'
    Set-RFLHealthCheckDefaultValue -ValueName 'MinConfigMgrModuleVersion' -ValueNonExist 5.1702
    Set-RFLHealthCheckDefaultValue -ValueName 'MinConfigMgrVersion' -ValueNonExist '1702'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaximumNumberOfMPS' -ValueNonExist 15
    Set-RFLHealthCheckDefaultValue -ValueName 'RolesThatMustBeInstalledPrimary' -ValueNonExist @('SMS Management Point', 'SMS Distribution Point', 'SMS Fallback Status Point', 'SMS SRS Reporting Point', 'SMS Software Update Point', 'SMS Application Web Service', 'SMS Portal Web Site')
    Set-RFLHealthCheckDefaultValue -ValueName 'RulesThatMustBeInstalledSecondary' -ValueNonExist @('SMS Management Point', 'SMS Distribution Point', 'SMS Fallback Status Point', 'SMS Software Update Point')
    Set-RFLHealthCheckDefaultValue -ValueName 'HiddenPackages' -ValueNonExist @('Configuration Manager Client Package', 'Configuration Manager Client Piloting Package')
    Set-RFLHealthCheckDefaultValue -ValueName 'RolesThatMustNotBeInstalledPrimary' -ValueNonExist @()
    Set-RFLHealthCheckDefaultValue -ValueName 'RolesThatMustNotBeInstalledSecondary' -ValueNonExist @()
    Set-RFLHealthCheckDefaultValue -ValueName 'DDRMinScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'DDRMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'ForestDiscoveryMinScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'ForestDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinScheduleInMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinExpiredLogon' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxExpiredLogon' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinPasswordSet' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxPasswordSet' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinScheduleInMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinExpiredLogon' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxExpiredLogon' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinPasswordSet' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxPasswordSet' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'UserMinScheduleInMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'UserMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinCollectionMembershipEvaluation' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionMembershipEvaluation' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionIncrementalUpdateWarning' -ValueNonExist 125
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionIncrementalUpdateError' -ValueNonExist 200
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsCleanUpInterval' -ValueNonExist 31
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsCleanUpInterval' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsDDRInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsDDRInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsHWInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsHWInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsPolicyInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsPolicyInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsStatusInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsStatusInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsSWInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsSWInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinCacheSize' -ValueNonExist 5120
    Set-RFLHealthCheckDefaultValue -ValueName 'MinPolicyRequestAssignmentTimeout' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPolicyRequestAssignmentTimeout' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MinRebootLogoffNotificationCountdownDuration' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxRebootLogoffNotificationCountdownDuration' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MinRebootLogoffNotificationFinalWindow' -ValueNonExist 15
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxRebootLogoffNotificationFinalWindow' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'MinHardwareInventoryScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxHardwareInventoryScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareInventoryScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareInventoryScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareDeploymentEvaluationScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareDeploymentEvaluationScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareUpdateScanScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareUpdateScanScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareUpdateReScanScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareUpdateReScanScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackDPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackDPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackMPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackMPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackSMPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackSMPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackSUPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackSUPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMinWarningValueAlert' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMaxWarningValueAlert' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMinCriticalValueAlert' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMaxCriticalValueAlert' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwareLimitCPUUsageMax' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwareDeleteQuarantinedFilesMax' -ValueNonExist 120
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwareDeleteQuarantinedFilesMin' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwarePolicySettingsListName' -ValueNonExist @('Advanced', 'DefaultActions', 'DefinitionUpdates', 'ExclusionSettings', 'MicrosoftActiveProtectionService', 'RealTimeProtection', 'ScanSettings', 'ScheduledScans', 'ThreatOverrides')
    Set-RFLHealthCheckDefaultValue -ValueName 'TotalOfSites' -ValueNonExist 1
    Set-RFLHealthCheckDefaultValue -ValueName 'RegExLDAPDiscovery' -ValueNonExist 'LDAP:\/\/DC=(.+[^,])'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxUpdateInSUPGroupWarning' -ValueNonExist 750
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxUpdateInSUPGroupError' -ValueNonExist 1000
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUPSummarizationTime' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSUPSummarizationTime' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'ADRLastRunMaxTime' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUPAlertTime' -ValueNonExist 4320
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSUPAlertTime' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxADRSchedule' -ValueNonExist 43200
    Set-RFLHealthCheckDefaultValue -ValueName 'MinADRSchedule' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientUpgradeDays' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientUpgradeDays' -ValueNonExist 14
    Set-RFLHealthCheckDefaultValue -ValueName 'ForestDiscoveryMaxDiscoveryTime' -ValueNonExist 14
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseReplicationMaxLagTime' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxLinkDatabaseReplicationSchedule' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinLinkDatabaseReplicationSchedule' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization1' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization1' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization2' -ValueNonExist 2880
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization2' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization3' -ValueNonExist 20160
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization3' -ValueNonExist 5040
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization1' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization1' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization2' -ValueNonExist 2880
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization2' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization3' -ValueNonExist 20160
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization3' -ValueNonExist 5040
    Set-RFLHealthCheckDefaultValue -ValueName 'GroupsNotAllowed' -ValueNonExist @('Access Control Assistance Operators', 'Account Operators', 'Administrators', 'Backup Operators', 'Certificate Service DCOM Access', 'Cryptographic Operators', 'Distributed COM Users', 'Event Log Readers', 'Guests', 'Hyper-V Administrators', 'IIS_IUSRS', 'Incoming Forest Trust Builders', 'Network Configuration Operators', 'Performance Log Users', 'Performance Monitor Users', 'Pre-Windows 2000 Compatible Access', 'Print Operators', 'RDS Endpoint Servers', 'RDS Management Servers', 'RDS Remote Access Servers', 'Remote Desktop Users', 'Remote Management Users', 'Replicator', 'Server Operators', 'Storage Replica Administrators', 'System Managed Accounts Group', 'Terminal Server License Servers', 'Windows Authorization Access Group', 'Allowed RODC Password Replication Group', 'Cert Publishers', 'Cloneable Domain Controllers', 'DHCP Administrators', 'DHCP Users', 'DnsAdmins', 'DnsUpdateProxy', 'Domain Admins', 'Domain Computers', 'Domain Controllers', 'Domain Guests', 'Enterprise Admins', 'Enterprise Key Admins', 'Enterprise Read-only Domain Controllers', 'Group Policy Creator Owners', 'Key Admins', 'Protected Users', 'RAS and IAS Servers', 'Read-only Domain Controllers', 'Schema Admins')
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFullAdminWarning' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFullAdminError' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'WarningCPUAverageUsage' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'ErrorCPUAverageUsage' -ValueNonExist 75
    Set-RFLHealthCheckDefaultValue -ValueName 'WarningPercentageFreeSpace' -ValueNonExist 20
    Set-RFLHealthCheckDefaultValue -ValueName 'ErrorPercentageFreeSpace' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'InboxFolderCountWarning' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'InboxFolderCountError' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'ApplicationFailurePercentageWarning' -ValueNonExist 25
    Set-RFLHealthCheckDefaultValue -ValueName 'ApplicationFailurePercentageError' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'ComponentStatusMessageDateOld' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxDPContentValudationSchedule' -ValueNonExist 20160
    Set-RFLHealthCheckDefaultValue -ValueName 'MinDPContentValudationSchedule' -ValueNonExist 4320
    Set-RFLHealthCheckDefaultValue -ValueName 'IgnoreCloudDP' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'AddMultipleComponentStatusMessage' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxApprovalRequestDate' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MinMDTVersion' -ValueNonExist '6.3.8450.1000'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxDistributionInProgressWarning' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxDistributionInProgressError' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingResponseTimeWarning' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingResponseTimeError' -ValueNonExist 100
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingDropPercentWarning' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingDropPercentError' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'PingDelay' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingCount' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinScheduleInMinutes' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'FreeDiskSpacePercentageWarning' -ValueNonExist 20
    Set-RFLHealthCheckDefaultValue -ValueName 'FreeDiskSpacePercentageError' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSiteServerRAMGB' -ValueNonExist 8
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSiteServerCPUCore' -ValueNonExist 8
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumRemoteServerRAMGB' -ValueNonExist 8
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumRemoteServerCPUCore' -ValueNonExist 4
    Set-RFLHealthCheckDefaultValue -ValueName 'DeploymentErrorsWarning' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'DeploymentErrorsError' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'IISRoles' -ValueNonExist @('SMS Distribution Point','SMS Management Point','SMS Software Update Point','SMS Fallback Status Point','SMS Application Web Service','SMS Portal Web Site')
    Set-RFLHealthCheckDefaultValue -ValueName 'IISExecutionTimeOut' -ValueNonExist 7200
    Set-RFLHealthCheckDefaultValue -ValueName 'IISmaxRequestLength' -ValueNonExist 20480
    Set-RFLHealthCheckDefaultValue -ValueName 'IISLogOldItemsWarning' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'IISLogOldItemsError' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'IISMaxBandwidth' -ValueNonExist -1
    Set-RFLHealthCheckDefaultValue -ValueName 'IISConnectionTimeout' -ValueNonExist 300
    Set-RFLHealthCheckDefaultValue -ValueName 'IISMaxConnections' -ValueNonExist 0
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolCPUResetInterval' -ValueNonExist 900
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolPingingEnabled' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolAppPoolRecyclePrivateMemory' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolAppPoolQueueLength' -ValueNonExist 30000
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolRapidFailProtection' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolPeriodicRestartTime' -ValueNonExist 0
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolPeriodicRestartRequests' -ValueNonExist 0
    Set-RFLHealthCheckDefaultValue -ValueName 'DPFeatures' -ValueNonExist 'Internet Information Services,IIS-WebServerRole;World Wide Web Services,IIS-WebServer;Common HTTP Features, IIS-CommonHttpFeatures;Default Document,IIS-DefaultDocument;Directory Browsing,IIS-DirectoryBrowsing;HTTP Errors,IIS-HttpErrors;Static Content,IIS-StaticContent;HTTP Redirection,IIS-HttpRedirect;Health and Diagnostics,IIS-HealthAndDiagnostics;HTTP Logging,IIS-HttpLogging;Performance Features,IIS-Performance;Static Content Compression,IIS-HttpCompressionStatic;Security,IIS-Security;Request Filtering,IIS-RequestFiltering;Windows Authentication,IIS-WindowsAuthentication;Application Development Features,IIS-ApplicationDevelopment;ISAPI Extensions,IIS-ISAPIExtensions;Web Management Tools,IIS-WebServerManagementTools;IIS Management Console,IIS-ManagementConsole;IIS 6 Management Compatibility,IIS-IIS6ManagementCompatibility;IIS Metabase and IIS 6 configuration compatibility,IIS-Metabase;IIS 6 WMI Compatibility,IIS-WMICompatibility;IIS Management Scripts and Tools,IIS-ManagementScriptingTools;Remote Differential Compression API Support,MSRDC-Infrastructure'
    Set-RFLHealthCheckDefaultValue -ValueName 'MPFeatures' -ValueNonExist 'Internet Information Services,IIS-WebServerRole;World Wide Web Services,IIS-WebServer;Common HTTP Features,IIS-CommonHttpFeatures;Default Document,IIS-DefaultDocument;Directory Browsing,IIS-DirectoryBrowsing;HTTP Errors,IIS-HttpErrors;Static Content,IIS-StaticContent;HTTP Redirection,IIS-HttpRedirect;Health and Diagnostics,IIS-HealthAndDiagnostics;HTTP Logging,IIS-HttpLogging;Logging Tools,IIS-LoggingLibraries;Request Monitor,IIS-RequestMonitor;Tracing,IIS-HttpTracing;Performance Features,IIS-Performance;Static Content Compression,IIS-HttpCompressionStatic;Security,IIS-Security;Request Filtering,IIS-RequestFiltering;Windows Authentication,IIS-WindowsAuthentication;Application Development Features,IIS-ApplicationDevelopment;.NET Extensibility 3.5,IIS-NetFxExtensibility;.NET Extensibility 4.6,IIS-NetFxExtensibility45;ISAPI Extensions,IIS-ISAPIExtensions;ISAPI Filters,IIS-ISAPIFilter;ASP.NET 3.5,IIS-ASPNET;ASP.NET 4.6,IIS-ASPNET45;Web Management Tools,IIS-WebServerManagementTools;IIS Management Console,IIS-ManagementConsole;IIS 6 Management Compatibility,IIS-IIS6ManagementCompatibility;IIS Metabase and IIS 6 configuration compatibility,IIS-Metabase;IIS 6 WMI Compatibility,IIS-WMICompatibility;IIS Management Scripts and Tools,IIS-ManagementScriptingTools;IIS Management Service,IIS-ManagementService;Background Intelligent Transfer Service (BITS),BITS;Background Intelligent Transfer Service (BITS) Server Extensions for File Upload,BITSExtensions-Upload'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxThreads' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCPULoad' -ValueNonExist 20
    Set-RFLHealthCheckDefaultValue -ValueName 'AutoGrowthDateOld' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUPGroupSummarizationTime' -ValueNonExist 43200
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSUPGroupSummarizationTime' -ValueNonExist 86400
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUSDBSize' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinConfigMgrDBSize' -ValueNonExist 75
    Set-RFLHealthCheckDefaultValue -ValueName 'ConfigMgrDBMinClients' -ValueNonExist 25000
    Set-RFLHealthCheckDefaultValue -ValueName 'LimitedCollectionToIgnore' -ValueNonExist @('All Unknown Computers','All Mobile Devices','All Desktop and Server Clients','All Provisioning Devices')
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxLimitCollection' -ValueNonExist 1
    Set-RFLHealthCheckDefaultValue -ValueName 'MinMaxMifSize' -ValueNonExist 25000000
    Set-RFLHealthCheckDefaultValue -ValueName 'AADApplicationExpireWarning' -ValueNonExist 30
    #endregion

    #region set Override Rules
    Set-RFLHealthCheckRulesOverride -RuleID 1 -RuleName 'Server Down' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 2 -RuleName 'Minimum ConfigMgr Build Version' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 3 -RuleName 'Latest ConfigMgr Build Version' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 4 -RuleName 'Enforce Enhanced Hash Algorithm' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 5 -RuleName 'Enforce Message Signing' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 6 -RuleName 'Use Encryption' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 7 -RuleName 'Site Alert' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 8 -RuleName 'Database Free Space Warning (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 9 -RuleName 'Database Free Space Warning (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 10 -RuleName 'Database Free Space Error (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 11 -RuleName 'Database Free Space Error (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 12 -RuleName 'List Roles Installed' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 13 -RuleName 'List Roles Not Installed' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 14 -RuleName 'Test MP (MPList) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 15 -RuleName 'Test MP (MPCert) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 16 -RuleName 'Test MP (SiteSign Cert) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 17 -RuleName 'MP Count' -DefaultCategory 6 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 18 -RuleName 'Application Catalog Web Service URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 19 -RuleName 'Application Catalog Web Site URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 20 -RuleName 'SUP (SimpleAuth) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 21 -RuleName 'SUP (Registration) URL' -DefaultCategory 6 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 22 -RuleName 'Application Catalog Integration' -DefaultCategory 7 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 23 -RuleName 'SQL Server Reporting Services (Reports) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 24 -RuleName 'SQL Server Reporting Services (ReportServer) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 25 -RuleName 'Minimum SQL Server' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 26 -RuleName 'Minimum SQL Memory' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 27 -RuleName 'Maximum SQL Memory' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 28 -RuleName 'SQL Compatibility Level' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 29 -RuleName 'SQL Server Installation Folder' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 30 -RuleName 'SQL Server Data Folder' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 31 -RuleName 'SQL Server Log Folder' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 32 -RuleName 'SQL Server Data Folder (Install)' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 33 -RuleName 'SQL Server Log Folder (Install)' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 34 -RuleName 'SQL Server Data Folder (Log)' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 35 -RuleName 'Account Usage' -DefaultCategory 8 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 36 -RuleName 'Account Usage (Software Distribution)' -DefaultCategory 8 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 37 -RuleName 'Account Usage (Admin)' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 38 -RuleName 'Client Status (Clean Up) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 39 -RuleName 'Client Status (Clean Up) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 40 -RuleName 'Client Status (Heartbeat) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 41 -RuleName 'Client Status (Heartbeat) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 42 -RuleName 'Client Status (Hardware) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 43 -RuleName 'Client Status (Hardware) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 44 -RuleName 'Client Status (Client Policy) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 45 -RuleName 'Client Status (Client Policy) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 46 -RuleName 'Client Status (Status Message) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 47 -RuleName 'Client Status (Status Message) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 48 -RuleName 'Client Status (Software) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 49 -RuleName 'Client Status (Software) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 50 -RuleName 'Enabled Heartbeat Discovery' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 51 -RuleName 'Heartbeat Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 52 -RuleName 'Forest Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 53 -RuleName 'Forest Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 54 -RuleName 'Forest Discovery AD Boundary' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 55 -RuleName 'Forest Discovery Subnet Boundary' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 56 -RuleName 'Network Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 57 -RuleName 'Security Group Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 58 -RuleName 'Security Group Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 59 -RuleName 'Security Group Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 60 -RuleName 'Security Group Discovery Expired Logon' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 61 -RuleName 'Security Group Discovery Expired Logon Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 62 -RuleName 'Security Group Discovery Expired Logon Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 63 -RuleName 'Security Group Discovery Expired Password' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 64 -RuleName 'Security Group Discovery Expired Password Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 65 -RuleName 'Security Group Discovery Expired Password Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 66 -RuleName 'Security Group Discovery LDAP Count' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 67 -RuleName 'Security Group Discovery LDAP Root' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 68 -RuleName 'System Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 69 -RuleName 'System Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 70 -RuleName 'System Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 71 -RuleName 'System Discovery Expired Logon' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 72 -RuleName 'System Discovery Expired Logon Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 73 -RuleName 'System Discovery Expired Logon Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 74 -RuleName 'System Discovery Expired Password' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 75 -RuleName 'System Discovery Expired Password Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 76 -RuleName 'System Discovery Expired Password Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 77 -RuleName 'System Discovery LDAP Count' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 78 -RuleName 'System Discovery LDAP Root' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 79 -RuleName 'User Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 80 -RuleName 'User Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 81 -RuleName 'User Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 82 -RuleName 'User Discovery LDAP Count' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 83 -RuleName 'User Discovery LDAP Root' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 84 -RuleName 'DP Group Has Members' -DefaultCategory 12 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 85 -RuleName 'DP Group Content In Sync' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 86 -RuleName 'Collection Membership Evaluation Schedule (Higher)' -DefaultCategory 11 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 87 -RuleName 'Collection Membership Evaluation Schedule (Lower)' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 88 -RuleName 'Device Collection Membership Rules Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 89 -RuleName 'Device Collection Membership Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 90 -RuleName 'Device Collection Limited by' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 91 -RuleName 'Device Collection Incremental Warning' -DefaultCategory 11 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 92 -RuleName 'Device Collection Incremental Error' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 93 -RuleName 'Device Collection Direct Membership Rule Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 94 -RuleName 'User Collection Membership Rules Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 95 -RuleName 'User Collection Membership Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 96 -RuleName 'User Collection Limited By' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 97 -RuleName 'User Collection Incremental Warning' -DefaultCategory 11 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 98 -RuleName 'User Collection Incremental Error' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 99 -RuleName 'User Collection Direct Membership Rule Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 100 -RuleName 'Deployment Empty Collection' -DefaultCategory 21 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 101 -RuleName 'Deployment to Root Collection' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 102 -RuleName 'Active Alerts' -DefaultCategory 18 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 103 -RuleName 'Alert Subscription Count' -DefaultCategory 18 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 104 -RuleName 'Alert Subscription' -DefaultCategory 18 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 105 -RuleName 'Device List - Non Client' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 106 -RuleName 'Device List - Active Status' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 107 -RuleName 'Device List - Blocked' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 108 -RuleName 'Device List - Approved' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 109 -RuleName 'Device List - Obsolete' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 110 -RuleName 'Device List - Windows XP' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 111 -RuleName 'Device List - WIndows XP x64' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 112 -RuleName 'Device List - WIndows Vista' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 113 -RuleName 'Device List - Windows 7' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 114 -RuleName 'Device List - Windows 2003' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 115 -RuleName 'Device List - Windows 2008' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 116 -RuleName 'Device List - Windows 2008 R2' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 117 -RuleName 'Device List - Windows Server 2012' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 118 -RuleName 'Client Version Lower Site Server' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 119 -RuleName 'Endpoint Protection - Unmanaged' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 120 -RuleName 'Endpoint Protection - To Be Installed' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 121 -RuleName 'Endpoint Protection - Install with Error' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 122 -RuleName 'Endpoint Protection - Pending Reboot' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 123 -RuleName 'Endpoint Protection - Infection Status Error' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 124 -RuleName 'Endpoint Protection - Infection Status Pending' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 125 -RuleName 'Endpoint Protection - Infection Status Unknown' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 126 -RuleName 'Endpoint Protection - Policy Status Error' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 127 -RuleName 'Endpoint Protection - Product Status Service Not Started' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 128 -RuleName 'Endpoint Protection - Product Status Pending Full Scan' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 129 -RuleName 'Endpoint Protection - Product Status Pending reboot' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 130 -RuleName 'Endpoint Protection - Product Status Pending manual steps' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 131 -RuleName 'Endpoint Protection - Product Status AV Signature Out to Date' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 132 -RuleName 'Endpoint Protection - Product Status AS Signature Out to Date' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 133 -RuleName 'Endpoint Protection - Product Status Missing quick scan' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 134 -RuleName 'Endpoint Protection - Product Status Missing full scan' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 135 -RuleName 'Endpoint Protection - Product Status Cleaning in progress' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 136 -RuleName 'Endpoint Protection - Product Status non-genuine windows' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 137 -RuleName 'Endpoint Protection - Product Status expired' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 138 -RuleName 'Endpoint Protection - Product Status offline scan required' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 139 -RuleName 'Client Settings - Deployments' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 140 -RuleName 'Client Settings - Use New Software Center' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 141 -RuleName 'Client Settings - Client Cache Size' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 142 -RuleName 'Client Settings - Policy Request Schedule (Higher)' -DefaultCategory 9 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 143 -RuleName 'Client Settings - Policy Request Schedule (Lower)' -DefaultCategory 9 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 144 -RuleName 'Client Settings - User Policy' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 145 -RuleName 'Client Settings - Reboot Logoff Notification Countdown Duration (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 146 -RuleName 'Client Settings - Reboot Logoff Notification Countdown Duration (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 147 -RuleName 'Client Settings - Reboot Logoff Notification Final Countdown (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 148 -RuleName 'Client Settings - Reboot Logoff Notification Final Countdown (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 149 -RuleName 'Client Settings - Hardware Inventory' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 150 -RuleName 'Client Settings - Hardware Inventory Schedule (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 151 -RuleName 'Client Settings - Hardware Inventory Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 152 -RuleName 'Client Settings - Software Inventory' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 153 -RuleName 'Client Settings - Software Inventory Schedule (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 154 -RuleName 'Client Settings - Software Inventory Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 155 -RuleName 'Client Settings - Software Reevaluation (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 156 -RuleName 'Client Settings - Software Reevaluation (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 157 -RuleName 'Client Settings - Software Updates' -DefaultCategory 9 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 158 -RuleName 'Client Settings - Software Update Scan Schedule (Higher)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 159 -RuleName 'Client Settings - Software Update Scan Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 160 -RuleName 'Client Settings - Software Update Reevaluation Schedule (Higher)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 161 -RuleName 'Client Settings - Software Update Reevaluation Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 162 -RuleName 'Client Settings - Software Update Reevaluation and Scan Schedule' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 163 -RuleName 'Client Settings - Endpoint Protection' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 164 -RuleName 'Maintenance Task - Backup SMS Site Server' -DefaultCategory 4 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 165 -RuleName 'Maintenance Task - Rebuild Indexes' -DefaultCategory 4 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 166 -RuleName 'Boundary Group - Site System Count' -DefaultCategory 13 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 167 -RuleName 'Boundary Group - Boundary Count' -DefaultCategory 13 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 168 -RuleName 'Boundary Group - Fallback DP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 169 -RuleName 'Boundary Group - Fallback DP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 170 -RuleName 'Boundary Group - Fallback MP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 171 -RuleName 'Boundary Group - Fallback MP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 172 -RuleName 'Boundary Group - Fallback SMP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 173 -RuleName 'Boundary Group - Fallback SMP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 174 -RuleName 'Boundary Group - Fallback SUP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 175 -RuleName 'Boundary Group - Fallback SUP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 176 -RuleName 'Endpoint Protection - Malware Detected' -DefaultCategory 14 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 177 -RuleName 'Endpoint Protection - Antimalware Policy Deployment Count' -DefaultCategory 14 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 178 -RuleName 'Endpoint Protection - Antimalware Policy Limit CPU' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 179 -RuleName 'Endpoint Protection - Antimalware Policy Delete Quarantined Files Schedule (Higher)' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 180 -RuleName 'Endpoint Protection - Antimalware Policy Delete Quarantined Files Schedule (Lower)' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 181 -RuleName 'Endpoint Protection - Firewall Policy Deployment Count' -DefaultCategory 14 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 182 -RuleName 'Endpoint Protection - Firewall Policy Settings' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 183 -RuleName 'Software Metering - Auto Create Rules' -DefaultCategory 15 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 184 -RuleName 'Software Metering - Disabled Rules' -DefaultCategory 15 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 185 -RuleName 'Boot Images - F8' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 186 -RuleName 'Boot Images - Default Boot Image Usage' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 187 -RuleName 'Boot Images - Boot Image Usage' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 188 -RuleName 'Boot Images - PXE Architecture Count' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 189 -RuleName 'Boot Images - Default Boot Image Binary Delta Replication' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 190 -RuleName 'Boot Images - Default Boot Image Drivers' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 191 -RuleName 'Boot Images - Binary Delta Replication' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 192 -RuleName 'Boot Images - ADK Version' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 193 -RuleName 'Software Update - Summarization (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 194 -RuleName 'Software Update - Summarization (Lower)' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 195 -RuleName 'Software Update - Superseded' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 196 -RuleName 'Software Update - Expired' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 197 -RuleName 'Software Update - Missing Content' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 198 -RuleName 'Software Update - Content not Deployed' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 199 -RuleName 'Software Update Group - Deployments' -DefaultCategory 17 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 200 -RuleName 'Software Update Group - Warning Count' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 201 -RuleName 'Software Update Group - Error Count' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 202 -RuleName 'Software Update Group - Member Count' -DefaultCategory 17 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 203 -RuleName 'Software Update Group - Expired Updates' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 204 -RuleName 'Software Update Group - Superseded Updates' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 205 -RuleName 'Software Update Group - Missing Content' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 206 -RuleName 'Software Update Group - Content not Deployed' -DefaultCategory 17 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 207 -RuleName 'Software Update Deployment' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 208 -RuleName 'Software Update Deployment - Root Collection' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 209 -RuleName 'Software Update Deployment - State Message' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 210 -RuleName 'Software Update - ADR Deployment' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 211 -RuleName 'Software Update - ADR Last Run Error' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 212 -RuleName 'Software Update - ADR Last Run Date and Time' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 213 -RuleName 'Software Update - ADR Deployment Count' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 214 -RuleName 'Software Update - ADR Root Collection' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 215 -RuleName 'Software Update - ADR Schedule (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 216 -RuleName 'Software Update - ADR Schedule (Lower)' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 217 -RuleName 'Software Update - ADR No Schedule' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 218 -RuleName 'Software Update - ADR State Message' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 219 -RuleName 'Software Update - ADR Alert' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 220 -RuleName 'Software Update - ADR Alert Schedule (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 221 -RuleName 'Software Update - ADR Alert Schedule (Lower)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 222 -RuleName 'Hierarchy Settings - Auto Upgrade Client' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 223 -RuleName 'Hierarchy Settings - Auto Upgrade Client Schedule (Higher)' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 224 -RuleName 'Hierarchy Settings - Auto Upgrade Client Schedule (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 225 -RuleName 'Hierarchy Settings - Email Notification' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 226 -RuleName 'Hierarchy Settings - Email Notification Account' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 227 -RuleName 'Hierarchy Settings - Email Notification Security' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 228 -RuleName 'Active Directory Forests - Publishing Enabled' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 229 -RuleName 'Active Directory Forests - Last Discovery Error (Discovery - Access Denied)' -DefaultCategory 10 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 230 -RuleName 'Active Directory Forests - Last Discovery Error (Discovery - Failed)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 231 -RuleName 'Active Directory Forests - Last Discovery Error (Publishing - Failed)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 232 -RuleName 'Active Directory Forests - Last Discovery Error (Publishing - Unknown)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 233 -RuleName 'Active Directory Forests - Last Discovery Schedule' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 234 -RuleName 'Database Replication Status (Failed)' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 235 -RuleName 'Database Replication Status (Degraded)' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 236 -RuleName 'Database Replication Status (Unknown)' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 237 -RuleName 'Database Replication Status - Site1 To Site2 Global Sync' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 238 -RuleName 'Database Replication Status - Site2 To Site1 Global Sync' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 239 -RuleName 'Database Replication Status - Enforce Enhanced Hash Algorithm' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 240 -RuleName 'Database Replication Status - Link Schedule (Higher)' -DefaultCategory 19 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 241 -RuleName 'Database Replication Status - Link Schedule (Lower)' -DefaultCategory 19 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 242 -RuleName 'Status Summarization - Application Deployment 1st Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 243 -RuleName 'Status Summarization - Application Deployment 1st Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 244 -RuleName 'Status Summarization - Application Deployment 2nd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 245 -RuleName 'Status Summarization - Application Deployment 2nd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 246 -RuleName 'Status Summarization - Application Deployment 3rd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 247 -RuleName 'Status Summarization - Application Deployment 3rd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 248 -RuleName 'Status Summarization - Application Statistics 1st Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 249 -RuleName 'Status Summarization - Application Statistics 1st Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 250 -RuleName 'Status Summarization - Application Statistics 2nd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 251 -RuleName 'Status Summarization - Application Statistics 2nd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 252 -RuleName 'Status Summarization - Application Statistics 3rd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 253 -RuleName 'Status Summarization - Application Statistics 3rd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 254 -RuleName 'Account - Admin (RBAC)' -DefaultCategory 8 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 255 -RuleName 'Account - Service Account' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 256 -RuleName 'Account - Full Admin Warning' -DefaultCategory 8 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 257 -RuleName 'Account - Full Admin Error' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 258 -RuleName 'Account - Group Membership' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 259 -RuleName 'CPU Usage - Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 260 -RuleName 'CPU Usage - Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 261 -RuleName 'Short file name creation' -DefaultCategory 1 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 262 -RuleName 'ConfigMgr Installation on Root Drive' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 263 -RuleName 'Distribution Point - Drive Free Space Error' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 264 -RuleName 'Distribution Point - Drive Free Space Warning' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 265 -RuleName 'Distribution Point - Group Membership Count' -DefaultCategory 12 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 266 -RuleName 'Distribution Point - Boundary Group Count' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 267 -RuleName 'Distribution Point - Multicast' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 268 -RuleName 'Distribution Point - PXE Password' -DefaultCategory 12 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 269 -RuleName 'Distribution Point - Responding to PXE' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 270 -RuleName 'Distribution Point - PXE Unknown Machines' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 271 -RuleName 'Distribution Point - Content Evaluation' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 272 -RuleName 'Distribution Point - Content Evaluation Schedule (Higher)' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 273 -RuleName 'Distribution Point - Content Evaluation Schedule (Lower)' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 274 -RuleName 'Distribution Point - Content Evaluation Priority' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 275 -RuleName 'Distribution Status - Default Boot Image' -DefaultCategory 20 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 276 -RuleName 'Distribution Status - Targeted Count' -DefaultCategory 20 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 277 -RuleName 'Distribution Status - Errors' -DefaultCategory 20 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 278 -RuleName 'Application - Hidden' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 279 -RuleName 'Application - Devices with Failure (Error)' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 280 -RuleName 'Application - Devices with Failure (Warning)' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 281 -RuleName 'Application - Users with Failure (Error)' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 282 -RuleName 'Application - Users with Failure (Warning)' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 283 -RuleName 'Application - not used' -DefaultCategory 22 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 284 -RuleName 'Application - used by not deployed TS' -DefaultCategory 22 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 285 -RuleName 'NO_SMS_ON_DRIVE.SMS on SQL Drive' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 286 -RuleName 'Application - DT Folder does not exist' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 287 -RuleName 'Application - DT allow User Interaction' -DefaultCategory 22 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 288 -RuleName 'Distribution Point Content - Not on DP Group' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 289 -RuleName 'Distribution Point Content - Not on All DPs' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 290 -RuleName 'Packages - Source Path does not exist' -DefaultCategory 23 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 291 -RuleName 'Packages - Source Path Local' -DefaultCategory 23 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 292 -RuleName 'Packages - Deployment Count not used by TS' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 293 -RuleName 'Packages - Deployment Count used by not deployed TS' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 294 -RuleName 'Operating System - Source File Exist' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 295 -RuleName 'Operating System - Used by TS' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 296 -RuleName 'Operating System Installer - Source Exist' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 297 -RuleName 'Operating System Installer - Used by TS' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 298 -RuleName 'Task Sequence - Enabled' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 299 -RuleName 'Task Sequence - Deployment Count' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 300 -RuleName 'Task Sequence - Reboot to WinPE' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 301 -RuleName 'Task Sequence - Boot Image' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 302 -RuleName 'Task Sequence - Content Distributed' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 303 -RuleName 'Task Sequence - Content Distributed with Error' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 304 -RuleName 'Inbox - Count (Error)' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 305 -RuleName 'Inbox - Count (Warning)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 306 -RuleName 'Driver Package' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 307 -RuleName 'Component Status - Summarization' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 308 -RuleName 'Component Message' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 309 -RuleName 'Heartbeat Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 310 -RuleName 'Forest Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 311 -RuleName 'SQL Server 2016 SP1' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 312 -RuleName 'WSUS Windows Internal Database' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 313 -RuleName 'NO_SMS_ON_DRIVE.SMS on SystemDrive' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 314 -RuleName 'Multiple Software Update Point (WSUS) using same SQL Server' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 315 -RuleName 'Pending Approval Request' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 316 -RuleName 'Hierarchy Settings - Auto Upgrade Client Excluded specified clients from update' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 317 -RuleName 'Hierarchy Settings - Auto Upgrade Client Exclude Servers' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 318 -RuleName 'Hierarchy Settings - Auto Upgrade Client Automatically distribute client installation package' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 319 -RuleName 'Software Update - Windows 10 Express Updates' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 320 -RuleName 'Software Update - WSUS Cleanup' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 321 -RuleName 'Software Update - Synchronisation Alert' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 322 -RuleName 'Site Hierarchy - Conflicting Client Record' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 323 -RuleName 'Site Hierarchy - Client Approval Method - Manual' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 324 -RuleName 'Site Hierarchy - Client Approval Method - Automatically all' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 325 -RuleName 'Site Hierarchy - Script authors require approver' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 326 -RuleName 'Site Hierarchy - Clients prefer to use management point specified in boundary group' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 327 -RuleName 'ADK Version' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 328 -RuleName 'MDT Version' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 329 -RuleName 'ConfigMgr Services on ConfigMgr Servers' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 330 -RuleName 'Collection (Total) Incremental Warning' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 331 -RuleName 'Collection (Total) Incremental Error' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 332 -RuleName 'Distribution Status - InProgress Warning' -DefaultCategory 20 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 333 -RuleName 'Distribution Status - InProgress Error' -DefaultCategory 20 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 334 -RuleName 'Ping Response Time Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 335 -RuleName 'Ping Response Time Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 336 -RuleName 'Ping Drop Percentace Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 337 -RuleName 'Ping Drop Percentace Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 338 -RuleName 'Application - Number of DT' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 339 -RuleName 'Intune Subscription' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 340 -RuleName 'IP Subnet Boundary' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 341 -RuleName 'Device Collection Schedule Too Often' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 342 -RuleName 'User Collection Schedule Too Often' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 343 -RuleName 'Boundary without GroupCount' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 344 -RuleName 'Free Disk Space - Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 345 -RuleName 'Free Disk Space - Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 346 -RuleName 'Total Site Server RAM Memory' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 347 -RuleName 'Total Site Server CPU' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 348 -RuleName 'Total Remote Server RAM Memory' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 349 -RuleName 'Total Remote Server CPU' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 350 -RuleName 'Empty Folder' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 351 -RuleName 'Deployment Errors - Warning' -DefaultCategory 21 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 352 -RuleName 'Deployment Errors - Error' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 353 -RuleName 'Task Sequence advertise to Unknown Computers for only ConfigMgr Clients' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 354 -RuleName 'Baseline - not deployed' -DefaultCategory 21 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 355 -RuleName 'Baseline - disabled' -DefaultCategory 25 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 356 -RuleName 'Baseline - hidden' -DefaultCategory 25 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 357 -RuleName 'Baseline - failures warning' -DefaultCategory 25 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 358 -RuleName 'Baseline - failures error' -DefaultCategory 25 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 359 -RuleName 'Baseline - non-compliance warning' -DefaultCategory 25 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 360 -RuleName 'Baseline - non-compliance error' -DefaultCategory 25 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 361 -RuleName 'Baseline - evaluation Schedule Too Often' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 362 -RuleName 'Account - Group Membership - Unable to collect' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 363 -RuleName 'Component Message - Errors' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 364 -RuleName 'IIS - httpRuntime executionTimeout' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 365 -RuleName 'IIS - httpRuntime maxRequestLength' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 366 -RuleName 'IIS - Log Folder - Location' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 367 -RuleName 'IIS - Log Folder - Old Items Warning' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 368 -RuleName 'IIS - Log Folder - Old Items Error' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 369 -RuleName 'IIS - WSUS Administration - MaxBandwidth' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 370 -RuleName 'IIS - WSUS Administration - ConnectionTimeout' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 371 -RuleName 'IIS - WSUS Administration - MaxConnections' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 372 -RuleName 'IIS - WSUS Administration - AppPool - CPU Reset Interval' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 373 -RuleName 'IIS - WSUS Administration - AppPool - Pinging Enabled' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 374 -RuleName 'IIS - WSUS Administration - AppPool - Recycle Private Memory' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 375 -RuleName 'IIS - WSUS Administration - AppPool - Pool Queue Length' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 376 -RuleName 'IIS - WSUS Administration - AppPool - Rapid Fail Protection' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 377 -RuleName 'IIS - WSUS Administration - AppPool - Periodic Restart Time' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 378 -RuleName 'IIS - WSUS Administration - AppPool - Periodic Restart Requests' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 379 -RuleName 'Packages - Binary Delta Replication' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 380 -RuleName 'Packages - Copy to a Package Share' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 381 -RuleName 'Ping - Unable to ping computer' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 382 -RuleName 'Boot Images - Copy to a Package Share' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 383 -RuleName 'Hirarchy Updates' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 384 -RuleName 'Device Collection - invalid Schedule' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 385 -RuleName 'User Collection - invalid Schedule' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 386 -RuleName 'Windows Features - DP' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 387 -RuleName 'Windows Features - MP' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 388 -RuleName 'Software Update - Packages - Binary Delta Replication' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 389 -RuleName 'Software Update - Packages - Copy to a Package Share' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 390 -RuleName 'SQL Server Jobs Disabled' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 391 -RuleName 'SQL Server Jobs Enabled but not scheduled' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 392 -RuleName 'SQL Server Jobs Last run status' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 393 -RuleName 'SQL Server DB CPU Waits' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 394 -RuleName 'SQL Server DB Information - Number of DB Files' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 395 -RuleName 'SQL Server DB Information - Number of Log Files' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 396 -RuleName 'SQL Server DB Information - File Size' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 397 -RuleName 'SQL Server DB Information - File Growth Size' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 398 -RuleName 'SQL Server DB Growth' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 399 -RuleName 'Software Update Group Summary Task Schedule (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 400 -RuleName 'Software Update Group Summary Task Schedule (Lower)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 401 -RuleName 'Management Insights - Action Needed' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 402 -RuleName 'Site Feature - Release and off' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 403 -RuleName 'Client Settings - Enable user policy on clients' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 404 -RuleName 'Device List - Windows 10' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 405 -RuleName 'ADK Support for ConfigMgr' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 406 -RuleName 'SQL Server Service Account' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 407 -RuleName 'Maximum Allowable Inventory file size' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 408 -RuleName 'Azure Active Directory Tenants - Application Secret Key Expirity (WARNING)' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 409 -RuleName 'Azure Active Directory Tenants - Application Secret Key Expirity (ERROR)' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 410 -RuleName 'Cloud Management Gateway - Certificate Revocation List' -DefaultCategory 1 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 411 -RuleName 'Cloud Management Gateway - VM Size' -DefaultCategory 1 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 412 -RuleName 'Cloud Management Gateway - Deployment Model' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 413 -RuleName 'HTTPS or Enhanced HTTP enabled' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    #endregion

    #region HealthCheck Table
    Write-RFLLog -logtype "Info" -logmessage "Default Reporting Table"
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
    $newCol = New-Object system.Data.DataColumn "CategoryID",([int])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "RuleName",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Criticality",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "CriticalityID",([int])
    $Script:HealthCheckData.Columns.Add($newCol)
    #endregion

    #region XML files
    Write-RFLLog -logtype "Info" -logmessage 'Importing Data from XML files'
    $xmlList = @('SiteList', 'SiteRoleList', 'SiteRoleListWOCDP', 'SiteComponentList', 'SiteComponentManagerList', 'SMSPolProvComponentList', 'AlertList', 'MPComponentList', 'MPList', 
        'AppCatalogWebServiceList', 'AppCatalogWebSiteList', 'SUPList', 'SRSList', 'SQLList', 'SQLServerPrimarySiteList', 'SQLConfigurationList', 'SQLServerInformationList', 
        'ServiceAccountList', 'AdminAccountList', 'SQLServiceAccountList', 'GroupMembershipList', 'GroupMembershipErrorList', 'AccountDoesNotExist', 'ClientStatusSettings', 
        'DiscoveryMethodList', 'DPGroupList', 'CollectionMembershipEvaluation', 'DeviceCollectionList', 'CollectionDeviceFilterCount', 'UserCollectionList', 'CollectionUserFilterCount', 
        'DeploymentList', 'AlertSubscriptionList', 'DeviceList', 'EndpointProtectionList', 'ClientSettingsList', 'ClientSettingsSettingsList', 'MaintenanceTaskList', 'BoundaryGroupList', 
        'BoundaryGroupRelationshipList', 'DPList', 'SMPList', 'MalwareDetectedList', 'MalwarePolicyList', 'MalwarePolicySettingsList', 'MalwarePolicyList', 'SwMeteringSettingsList', 
        'SwMeteringRuleList', 'BootList', 'TaskSequenceList', 'TaskSequenceReferenceList', 'SoftwareUpdateSummarizationList', 'SoftwareUpdateList', 'SoftwareUpdateDeploymentList', 
        'SoftwareUpdateGroupList', 'SoftwareUpdateGroupDeploymentList', 'SoftwareUpdateADRList', 'SoftwareUpdateADRDeploymetList', 'AutoUpgradeConfigs', 'AutoUpgradeConfigsError', 
        'EmailNotificationList', 'ADForestlist', 'ADForestDiscoveryStatusList', 'DatabaseReplicationStatusList', 'DatabaseReplicationScheduleList', 'SiteSummarizationList', 
        'ProcessAverageTimeList', 'ProcessAverageTimeList', 'ServerRegistryInformation', 'DistributionPointList', 'DistributionPointInformationList', 'BoundarySiteSystemsList', 
        'DistributionPointDriveInfo', 'DistributionStatusList', 'ApplicationList', 'DeploymentTypeList', 'PathDTInformationList', 'DPContentList', 'DPGroupContentList', 'PackageList', 
        'PathPkgInformationList', 'OperatingSystemImageList', 'PathOSImgInformationList', 'OperatingSystemInstallerList', 'PathOSInstallerInformationList', 'TaskSequenceRebootOptions', 
        'inboxList', 'DriverPackageList', 'ComponentSummarizerList', 'ComponentStatusMessageList', 'ComponentStatusMessageListError', 'ComponentStatusMessageCompletedList', 'SUPWIDList', 
        'ServerNOSMSONDriveInformation', 'SUPSQL', 'ApprovalRequestList', 'SUPComponentSyncManager', 'SUPComponent', 'SiteDefinition', 'SoftwareVersionList', 'ServiceList', 'PingList', 
        'IntuneSubscription', 'Boundary', 'LogicalDiskInfoList', 'ComputerInformationList', 'FolderInformationList', 'AdvertisementList', 'BaselineList', 'BaselineDeploymentList', 'IISList', 
        'IISClientWebService', 'IISWebServerSetting', 'IISLogs', 'IisWebVirtualDirSetting', 'IIsApplicationPoolSetting', 'CMUpdates', 'OptionalFeaturesList', 'SoftwareUpdateDeploymentPackage', 
        'SQLJobs', 'SQLDBWaits', 'SQLDBInfo', 'SQLDBGrowth', 'sitesummarytask', 'ManagementInsights', 'SiteFeature', 'ServerDown', 'ServerHTTPAccessInformation', 'AADTenant', 'AADApplication',
        'CloudManagementGateway'
    )

    $xmlList | ForEach-Object {
        $item = $_
        $File = "$($SaveToFolder)\$($item).xml"
        if (Test-Path -LiteralPath $File) {
            Write-RFLLog -logtype "INFO" -logmessage "Importing $($File)"
            New-Variable -Name "$item" -Value (Import-Clixml -Path "$($SaveToFolder)\$($item).xml") -Force -Option AllScope -Scope Script
        } else {
            Write-RFLLog -logtype "WARNING" -logmessage "File $($File) does not exist. Creating an empty variable"
            New-Variable -Name "$item" -Value @() -Force -Option AllScope -Scope Script
        }
    }
    $ManagedDeviceCount = ($DeviceList | Where-Object {$_.IsClient -eq $true}).Count
    #endregion

    #region HealthCheck
    try {
        #region Analysing ConfigMgr Data
        #region RuleID = 1
        $RuleID = 1
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled" 
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $script:ServerDown) {
                $script:ServerDown | Group-Object ConnectionType | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3217 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 2
        $RuleID = 2
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SiteList | ForEach-Object {
                $item = $_
                if ($item.BuildNumber -lt $Script:MinimumConfigMgrBuildVersion) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3025 @($item.SiteCode, $item.BuildNumber)) -Comment (Get-RFLHealthCheckRecommendation 5001)
                }
            }
        }
        #endregion

        #region RuleID = 3
        $RuleID = 3
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SiteList) {
                $SiteList | where-object {($_.BuildNumber -lt $Script:LatestConfigMgrBuildVersion)} | Group-Object Version | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3231 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5001 @($Script:LatestWhatsNew))
                }
            }
        }
        #endregion

        #region RuleID = 4
        $RuleID = 4
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SiteComponentManagerList)) {
                $tmpArr = @()
                $SiteList | ForEach-Object {
                    $item = $_

                    $SiteComponentManagerList | where-object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                        $Props = $_.Props
                        $Props | Where-Object {($_.PropertyName -eq 'Enforce Enhanced Hash Algorithm') -and ($_.Value -eq $false)} | ForEach-Object {
                            $tmpArr += $item
                        }
                    }
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3220 @($tmpArr.Count, 'Require SHA-256', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5089 'Require SHA-256')
                }
            }
        }
        #endregion

        #region RuleID = 5
        $RuleID = 5
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SiteComponentManagerList)) {
                $tmpArr = @()
                $SiteList | ForEach-Object {
                    $item = $_

                    $SiteComponentManagerList | where-object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                        $Props = $_.Props
                        $Props | Where-Object {($_.PropertyName -eq 'Enforce Message Signing') -and ($_.Value -eq $false)} | ForEach-Object {
                            $tmpArr += $item
                        }
                    }
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3220 @($tmpArr.Count, 'Require signing', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5089 'Require signing')
                }
            }
        }
        #endregion

        #region RuleID = 6
        $RuleID = 6
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SMSPolProvComponentList)) {
                $tmpArr = @()
                $SiteList | ForEach-Object {
                    $item = $_

                    $SiteComponentManagerList | where-object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                        $Props = $_.Props
                        $Props | Where-Object {($_.PropertyName -eq 'Use Encryption') -and ($_.Value -eq $false)} | ForEach-Object {
                            $tmpArr += $item
                        }
                    }
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3220 @($tmpArr.Count, 'Use Encryption', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5089 'Use Encryption')
                }
            }
        }
        #endregion

        #region RuleID = 7
        $RuleID = 7
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if (($null -ne $SiteList) -and ($null -ne $AlertList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $siteAlert = ($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode)} | Measure-Object).Count
                    if ($siteAlert -lt 1) {
                        $tmpArr += $item
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3190 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5090 'Alerts for database disk space')
            }
        }
        #endregion

        #region RuleID = 8
        $RuleID = 8
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if (($null -ne $SiteList) -and ($null -ne $AlertList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $siteAlert = ($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceWarningName')} | Measure-Object).Count
                    if ($siteAlert -ge 1) {
                        $dbAlertValue = [int]([xml]($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceWarningName')}).ParameterValues).Parameters.Parameter[3].'#text'

                        if ($dbAlertValue -gt $script:DatabaseFreeSpaceMaxWarningValueAlert) {
                            $tmpArr += $item
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3191 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:DatabaseFreeSpaceMaxWarningValueAlert)
            }
        }
        #endregion

        #region RuleID = 9
        $RuleID = 9
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if (($null -ne $SiteList) -and ($null -ne $AlertList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $siteAlert = ($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceWarningName')} | Measure-Object).Count
                    if ($siteAlert -ge 1) {
                        $dbAlertValue = [int]([xml]($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceWarningName')}).ParameterValues).Parameters.Parameter[3].'#text'

                        if ($dbAlertValue -lt $script:DatabaseFreeSpaceMinWarningValueAlert) {
                            $tmpArr += $item
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3192 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:DatabaseFreeSpaceMinWarningValueAlert)
            }
        }
        #endregion

        #region RuleID = 10
        $RuleID = 10
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if (($null -ne $SiteList) -and ($null -ne $AlertList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $siteAlert = ($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceCriticalName')} | Measure-Object).Count
                    if ($siteAlert -ge 1) {
                        $dbAlertValue = [int]([xml]($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceCriticalName')}).ParameterValues).Parameters.Parameter[2].'#text'
                        if ($dbAlertValue -gt $script:DatabaseFreeSpaceMaxCriticalValueAlert) {
                            $tmpArr += $item
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3193 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:DatabaseFreeSpaceMaxCriticalValueAlert)
            }
        }
        #endregion

        #region RuleID = 11
        $RuleID = 11
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if (($null -ne $SiteList) -and ($null -ne $AlertList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $siteAlert = ($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceCriticalName')} | Measure-Object).Count
                    if ($siteAlert -ge 1) {
                        $dbAlertValue = [int]([xml]($AlertList | Where-Object {($_.TypeId -in (24,25)) -and ($_.TypeInstanceID -eq $item.SiteCode) -and ($_.Name -eq '$DatabaseFreeSpaceCriticalName')}).ParameterValues).Parameters.Parameter[2].'#text'
                        if ($dbAlertValue -lt $script:DatabaseFreeSpaceMinCriticalValueAlert) {
                            $tmpArr += $item
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3194 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:DatabaseFreeSpaceMinCriticalValueAlert)
            }
        }
        #endregion

        #region RuleID = 12
        $RuleID = 12
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                $item = $_
                if ($item.Type -eq 2) { #primary site
                    $ListInstalled = $Script:RolesThatMustBeInstalledPrimary
                    $ListNotInstalled = $Script:RolesThatMustNotBeInstalledPrimary
                } elseif ($item.Type -eq 1) { #secondary site
                    $ListInstalled = $Script:RolesThatMustBeInstalledSecondary
                    $ListNotInstalled = $Script:RolesThatMustNotBeInstalledSecondary
                }

                $Script:ListInstalled | ForEach-Object {
                    $itemRoleName = $_
                    if (-not [string]::IsNullOrEmpty($_)) {
                        if ($null -eq ($SiteRoleList | Where-Object {($_.SiteCode -eq $item.SiteCode) -and ($_.RoleName -eq $itemRoleName)})) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3026 @($itemRoleName, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5002 $itemRoleName)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 13
        $RuleID = 13
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SiteList) {
                $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    $item = $_
                    if ($item.Type -eq 2) { #primary site
                        $ListInstalled = $Script:RolesThatMustBeInstalledPrimary
                        $ListNotInstalled = $Script:RolesThatMustNotBeInstalledPrimary
                    } elseif ($item.Type -eq 1) { #secondary site
                        $ListInstalled = $Script:RolesThatMustBeInstalledSecondary
                        $ListNotInstalled = $Script:RolesThatMustNotBeInstalledSecondary
                    }

                    $Script:ListNotInstalled | ForEach-Object {
                        $itemRoleName = $_
                        if (-not [string]::IsNullOrEmpty($_)) {
                            if ($null -ne ($SiteRoleList | Where-Object {($_.SiteCode -eq $item.SiteCode) -and ($_.RoleName -eq $itemRoleName)})) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3139 @($itemRoleName, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5024 $itemRoleName)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 14
        $RuleID = 14
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'MPList', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 15
        $RuleID = 15
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'MPCert', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 16
        $RuleID = 16
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'SiteSign Cert', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 17
        $RuleID = 17
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $MPList)) {
                $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    $item = $_
                    $MPListCount = ($MPList | Where-Object {$_.Sitecode -eq $item.SiteCode} | Measure-Object).Count
                    if ($MPListCount -gt $Script:MaximumNumberOfMPS) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3027 @($item.SiteCode, $MPList)) -Comment (Get-RFLHealthCheckRecommendation 5129 $Script:MaximumNumberOfMPS)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 18
        $RuleID = 18
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'Application Catalog Web Service', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 19
        $RuleID = 19
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'Application Catalog Web Site', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 20
        $RuleID = 20
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'SUP SimpleAuth', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 21
        $RuleID = 21
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'SUP Registration', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 22
        $RuleID = 22
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $AppCatalogWebServiceList) {
                $AppCatalogWebServiceList | ForEach-Object {
                    $item = $_

                    $AppWebServiceName = ($item.Props | Where-Object {$_.PropertyName -eq 'ServiceHostName'}).Value1
                    if ([string]::IsNullOrEmpty($AppWebServiceName)) { #siteserver itself
                        $AppWebServiceName = $item.NetworkOSPath.Replace('\\','')
                    }
                    $bFound = $false

                    $AppCatalogWebSiteList | ForEach-Object {
                        $subItem = $_
                        $ServiceName = ($subItem.Props | Where-Object {$_.PropertyName -eq 'ServiceHostName'}).Value1
                        if ($ServiceName.tolower() -eq $AppWebServiceName.tolower()) {
                            $bFound = $true
                        }
                    }

                    if (-not $bFound) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3090 $AppWebServiceName) -Comment (Get-RFLHealthCheckRecommendation 5051)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 23
        $RuleID = 23
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'SSRS Reports', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 24
        $RuleID = 24
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Script:ServerHTTPAccessInformation) {
                $Script:ServerHTTPAccessInformation | where-object {($_.StatusCode -ne 200) -and ($_.RuleInfo -eq $RuleID)} | Group-Object StatusCode | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3218 @($item.Count, 'SSRS ReportServer', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5050)
                }
            }
        }
        #endregion

        #region RuleID = 25
        $RuleID = 25
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SQLConfigurationList) {
                $SQLConfigurationList | where-object {$_.Version -lt $Script:MinimumSQLVersion} | ForEach-Object {
                    $item = $_
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3105 @($item.ServerName, $item.Version)) -Comment (Get-RFLHealthCheckRecommendation 5053 $Script:MinimumSQLVersion)
                }
            }
        }
        #endregion

        #region RuleID = 26
        $RuleID = 26
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SQLConfigurationList) {
                $SQLConfigurationList | where-object {$_.MinMemory -lt $Script:MinimumSQLMemory} | ForEach-Object {
                    $item = $_
                    $isServerDown = $null -ne ($Script:ServerDown | where-object {($_.ServerName -eq $item.ServerName) -and ($_.ConnectionType -eq 'SQL Server (DM_OS_SYS_INFO) (SQL TCP)')})

                    if ($isServerDown -eq $false) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3024 @($item.ServerName, 'minimum', $item.MinMemory)) -Comment (Get-RFLHealthCheckRecommendation 5054 @('minimum memory', $Script:MinimumSQLMemory))
                    }
                }
            }
        }
        #endregion

        #region RuleID = 27
        $RuleID = 27
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SQLConfigurationList) {
                $SQLConfigurationList | where-object {$_.MaxMemory -lt $Script:MinimumSQLMemory} | ForEach-Object {
                    $item = $_
                    $isServerDown = $null -ne ($Script:ServerDown | where-object {($_.ServerName -eq $item.ServerName) -and ($_.ConnectionType -eq 'SQL Server (DM_OS_SYS_INFO) (SQL TCP)')})

                    if ($isServerDown -eq $false) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3024 @($item.ServerName, 'maximum', $item.MaxMemory)) -Comment (Get-RFLHealthCheckRecommendation 5054 @('maximum memory', $Script:MinimumSQLMemory))
                    }
                }
            }
        }
        #endregion

        #region RuleID = 28
        $RuleID = 28
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SQLConfigurationList) {
                $SQLConfigurationList | ForEach-Object {
                    $item = $_

                    $sqlVersion = $item.Version.Split('.')[0]
                    if ($sqlVersion -ge 13) { #sql 2016+
                        if ($item.CompLevel -lt 130) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3129 @($item.ServerName, $item.Database, $item.CompLevel)) -Comment (Get-RFLHealthCheckRecommendation 5055)
                        }
                    } elseif ($sqlVersion -ge 11) { #sql 2012+
                        if ($item.CompLevel -lt 110) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3129 @($item.ServerName, $item.Database, $item.CompLevel)) -Comment (Get-RFLHealthCheckRecommendation 5055)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 29
        $RuleID = 29
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SQLServerInformationList | Where-Object {(![string]::IsNullOrEmpty($_.InstallationFolder)) -and ((![string]::IsNullOrEmpty($_.ProgramFiles))) -and (($_.InstallationFolder.Substring(0,2) -eq $_.ProgramFiles.Substring(0,2)))} | ForEach-Object {
                $item = $_
                #need to report the instance ID information
                if ($item.InstallationFolder.Substring(0,2) -eq $item.ProgramFiles.Substring(0,2)) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3127 @($item.ServerName, 'Installation folder', 'Program Files folder')) -Comment (Get-RFLHealthCheckRecommendation 5083)
                }
            }
        }
        #endregion

        #region RuleID = 30
        $RuleID = 30
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLServerInformationList | Where-Object {(![string]::IsNullOrEmpty($_.DataFolder)) -and ((![string]::IsNullOrEmpty($_.ProgramFiles))) -and (($_.DataFolder.Substring(0,2) -eq $_.ProgramFiles.Substring(0,2)))} | ForEach-Object {
                $item = $_
                if ($item.DataFolder.Substring(0,2) -eq $item.ProgramFiles.Substring(0,2)) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3127 @($item.ServerName, 'SQL Data folder', 'Program Files folder')) -Comment (Get-RFLHealthCheckRecommendation 5083)
                }
            }
        }
        #endregion

        #region RuleID = 31
        $RuleID = 31
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLServerInformationList | Where-Object {(![string]::IsNullOrEmpty($_.LogFolder)) -and ((![string]::IsNullOrEmpty($_.ProgramFiles))) -and (($_.LogFolder.Substring(0,2) -eq $_.ProgramFiles.Substring(0,2)))} | ForEach-Object {
                $item = $_
                if ($item.LogFolder.Substring(0,2) -eq $item.ProgramFiles.Substring(0,2)) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3127 @($item.ServerName, 'SQL Logs folder', 'Program Files folder')) -Comment (Get-RFLHealthCheckRecommendation 5083)
                }
            }
        }
        #endregion

        #region RuleID = 32
        $RuleID = 32
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLServerInformationList | Where-Object {(![string]::IsNullOrEmpty($_.DataFolder)) -and ((![string]::IsNullOrEmpty($_.InstallationFolder))) -and (($_.DataFolder.Substring(0,2) -eq $_.InstallationFolder.Substring(0,2)))} | ForEach-Object {
                $item = $_
                if ($item.DataFolder.Substring(0,2) -eq $item.InstallationFolder.Substring(0,2)) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3127 @($item.ServerName, 'SQL Data folder', 'SQL Binaries Folder')) -Comment (Get-RFLHealthCheckRecommendation 5083)
                }
            }
        }
        #endregion

        #region RuleID = 33
        $RuleID = 33
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLServerInformationList | Where-Object {(![string]::IsNullOrEmpty($_.LogFolder)) -and ((![string]::IsNullOrEmpty($_.InstallationFolder))) -and (($_.LogFolder.Substring(0,2) -eq $_.InstallationFolder.Substring(0,2)))} | ForEach-Object {
                $item = $_
                if ($item.LogFolder.Substring(0,2) -eq $item.InstallationFolder.Substring(0,2)) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3127 @($item.ServerName, 'SQL Logs folder', 'SQL Binaries Folder')) -Comment (Get-RFLHealthCheckRecommendation 5083)
                }
            }
        }
        #endregion

        #region RuleID = 34
        $RuleID = 34
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $SQLServerInformationList | Where-Object {(![string]::IsNullOrEmpty($_.LogFolder)) -and ((![string]::IsNullOrEmpty($_.DataFolder))) -and (($_.LogFolder.Substring(0,2) -eq $_.DataFolder.Substring(0,2)))} | ForEach-Object {
                $item = $_
                if ($item.LogFolder.Substring(0,2) -eq $item.DataFolder.Substring(0,2)) {
                    $tmpArr += $item
                }
            }

            if ($tmpArr.Count -gt 0) {
                $count = ($tmpArr | select-Object ServerName -unique | Measure-Object).Count
                $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3241 @($count, 'SQL Logs folder', 'SQL Data Folder', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5083)
            }
        }
        #endregion

        #region RuleID = 35
        $RuleID = 35
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ServiceAccountList | Where-Object {!$_.AccountUsage} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object UserName -unique) | Foreach {"'$($_.UserName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3172 @($item.Count, 'service account(s)', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5005)
            }
        }
        #endregion

        #region RuleID = 36
        $RuleID = 36
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($null -eq ($ServiceAccountList | Where-Object {$_.AccountUsage -icontains "Software Distribution"})) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3029) -Comment (Get-RFLHealthCheckRecommendation 5006)
            }
        }
        #endregion

        #region RuleID = 37
        $RuleID = 37
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ServiceAccountList | Where-Object {($AdminAccountList | select -ExpandProperty LogonName) -contains $_.Username} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object UserName -unique) | Foreach {"'$($_.UserName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3173 @($item.Count, 'service account(s)', $item.Name, 'administrative user', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5007)
            }
        }
        #endregion

        #region RuleID = 38
        $RuleID = 38
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.CleanUpInterval -gt $script:MaxClientStatusSettingsCleanUpInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Client Status, Retain client status history Interval', $ClientStatusSettings.CleanUpInterval)) -Comment (Get-RFLHealthCheckRecommendation 5091 $script:MaxClientStatusSettingsCleanUpInterval)
            }
        }
        #endregion

        #region RuleID = 39
        $RuleID = 39
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.CleanUpInterval -lt $script:MinClientStatusSettingsCleanUpInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Client Status, Retain client status history Interval', $ClientStatusSettings.CleanUpInterval)) -Comment (Get-RFLHealthCheckRecommendation 5092 $script:MinClientStatusSettingsCleanUpInterval)
            }
        }
        #endregion

        #region RuleID = 40
        $RuleID = 40
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.DDRInactiveInterval -gt $script:MaxClientStatusSettingsDDRInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Client Status, Heartbeat discovery interval', $ClientStatusSettings.DDRInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5091 $script:MaxClientStatusSettingsDDRInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 41
        $RuleID = 41
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($ClientStatusSettings.DDRInactiveInterval -lt $script:MinClientStatusSettingsDDRInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Client Status, Heartbeat discovery interval', $ClientStatusSettings.DDRInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5092 $script:MinClientStatusSettingsDDRInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 42
        $RuleID = 42
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.HWInactiveInterval -gt $script:MaxClientStatusSettingsHWInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Client Status, Hardware inventory interval', $ClientStatusSettings.HWInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5091 $script:MaxClientStatusSettingsHWInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 43
        $RuleID = 43
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.HWInactiveInterval -lt $script:MinClientStatusSettingsHWInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Client Status, Hardware inventory interval', $ClientStatusSettings.HWInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5092 $script:MinClientStatusSettingsHWInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 44
        $RuleID = 44
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.PolicyInactiveInterval -gt $script:MaxClientStatusSettingsPolicyInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Client Status, Client Policy request interval', $ClientStatusSettings.PolicyInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5091 $script:MaxClientStatusSettingsPolicyInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 45
        $RuleID = 45
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.PolicyInactiveInterval -lt $script:MinClientStatusSettingsPolicyInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Client Status, Client Policy request interval', $ClientStatusSettings.PolicyInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5092 $script:MinClientStatusSettingsPolicyInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 46
        $RuleID = 46
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.StatusInactiveInterval -gt $script:MaxClientStatusSettingsStatusInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Client Status, Status messages interval', $ClientStatusSettings.StatusInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5091 $script:MaxClientStatusSettingsStatusInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 47
        $RuleID = 47
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($ClientStatusSettings.StatusInactiveInterval -lt $script:MinClientStatusSettingsStatusInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Client Status, Status messages interval', $ClientStatusSettings.StatusInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5092 $script:MinClientStatusSettingsStatusInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 48
        $RuleID = 48
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.SWInactiveInterval -gt $script:MaxClientStatusSettingsSWInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Client Status, Software inventory interval', $ClientStatusSettings.StatusInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5091 $script:MaxClientStatusSettingsSWInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 49
        $RuleID = 49
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($ClientStatusSettings.SWInactiveInterval -lt $script:MinClientStatusSettingsSWInactiveInterval) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Client Status, Software inventory interval', $ClientStatusSettings.StatusInactiveInterval)) -Comment (Get-RFLHealthCheckRecommendation 5092 $script:MinClientStatusSettingsSWInactiveInterval)
            }
        }
        #endregion

        #region RuleID = 50
        $RuleID = 50
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ItemName -eq 'Client Properties')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'DDR Refresh Interval'}).Value2)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Heartbeat DDR'}).Value) -ne 1) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Heartbeat Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Heartbeat Discovery')
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 51
        $RuleID = 51
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ItemName -eq 'Client Properties')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'DDR Refresh Interval'}).Value2)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Heartbeat DDR'}).Value) -eq 1) {
                            if ($scheduleToMinutes -lt $Script:DDRMinScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Heartbeat Discovery schedule', $scheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:DDRMinScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 52
        $RuleID = 52
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_FOREST_DISCOVERY_MANAGER')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Startup Schedule'}).Value1)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -ne 'ACTIVE') {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Forest Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Forest Discovery')
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 53
        $RuleID = 53
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_FOREST_DISCOVERY_MANAGER')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Startup Schedule'}).Value1)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($scheduleToMinutes -lt $Script:ForestDiscoveryMinScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Forest Discovery schedule', $scheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:ForestDiscoveryMinScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 54
        $RuleID = 54
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_FOREST_DISCOVERY_MANAGER')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Startup Schedule'}).Value1)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {

                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable AD Site Boundary Creation'}).Value) -ne 1) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Forest Discovery AD Site Boundary Creation', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Forest Discovery AD Site Boundary Creation')
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 55
        $RuleID = 55
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_FOREST_DISCOVERY_MANAGER')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Startup Schedule'}).Value1)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Subnet Boundary Creation'}).Value) -ne 1) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Forest Discovery Subnet Boundary Creation', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Forest Discovery Subnet Boundary Creation')
                            }
                        }
                    }
                }
            }
        }
       #endregion

        #region RuleID = 56
        $RuleID = 56
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_NETWORK_DISCOVERY')})) {

                    if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Discovery Enabled'}).Value1) -eq $true) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3003 @('Network Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5011 'Network Discovery')
                    }
                }
            }
        }
        #endregion

        #region RuleID = 57
        $RuleID = 57
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -ne 'ACTIVE') {
                           Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Active Directory Group Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Active Directory Group Discovery')
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 58
        $RuleID = 58
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($FullscheduleToMinutes -gt $script:SecurityGroupDiscoveryMaxScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('Active Directory Group Discovery full schedule', $FullscheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:SecurityGroupDiscoveryMaxScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 59
        $RuleID = 59
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($FullscheduleToMinutes -lt $script:SecurityGroupDiscoveryMinScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Active Directory Group Discovery full schedule', $FullscheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:SecurityGroupDiscoveryMinScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 60
        $RuleID = 60
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Logon'}).Value) -ne 1) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Active Directory Group Discovery Filtering (Expired Logon)', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5088 'Active Directory Group Security Filtering (Expired Logon)')
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 61
        $RuleID = 61
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Logon'}).Value) -eq 1) {
                                $DaysSinceLastLogon = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Logon'}).Value

                                if ($DaysSinceLastLogon -gt $script:SecurityGroupDiscoveryMaxExpiredLogon) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('Active Directory Group Security Filtering (Expired Logon) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:SecurityGroupDiscoveryMaxExpiredLogon)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 62
        $RuleID = 62
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Logon'}).Value) -eq 1) {
                                $DaysSinceLastLogon = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Logon'}).Value

                                if ($DaysSinceLastLogon -lt $script:SecurityGroupDiscoveryMinExpiredLogon) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Active Directory Group Security Filtering (Expired Logon) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:SecurityGroupDiscoveryMinExpiredLogon)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 63
        $RuleID = 63
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Password'}).Value) -ne 1) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Active Directory Group Security Filtering (Expired Password)', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5088 'Security Group Filtering (Expired Password)')
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 64
        $RuleID = 64
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Password'}).Value) -eq 1) {
                                $DaysSinceLastPassword = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Password Set'}).Value

                                if ($DaysSinceLastPassword -gt $script:SecurityGroupDiscoveryMaxPasswordSet) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('Active Directory Group Security Filtering (Expired Password) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:SecurityGroupDiscoveryMaxPasswordSet)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 65
        $RuleID = 65
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Password'}).Value) -eq 1) {
                                $DaysSinceLastPassword = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Password Set'}).Value

                                if ($DaysSinceLastPassword -lt $script:SecurityGroupDiscoveryMinPasswordSet) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Active Directory Group Security Filtering (Expired Password) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:SecurityGroupDiscoveryMinPasswordSet)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 66
        $RuleID = 66
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if (($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values.Count -eq 0) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3031 @('Active Directory Group Security Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5012)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 67
        $RuleID = 67
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if (($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values.Count -ne 0) {

                                foreach ($itemContainer in ($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -like 'Search Bases:*'}).Values) {
                                    if ($itemContainer -match $Script:RegExLDAPDiscovery) {
                                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3004 @('Active Directory Group Security Discovery', $itemContainer, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5013)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 68
        $RuleID = 68
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -ne 'ACTIVE') {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Active Directory System Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Active Directory System Discovery')
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 69
        $RuleID = 69
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($FullscheduleToMinutes -gt $script:SystemDiscoveryMaxScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('System Discovery schedule', $FullscheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:SystemDiscoveryMaxScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 70
        $RuleID = 70
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($FullscheduleToMinutes -lt $script:SystemDiscoveryMinScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('System Discovery schedule', $FullscheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:SystemDiscoveryMinScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 71
        $RuleID = 71
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Logon'}).Value) -ne 1) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Active Directory System Discovery Filtering (Expired Logon)', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5088 'Active Directory System Discovery Filtering')
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 72
        $RuleID = 72
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Logon'}).Value) -eq 1) {
                                $DaysSinceLastLogon = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Logon'}).Value

                                if ($DaysSinceLastLogon -gt $script:SystemDiscoveryMaxExpiredLogon) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('Active Directory System Discovery Filtering (Expired Logon) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:SystemDiscoveryMaxExpiredLogon)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 73
        $RuleID = 73
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Logon'}).Value) -eq 1) {
                                $DaysSinceLastLogon = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Logon'}).Value
                                if ($DaysSinceLastLogon -lt $script:SystemDiscoveryMinExpiredLogon) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Active Directory System Discovery Filtering (Expired Logon) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:SystemDiscoveryMinExpiredLogon)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 74
        $RuleID = 74
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Password'}).Value) -ne 1) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('System  Filtering (Expired Password)', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5088 'System  Filtering (Expired Password)')
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 75
        $RuleID = 75
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Password'}).Value) -eq 1) {
                                $DaysSinceLastPasswordSet = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Password Set'}).Value

                                if ($DaysSinceLastPasswordSet -gt $script:SystemDiscoveryMaxPasswordSet) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('Active Directory System Discovery Filtering (Expired Password) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:SystemDiscoveryMaxPasswordSet)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 76
        $RuleID = 76
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Filtering Expired Password'}).Value) -eq 1) {
                                $DaysSinceLastPasswordSet = ($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Days Since Last Password Set'}).Value
                                if ($DaysSinceLastPasswordSet -lt $script:SystemDiscoveryMinPasswordSet) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Active Directory System Discovery Filtering (Expired Password) is enabled with filtering', $DaysSinceLastLogon, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:SystemDiscoveryMinPasswordSet)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 77
        $RuleID = 77
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if (($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values.Count -eq 0) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3031 @('System Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5012)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 78
        $RuleID = 78
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_SYSTEM_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if (($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values.Count -ne 0) {
                                foreach ($itemContainer in ($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values) {
                                    if ($itemContainer -match $Script:RegExLDAPDiscovery) {
                                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3004 @('System Discovery', $itemContainer, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5013)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 79
        $RuleID = 79
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_USER_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -ne 'ACTIVE') {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Active Directory User Discovery', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Active Directory User Discovery')
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 80
        $RuleID = 80
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_USER_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($FullscheduleToMinutes -gt $script:UserMaxScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('User Discovery delta schedule', $FullscheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:UserMaxScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 81
        $RuleID = 81
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_USER_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($FullscheduleToMinutes -lt $script:UserMinScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('User Discovery - full discovery pooling schedule', $FullscheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:UserMinScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 82
        $RuleID = 82
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_USER_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if (($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values.Count -eq 0) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3031 @('User Discovery schedule', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5012)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 83
        $RuleID = 83
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_USER_DISCOVERY_AGENT')})) {
                    $FullSchedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Full Sync Schedule'}).Value1)"
                    if ($null -ne $FullSchedule) {
                        $FullscheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $FullSchedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if (($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values.Count -ne 0) {
                                foreach ($itemContainer in ($itemDiscovery.PropLists | Where-Object {$_.PropertyListName -eq 'AD Containers'}).Values) {
                                    if ($itemContainer -match $Script:RegExLDAPDiscovery) {
                                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3004 @('User Discovery', $itemContainer, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5013)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 84
        $RuleID = 84
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $DPGroupList) -and ($DPGroupList.Count -gt 0)) {
                $DPGroupList | where-object {$_.HasMember -eq $false}| Group-Object SourceSite | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '

                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3174 @($item.Count, 'Distribution Point Group', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5014)
                }
            }
        }
        #endregion

        #region RuleID = 85
        $RuleID = 85
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $DPGroupList) -and ($DPGroupList.Count -gt 0)) {
                $DPGroupList | where-object {$_.ContentInSync -eq $false}| Group-Object SourceSite | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3175 @($item.Count, 'Distribution Point Group', $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5015)
                }
            }
        }
        #endregion

        #region RuleID = 86
        $RuleID = 86
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($CollectionMembershipEvaluation | Select-Object SiteCode | get-unique -AsString)) {
                $itemComp = $CollectionMembershipEvaluation | Where-Object {$_.SiteCode -eq $item.SiteCode}
                $incrementalValue = ($itemComp.Props | Where-Object {$_.PropertyName -eq 'Incremental Interval'}).Value

                if ($incrementalValue -gt $script:MaxCollectionMembershipEvaluation) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3111 @('Collection Membership Evaluation', $incrementalValue, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5086 $script:MaxCollectionMembershipEvaluation)
                }
            }
        }
        #endregion

        #region RuleID = 87
        $RuleID = 87
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($CollectionMembershipEvaluation | Select-Object SiteCode | get-unique -AsString)) {
                $itemComp = $CollectionMembershipEvaluation | Where-Object {$_.SiteCode -eq $item.SiteCode}
                $incrementalValue = ($itemComp.Props | Where-Object {$_.PropertyName -eq 'Incremental Interval'}).Value

                if ($incrementalValue -lt $script:MinCollectionMembershipEvaluation) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Collection Membership Evaluation', $incrementalValue, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5087 $script:MinCollectionMembershipEvaluation)
                }
            }
        }
        #endregion

        #region RuleID = 88
        $RuleID = 88
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $CollectionFilterCount = ($DeviceCollectionList | Where-Object {$null -eq $_.CollectionRules} | Measure-Object).Count
            if ($CollectionFilterCount -gt 0) {
                $CollectionNameList = Get-RFLCollectionNames -CollectionList ($DeviceCollectionList | Where-Object {$null -eq $_.CollectionRules})
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3007 @($CollectionFilterCount, 'device', 'Collection Membership Rules', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5016 'Rule')
            }
        }
        #endregion

        #region RuleID = 89
        $RuleID = 89
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $CollectionFilterCount = ($DeviceCollectionList | Where-Object {($_.MemberCount -eq 0) -and ($_.Name -ne 'All Mobile Devices')} | Measure-Object).Count
            if ($CollectionFilterCount -gt 0) {
                $CollectionNameList = Get-RFLCollectionNames -CollectionList ($DeviceCollectionList | Where-Object {($_.MemberCount -eq 0) -and ($_.Name -ne 'All Mobile Devices')})
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3007 @($CollectionFilterCount, 'device', 'member', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5016 'member')
            }
        }
        #endregion

        #region RuleID = 90
        $RuleID = 90
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpDeviceCollectionList = $DeviceCollectionList | Where-Object {($_.LimitToCollectionName -eq 'All Systems') -and ($_.Name -notin $Script:LimitedCollectionToIgnore)} 
            $CollectionFilterCount = ($tmpDeviceCollectionList | Measure-Object).Count
            if ($CollectionFilterCount -gt $Script:MaxLimitCollection) {
                $CollectionNameList = Get-RFLCollectionNames -CollectionList ($tmpDeviceCollectionList)
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3008 @($CollectionFilterCount, 'All Systems', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5017 @($Script:MaxLimitCollection, 'All Systems'))
            }
        }
        #endregion

        #region RuleID = 91
        $RuleID = 91
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $CollectionFilterCount = ($DeviceCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            if (($CollectionFilterCount -gt $script:MaxCollectionIncrementalUpdateWarning) -and ($CollectionFilterCount -lt $script:MaxCollectionIncrementalUpdateError)) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3032 @($CollectionFilterCount, 'device')) -Comment (Get-RFLHealthCheckRecommendation 5018 $script:MaxCollectionIncrementalUpdateError)
            }
        }
        #endregion

        #region RuleID = 92
        $RuleID = 92
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $CollectionFilterCount = ($DeviceCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            if ($CollectionFilterCount -gt $script:MaxCollectionIncrementalUpdateError) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3032 @($CollectionFilterCount, 'device')) -Comment (Get-RFLHealthCheckRecommendation 5018 $script:MaxCollectionIncrementalUpdateError)
            }
        }
        #endregion

        #region RuleID = 93
        $RuleID = 93
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($CollectionDeviceFilterCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionDeviceFilterCount)
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionDeviceFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3033 $CollectionDeviceFilterCount, 'device') -Comment (Get-RFLHealthCheckRecommendation 5019 $script:MaxCollectionMembershipDirectRule)
            }
        }
        #endregion

        #region RuleID = 94
        $RuleID = 94
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $CollectionFilterCount = ($UserCollectionList | Where-Object {$null -eq $_.CollectionRules} | Measure-Object).Count
            if ($CollectionFilterCount -gt 0) {
                $CollectionNameList = Get-RFLCollectionNames -CollectionList ($UserCollectionList | Where-Object {$null -eq $_.CollectionRules})
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3007 @($CollectionFilterCount, 'user', 'Collection Membership Rules', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5016 'Rule')
            }
        }
        #endregion

        #region RuleID = 95
        $RuleID = 95
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $CollectionFilterCount = ($UserCollectionList | Where-Object {($_.MemberCount -eq 0) -and ($_.Name -ne 'All User Groups')} | Measure-Object).Count
            if ($CollectionFilterCount -gt 0) {
                $CollectionNameList = Get-RFLCollectionNames -CollectionList ($UserCollectionList | Where-Object {($_.MemberCount -eq 0) -and ($_.Name -ne 'All User Groups')})
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3007 @($CollectionFilterCount, 'user', 'member', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5016 'member')
            }
        }
        #endregion

        #region RuleID = 96
        $RuleID = 96
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $CollectionFilterCount = ($UserCollectionList | Where-Object {$_.LimitToCollectionName -eq 'All Users and User Groups'} | Measure-Object).Count
            if ($CollectionFilterCount -gt 2) {
                $CollectionNameList = Get-RFLCollectionNames -CollectionList ($UserCollectionList | Where-Object {$_.LimitToCollectionName -eq 'All Users and User Groups'})
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3008 @($CollectionFilterCount, 'All Users and User Groups', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5017 @(2, 'All Users and Groups'))
            }

            @('All Users', 'All User Groups') | ForEach-Object {
                $item = $_
                $CollectionFilterCount = ($UserCollectionList | Where-Object {$_.LimitToCollectionName -eq $item} | Measure-Object).Count
                if ($CollectionFilterCount -gt 1) {
                    $CollectionNameList = Get-RFLCollectionNames -CollectionList ($UserCollectionList | Where-Object {$_.LimitToCollectionName -eq $item})
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3008 @($CollectionFilterCount, $item, $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5017 @(1, $item))
                }
            }
        }
        #endregion

        #region RuleID = 97
        $RuleID = 97
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $CollectionFilterCount = ($UserCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            if (($CollectionFilterCount -gt $script:MaxCollectionIncrementalUpdateWarning) -and ($CollectionFilterCount -lt $script:MaxCollectionIncrementalUpdateError)) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3032 @($CollectionFilterCount, 'user')) -Comment (Get-RFLHealthCheckRecommendation 5018 $script:MaxCollectionIncrementalUpdateError)
            }
        }
        #endregion

        #region RuleID = 98
        $RuleID = 98
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $CollectionFilterCount = ($UserCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            if ($CollectionFilterCount -gt $script:MaxCollectionIncrementalUpdateError) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3032 @($CollectionFilterCount, 'user')) -Comment (Get-RFLHealthCheckRecommendation 5018 $script:MaxCollectionIncrementalUpdateError)
            }
        }
        #endregion

        #region RuleID = 99
        $RuleID = 99
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($CollectionUserFilterCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($CollectionUserFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3033 $CollectionUserFilterCount, 'user') -Comment (Get-RFLHealthCheckRecommendation 5019 $script:MaxCollectionMembershipDirectRule)
            }
        }
        #endregion

        #region RuleID = 100
        $RuleID = 100
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpCollectionFilter = @()
            [int]$depCount = 0
            $DeviceCollectionList | Where-Object {$_.MemberCount -eq 0} | ForEach-Object {
                $itemCol = $_; 
                $tmpDeploymentCount = ($DeploymentList | Where-Object {$_.CollectionName -eq $itemCol.Name} | Measure-Object).Count
                
                if (($DeploymentList | Where-Object {$_.CollectionName -eq $itemCol.Name} | Measure-Object).Count -gt 0) { 
                    $tmpCollectionFilter += $itemCol 
                    $depCount += $tmpDeploymentCount
                }
            }

            $deploymentfiltercount = ($tmpCollectionFilter | Measure-Object).Count
            if ($deploymentfiltercount -gt 0) {
                $CollectionNameList = Get-RFLCollectionNames -CollectionList ($tmpCollectionFilter)
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deploymentfiltercount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3034 @($depCount, 'device', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5020)
            }
        }
        #endregion

        #region RuleID = 101
        $RuleID = 101
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            @('All Systems', 'All Users', 'All User Groups', 'All Users and User Groups') | ForEach-Object {
                $itemCol = $_

                $DeploymentList | Where-Object {$_.CollectionName -eq 'All Users'} | Group-Object FeatureType | ForEach-Object {
                    $item = $_
                    switch ([int]$item.Name) {
                        1 { $itemType = 'Application' }
                        2 { $itemType = 'Program' }
                        3 { $itemType = 'Mobile Program' }
                        4 { $itemType = 'Script' }
                        5 { $itemType = 'Software Update' }
                        6 { $itemType = 'Configuration Baseline' }
                        7 { $itemType = 'Task Sequence' }
                        8 { $itemType = 'Content Distribution' }
                        9 { $itemType = 'Distribution Point Group' }
                        10 { $itemType = 'Distribution Point Health' }
                        11 { $itemType = 'Configuration Policy' }
                        default { $itemType = "$($_.FeatureType) unknown"}
                    }
                    $strArray = (($item.Group | select-Object SoftwareName -unique) | Foreach {"'$($_.SoftwareName.Trim())'"}) -join ' '

                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3176 @($item.Count, $itemType, $itemCol, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5015)
                }
            }
        }
        #endregion

        #region RuleID = 102
        $RuleID = 102
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpAlertList = $AlertList | Where-Object {($_.AlertState -eq 0) -and ($_.SkipUntil -lt (Get-Date))}

            $AlertListCount = ($tmpAlertList | Measure-Object).Count
            if ($AlertListCount -gt 0) {
                $strArray = (($tmpAlertList | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($AlertListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3036 $AlertListCount, $strArray) -Comment (Get-RFLHealthCheckRecommendation 5025)
            }
        }
        #endregion

        #region RuleID = 103 - Alert Subscription Information
        $RuleID = 103
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($AlertSubscriptionList | Measure-Object).Count -eq 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3073) -Comment (Get-RFLHealthCheckRecommendation 5049)
            }
        }
        #endregion

        #region RuleID = 104
        $RuleID = 104
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ReportAlerts = @()
            $ReportAlerts += $AlertList | Where-Object {$_.NumberOfSubscription -eq 0}
            if ($ReportAlerts) {
                $strArray = (($ReportAlerts | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($ReportAlerts.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3177 @($ReportAlerts.Count, 'alerts', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5049)
            }
        }
        #endregion

        #region RuleID = 105
        $RuleID = 105
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $false) -and ($_.Name -notlike '*Unknown*') -and ($_.Name -notlike '*Provisioning Device*')} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3010 $deviceListCount) -Comment (Get-RFLHealthCheckRecommendation 5026)
            }
        }
        #endregion

        #region RuleID = 106
        $RuleID = 106
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.ClientActiveStatus -eq $false)} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3039 @($deviceListCount ,'inactive')) -Comment (Get-RFLHealthCheckRecommendation 5097 'inactive')
            }
        }
        #endregion

        #region RuleID = 107
        $RuleID = 107
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.IsBLocked -eq $true)} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3039 @($deviceListCount, 'blocked')) -Comment (Get-RFLHealthCheckRecommendation 5027 'blocked')
            }
        }
        #endregion

        #region RuleID = 108
        $RuleID = 108
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.IsApproved -eq 0)} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3039 @($deviceListCount, 'not approved')) -Comment (Get-RFLHealthCheckRecommendation 5027 'not approved')
            }
        }
        #endregion

        #region RuleID = 109
        $RuleID = 109
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.IsObsolete -eq $true} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3039 @($deviceListCount, 'obsolete')) -Comment (Get-RFLHealthCheckRecommendation 5027 'obsolete')
            }
        }
        #endregion

        #region RuleID = 110
        $RuleID = 110
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Workstation*5.1'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows XP')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows XP')
            }
        }
        #endregion

        #region RuleID = 111
        $RuleID = 111
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Workstation*5.2'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows XP x64')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows XP x64')
            }
        }
        #endregion

        #region RuleID = 112
        $RuleID = 112
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Workstation*6.0'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows Vista')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows Vista')
            }
        }
        #endregion

        #region RuleID = 113
        $RuleID = 113
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Workstation*6.1'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows 7')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows 7')
            }
        }
        #endregion

        #region RuleID = 114
        $RuleID = 114
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Server*5.2'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows Server 2003')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows Server 2003')
            }
        }
        #endregion

        #region RuleID = 115
        $RuleID = 115
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Server*6.0'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows Server 2008')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows Server 2008')
            }
        }
        #endregion

        #region RuleID = 116
        $RuleID = 116
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Server*6.1'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows Server 2008 R2')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows Server 2008 R2')
            }
        }
        #endregion

        #region RuleID = 117
        $RuleID = 117
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Server*6.2'} | Measure-Object).Count
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'Windows Server 2012')) -Comment (Get-RFLHealthCheckRecommendation 5023 'Windows Server 2012')
            }
        }
        #endregion

        #region RuleID = 118
        $RuleID = 118
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $SiteList) {
                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.SiteCode -eq $item.SiteCode) -and ($_.ClientVersion -lt $item.Version)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3041 @($deviceListCount, $item.SiteCode, $item.Version)) -Comment (Get-RFLHealthCheckRecommendation 5099)
                }
            }
        }
        #endregion

        #region Endpoint Protection
        if ($null -ne $EndpointProtectionList) {
            #region RuleID = 119
            $RuleID = 119
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 1)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection', 'Unmanaged')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 120
            $RuleID = 120
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 2)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection', 'To Be Installed')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 121
            $RuleID = 121
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 4)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection', 'Install With Error')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 122
            $RuleID = 122
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 5)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection', 'Reboot Pending')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 123
            $RuleID = 123
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPInfectionStatus -eq 4)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Infection Status', 'Failed')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 124
            $RuleID = 124
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPInfectionStatus -eq 3)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Infection Status', 'Pending')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 125
            $RuleID = 125
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPInfectionStatus -eq 0)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Infection Status', 'Unknown')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 126
            $RuleID = 126
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPPolicyApplicationState -eq 2)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Policy Status', 'Failed')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 127
            $RuleID = 127
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 1)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'Service not Service started without any malware protection engine')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 128
            $RuleID = 128
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 2)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'Pending a full scan due to threat action')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 129
            $RuleID = 129
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 4)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'Pending a reboot due to threat action')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 130
            $RuleID = 130
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 8)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'Pending manual steps due to threat action')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 131
            $RuleID = 131
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 16)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'AV signatures out of date')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 132
            $RuleID = 132
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 32)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'AS signatures out of date')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 133
            $RuleID = 133
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 64)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'No quick scan has happened for a specified period')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 134
            $RuleID = 134
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 128)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'No full scan has happened for a specified period')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 135
            $RuleID = 135
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 512)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'System initiated clean in progress')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 136
            $RuleID = 136
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 4096)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'Product running in non-genuine Windows mode')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 137
            $RuleID = 137
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 8192)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'Product expired')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion

            #region RuleID = 138
            $RuleID = 138
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.EPDeploymentState -eq 3) -and ($_.EPProductStatus -eq 16384)} | Measure-Object).Count
                if ($deviceListCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3042 @($deviceListCount, 'Endpoint Protection Product Status', 'Off-line scan required')) -Comment (Get-RFLHealthCheckRecommendation 5100)
                }
            }
            #endregion
        }
        #endregion

        #region RuleID = 139 - Client Settings Analysis
        $RuleID = 139
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsList | where-object {($_.Name -ne 'Default Client Agent Settings') -and ($_.AssignmentCount -eq 0)} | Group-Object AssignmentCount | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3265 @($item.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5161)
            }
        }
        #endregion

        #region RuleID = 140
        $RuleID = 140
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ComputerAgent') -and ($_.Key -eq 'UseNewSoftwareCenter') -and ($_.Value -eq $false)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ComputerAgent', 'UseNewSoftwareCenter', 'disabled',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5023 'Old Software Center')
            }
        }
        #endregion

        #region RuleID = 141
        $RuleID = 141
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in $ClientSettingsList) {
                $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'ClientCache') -and ($_.Key -eq 'ConfigureCacheSize') -and ($_.Value -eq $true)}
                if ($null -ne $SettingInfo) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'ClientCache') -and ($_.Key -eq 'MaxCacheSizeMB') -and ($_.Value -lt $script:MinCacheSize)}
                    if ($null -ne $SettingInfo) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3009 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Max Cache Size', $SettingInfo.Value)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinCacheSize)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 142
        $RuleID = 142
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ClientPolicy') -and ($_.Key -eq 'PolicyRequestAssignmentTimeout') -and ($_.Value -gt $script:MaxPolicyRequestAssignmentTimeout)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ClientPolicy', 'PolicyRequestAssignmentTimeout', 'high',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxPolicyRequestAssignmentTimeout)
            }
        }
        #endregion

        #region RuleID = 143
        $RuleID = 143
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ClientPolicy') -and ($_.Key -eq 'PolicyRequestAssignmentTimeout') -and ($_.Value -lt $script:MinPolicyRequestAssignmentTimeout)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ClientPolicy', 'PolicyRequestAssignmentTimeout', 'low',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinPolicyRequestAssignmentTimeout)
            }
        }
        #endregion

        #region RuleID = 144 - xxcheck recommendation 5125
        $RuleID = 144
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ClientPolicy') -and ($_.Key -eq 'PolicyEnableUserPolicyPolling') -and ($_.Value -eq $false)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ClientPolicy', 'PolicyEnableUserPolicyPolling', 'disabled',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5125 'user policy on clients')
            }
        }
        #endregion

        #region RuleID = 145
        $RuleID = 145
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ComputerRestart') -and ($_.Key -eq 'RebootLogoffNotificationCountdownDuration') -and ($_.Value -gt $script:MaxRebootLogoffNotificationCountdownDuration)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ComputerRestart', 'RebootLogoffNotificationCountdownDuration', 'low',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxRebootLogoffNotificationCountdownDuration)
            }
        }
        #endregion

        #region RuleID = 146
        $RuleID = 146
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ComputerRestart') -and ($_.Key -eq 'RebootLogoffNotificationCountdownDuration') -and ($_.Value -lt $script:MinRebootLogoffNotificationCountdownDuration)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ComputerRestart', 'RebootLogoffNotificationCountdownDuration', 'low',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinRebootLogoffNotificationCountdownDuration)
            }
        }
        #endregion

        #region RuleID = 147
        $RuleID = 147
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ComputerRestart') -and ($_.Key -eq 'RebootLogoffNotificationFinalWindow') -and ($_.Value -gt $script:MaxRebootLogoffNotificationFinalWindow)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ComputerRestart', 'RebootLogoffNotificationFinalWindow', 'high',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxRebootLogoffNotificationFinalWindow)
            }
        }
        #endregion

        #region RuleID = 148
        $RuleID = 148
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ComputerRestart') -and ($_.Key -eq 'RebootLogoffNotificationFinalWindow') -and ($_.Value -lt $script:MinRebootLogoffNotificationFinalWindow)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ComputerRestart', 'RebootLogoffNotificationFinalWindow', 'low', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinRebootLogoffNotificationFinalWindow)
            }
        }
        #endregion

        #region RuleID = 149
        $RuleID = 149
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'HardwareInventory') -and ($_.Key -eq 'Enabled') -and ($_.Value -eq $false)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'HardwareInventory', 'Enabled', 'disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Hardware Inventory')
            }
        }
        #endregion

        #region RuleID = 150
        $RuleID = 150
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $ClientSettingsList) {
                $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'HardwareInventory') -and ($_.Key -eq 'Enabled')}
                if ($null -ne $SettingInfo) {
                    if ($SettingInfo.Value -ne $false) {
                        $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'HardwareInventory') -and ($_.Key -eq 'Schedule')}
                        if ($null -ne $SettingInfo) {
                            $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                            if ($null -ne $Schedule) {
                                $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                                if ($scheduleToMinutes -gt $script:MaxHardwareInventoryScheduleMinutes) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3112 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Hardware Inventory schedule', $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxHardwareInventoryScheduleMinutes)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 151
        $RuleID = 151
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $ClientSettingsList) {
                $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'HardwareInventory') -and ($_.Key -eq 'Enabled')}
                if ($null -ne $SettingInfo) {
                    if ($SettingInfo.Value -ne $false) {
                        $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'HardwareInventory') -and ($_.Key -eq 'Schedule')}
                        if ($null -ne $SettingInfo) {
                            $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                            if ($null -ne $Schedule) {
                                $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                                if ($scheduleToMinutes -lt $script:MinHardwareInventoryScheduleMinutes) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3113 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Hardware Inventory schedule', $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinHardwareInventoryScheduleMinutes)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 152
        $RuleID = 152
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'SoftwareInventory') -and ($_.Key -eq 'Enabled') -and ($_.Value -eq $true)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'SoftwareInventory', 'Enabled', 'enabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5095 'Software Inventory')
            }
        }
        #endregion

        #region RuleID = 153
        $RuleID = 153
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $ClientSettingsList) {
                $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareInventory') -and ($_.Key -eq 'Enabled') -and ($_.Value -eq $true)}
                if ($null -ne $SettingInfo) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareInventory') -and ($_.Key -eq 'Schedule')}
                    if ($null -ne $SettingInfo) {
                        $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                        if ($null -ne $Schedule) {
                            $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                            if ($scheduleToMinutes -gt $script:MaxSoftwareInventoryScheduleMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3112 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Software Inventory schedule', $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxSoftwareInventoryScheduleMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 154
        $RuleID = 154
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $ClientSettingsList) {
                $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareInventory') -and ($_.Key -eq 'Enabled') -and ($_.Value -eq $true)}
                if ($null -ne $SettingInfo) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareInventory') -and ($_.Key -eq 'Schedule')}
                    if ($null -ne $SettingInfo) {
                        $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                        if ($null -ne $Schedule) {
                            $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                            if ($scheduleToMinutes -lt $script:MinSoftwareInventoryScheduleMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3113 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Software Inventory schedule', $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinSoftwareInventoryScheduleMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 155
        $RuleID = 155
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $ClientSettingsList) {
                $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareDeployment') -and ($_.Key -eq 'EvaluationSchedule')}
                if ($null -ne $SettingInfo) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ($scheduleToMinutes -gt $script:MaxSoftwareDeploymentEvaluationScheduleMinutes) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3112 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Software Deployment re-evaluation schedule', $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxSoftwareDeploymentEvaluationScheduleMinutes)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 156
        $RuleID = 156
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $ClientSettingsList) {
                $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareDeployment') -and ($_.Key -eq 'EvaluationSchedule')}
                if ($null -ne $SettingInfo) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ($scheduleToMinutes -lt $script:MinSoftwareDeploymentEvaluationScheduleMinutes) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3113 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Software Deployment re-evaluation schedule', $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinSoftwareDeploymentEvaluationScheduleMinutes)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 157
        $RuleID = 157
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'Enabled') -and ($_.Value -eq $false)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'SoftwareUpdates', 'Enabled', 'disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Software Updates')
            }
        }
        #endregion

        #region RuleID = 158
        $RuleID = 158
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpArr = @()
            foreach ($item in $ClientSettingsList) {
                if ($null -ne $SUPList) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'Enabled')}
                    if ($null -ne $SettingInfo) {
                        if ($SettingInfo.Value -ne $false) {
                            $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'ScanSchedule')}
                            if ($null -ne $SettingInfo) {
                                $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                                if ($null -ne $Schedule) {
                                    $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule
                                    $SoftwareUpdateScanScheduleMinutes = $scheduleToMinutes

                                    if ($scheduleToMinutes -gt $script:MaxSoftwareUpdateScanScheduleMinutes) {
                                        $tmpArr += $SettingInfo
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($tmpArr.Count, $tmpArr[0].SettingsName, 'Software Update scan schedule', 'high', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxSoftwareUpdateScanScheduleMinutes)
            }

        }
        #endregion

        #region RuleID = 159
        $RuleID = 159
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpArr = @()
            foreach ($item in $ClientSettingsList) {
                if ($null -ne $SUPList) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'Enabled')}
                    if ($null -ne $SettingInfo) {
                        if ($SettingInfo.Value -ne $false) {
                            $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'ScanSchedule')}
                            if ($null -ne $SettingInfo) {
                                $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                                if ($null -ne $Schedule) {
                                    $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule
                                    $SoftwareUpdateScanScheduleMinutes = $scheduleToMinutes

                                    if ($scheduleToMinutes -lt $script:MinSoftwareUpdateScanScheduleMinutes) {
                                        $tmpArr += $SettingInfo
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($tmpArr.Count, $tmpArr[0].SettingsName, 'Software Update scan schedule', 'low', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinSoftwareUpdateScanScheduleMinutes)
            }
        }
        #endregion

        #region RuleID = 160
        $RuleID = 160
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach ($item in $ClientSettingsList) {
                if ($null -ne $SUPList) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'Enabled')}
                    if ($null -ne $SettingInfo) {
                        if ($SettingInfo.Value -ne $false) {
                            $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'EvaluationSchedule')}
                            if ($null -ne $SettingInfo) {
                                $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                                if ($null -ne $Schedule) {
                                    $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule
                                    $SoftwareUpdateReScanScheduleMinutes = $scheduleToMinutes

                                    if ($scheduleToMinutes -gt $script:MaxSoftwareUpdateReScanScheduleMinutes) {
                                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3112 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Software Update re-evaluation schedule', $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5125 $script:MaxSoftwareUpdateReScanScheduleMinutes)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 161
        $RuleID = 161
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpArr = @()
            foreach ($item in $ClientSettingsList) {
                if ($null -ne $SUPList) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'Enabled')}
                    if ($null -ne $SettingInfo) {
                        if ($SettingInfo.Value -ne $false) {
                            $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'EvaluationSchedule')}
                            if ($null -ne $SettingInfo) {
                                $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                                if ($null -ne $Schedule) {
                                    $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule
                                    $SoftwareUpdateReScanScheduleMinutes = $scheduleToMinutes

                                    if ($scheduleToMinutes -lt $script:MinSoftwareUpdateReScanScheduleMinutes) {
                                        $tmpArr += $SettingInfo
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if ($tmpArr.Count -gt 0) {
                $tmpArr | Group-Object SettingsName | ForEach-Object {
                    $Item = $_
                    $strArray = (($item.Group | select Name -Unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count, 'Software Updates', 're-evaluation schedule', 'low', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinSoftwareUpdateReScanScheduleMinutes)
                }
            }
        }
        #endregion

        #region RuleID = 162
        $RuleID = 162
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            foreach ($item in $ClientSettingsList) {
                if ($null -ne $SUPList) {
                    $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'Enabled')}
                    if ($null -ne $SettingInfo) {
                        if ($SettingInfo.Value -ne $false) {
                            $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'ScanSchedule')}
                            if ($null -ne $SettingInfo) {
                                $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                                if ($null -ne $Schedule) {
                                    $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule
                                    $SoftwareUpdateScanScheduleMinutes = $scheduleToMinutes
                                }
                            }

                            $SettingInfo = $ClientSettingsSettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'SoftwareUpdates') -and ($_.Key -eq 'EvaluationSchedule')}
                            if ($null -ne $SettingInfo) {
                                $Schedule = Convert-CMSchedule -ScheduleString "$($SettingInfo.Value)"
                                if ($null -ne $Schedule) {
                                    $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule
                                    $SoftwareUpdateReScanScheduleMinutes = $scheduleToMinutes
                                }
                            }

                            if ($SoftwareUpdateReScanScheduleMinutes -lt $SoftwareUpdateScanScheduleMinutes) {
                                $tmpArr += $SettingInfo
                            }
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $tmpArr | Group-Object SettingsName | ForEach-Object {
                    $Item = $_
                    $strArray = (($item.Group | select Name -Unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3272 @($item.Count, 'Software Updates', 're-evaluation schedule', 'scan schedule', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinSoftwareUpdateReScanScheduleMinutes)
                }
            }

        }
        #endregion

        #region RuleID = 163
        $RuleID = 163
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'EndpointProtection') -and ($_.Key -eq 'EnableEP') -and ($_.Value -eq $false)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'EndpointProtection', 'Enabled', 'disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Endpoint Protection')
            }
        }
        #endregion

        #region RuleID = 164
        $RuleID = 164
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $MaintenanceTaskList | where-object {($_.ItemName -eq 'Backup SMS Site Server') -and ($_.Enabled -eq $true)} | ForEach-Object {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3044 @($_.ItemName, $_.Enabled)) -Comment (Get-RFLHealthCheckRecommendation 5029 @($_.ItemName, '[HL]https://stevethompsonmvp.wordpress.com/2016/05/31/configuration-manager-sql-server-backup-guidelines/[/HL]'))
            }
        }
        #endregion

        #region RuleID = 165
        $RuleID = 165
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $MaintenanceTaskList | where-object {($_.ItemName -eq 'Rebuild Indexes') -and ($_.Enabled -eq $true)} | ForEach-Object {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3044 @($_.ItemName, $_.Enabled)) -Comment (Get-RFLHealthCheckRecommendation 5029 @($_.ItemName, '[HL]https://ola.hallengren.com/sql-server-index-and-statistics-maintenance.html[/HL]'))
            }
        }
        #endregion

        #region RuleID = 166
        $RuleID = 166
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.SiteSystemCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | Group-Object SiteSystemCount | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3178 @($item.Count, 'Boundary Group', 'Site Systems', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5030 'Site System')
            }
        }
        #endregion

        #region RuleID = 167
        $RuleID = 167
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | Group-Object MemberCount | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3178 @($item.Count, 'Boundary Group', 'Boundary', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5030 'Site System')
            }
        }
        #endregion

        #region RuleID = 168
        $RuleID = 168
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $DPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackDP -gt -1)} | ForEach-Object {

                        if ($_.FallbackDP  -gt $script:MaxFallbackDPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3114 @($item.Name, 'Distribution Point', $_.FallbackDP)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:MaxFallbackDPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 169
        $RuleID = 169
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $DPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackDP -gt -1)} | ForEach-Object {

                        if ($_.FallbackDP  -lt $script:MinFallbackDPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3115 @($item.Name, 'Distribution Point', $_.FallbackDP)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:MinFallbackDPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 170
        $RuleID = 170
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $MPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackMP -gt -1)} | ForEach-Object {

                        if ($_.FallbackMP -gt $script:MaxFallbackMPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3114 @($item.Name, 'Management Point', $_.FallbackMP)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:MaxFallbackMPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 171
        $RuleID = 171
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $MPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackMP -gt -1)} | ForEach-Object {

                        if ($_.FallbackMP -lt $script:MinFallbackMPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3115 @($item.Name, 'Management Point', $_.FallbackMP)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:MinFallbackMPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 172
        $RuleID = 172
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $SMPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackSMP -gt -1)} | ForEach-Object {

                        if ($_.FallbackSMP -gt $script:MaxFallbackSMPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3114 @($item.Name, 'State Migration Point', $_.FallbackSMP)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:MaxFallbackSMPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 173
        $RuleID = 173
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $SMPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackSMP -gt -1)} | ForEach-Object {

                        if ($_.FallbackSMP -lt $script:MinFallbackSMPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3115 @($item.Name, 'State Migration Point', $_.FallbackSMP)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:MinFallbackSMPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 174
        $RuleID = 174
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $SUPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackSUP -gt -1)} | ForEach-Object {

                        if ($_.FallbackSUP -gt $script:MaxFallbackSUPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3114 @($item.Name, 'Software Update Point', $_.FallbackSUP)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:MaxFallbackSUPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 175
        $RuleID = 175
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BoundaryGroupList | where-object {($_.MemberCount -lt 1) -and ($_.Name -notlike 'Default-Site-Boundary-Group<*>')} | ForEach-Object {
                $item = $_
                if ($null -ne $SUPList) {
                    $BoundaryGroupRelationshipList | Where-Object {($_.SourceGroupID -eq $item.GroupID) -and ($_.FallbackSUP -gt -1)} | ForEach-Object {

                        if ($_.FallbackSUP -lt $script:MinFallbackSUPBoundaryGroupRelationship) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3115 @($item.Name, 'Software Update Point', $_.FallbackSUP)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:MinFallbackSUPBoundaryGroupRelationship)
                        }
                    }
                }
            }
        }
        #endregion

        #region Endpoint Protection - Malware
        if ($null -ne $EndpointProtectionList) {
            #region RuleID = 176
            $RuleID = 176
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $MalwareDetectedCount = ($MalwareDetectedList | Where-Object {($_.InfectedCount -gt 0) -and ($_.PendingCount -gt 0)} | Measure-Object).Count
                if ($MalwareDetectedCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($MalwareDetectedCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3046 MalwareDetectedCount) -Comment (Get-RFLHealthCheckRecommendation 5031 'Boundary')
                }
            }
            #endregion

            #region RuleID = 177
            $RuleID = 177
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $MalwarePolicyList | where-object {($_.Name -ne 'Default Client Antimalware Policy') -and ($_.AssignmentCount -eq 0)} | ForEach-Object {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3047 $_.Name) -Comment (Get-RFLHealthCheckRecommendation 5022 'Anti-Malware policy')
                }
            }
            #endregion

            #region RuleID = 178
            $RuleID = 178
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                foreach ($item in $MalwarePolicyList) {
                    $MalwarePolicySettingsList | where-object {($_.Name -eq $item.Name) -and ($_.Key -eq 'LimitCPUUsage') -and ($_.Value -gt $Script:AntiMalwareLimitCPUUsageMax)} | ForEach-Object {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3048 @($_.Name, $_.SettingsName, 'Limit CPU Usage', $_.Value)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:AntiMalwareLimitCPUUsageMax)
                    }
                }
            }
            #endregion

            #region RuleID = 179
            $RuleID = 179
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                foreach ($item in $MalwarePolicyList) {
                    $SettingInfo = $MalwarePolicySettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'Advanced') -and ($_.Key -eq 'DeleteQuarantinedFilesPeriod')}
                    if ($null -ne $SettingInfo) {

                        if ($SettingInfo.Value -gt $script:AntiMalwareDeleteQuarantinedFilesMax) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3133 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Delete Quarantined Files', $SettingInfo.Value)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:AntiMalwareDeleteQuarantinedFilesMax)
                        }
                    }
                }
            }
            #endregion

            #region RuleID = 180
            $RuleID = 180
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                foreach ($item in $MalwarePolicyList) {
                    $SettingInfo = $MalwarePolicySettingsList | Where-Object {($_.Name -eq $item.Name) -and ($_.SettingsName -eq 'Advanced') -and ($_.Key -eq 'DeleteQuarantinedFilesPeriod')}
                    if ($null -ne $SettingInfo) {

                        if ($SettingInfo.Value -lt $script:AntiMalwareDeleteQuarantinedFilesMin) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3116 @($SettingInfo.Name, $SettingInfo.SettingsName, 'Delete Quarantined Files', $SettingInfo.Value)) -Comment (Get-RFLHealthCheckRecommendation 5009 $script:AntiMalwareDeleteQuarantinedFilesMin)
                        }
                    }
                }
            }
            #endregion
        }
        #endregion

        #region Endpoint Protection - Firewall
        if ($null -ne $EndpointProtectionList) {
            #region RuleID = 181
            $RuleID = 181
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $FirewallPolicyList | where-object {($_.AssignmentCount -eq 0)} | ForEach-Object {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3049 $_.Name) -Comment (Get-RFLHealthCheckRecommendation 5022 'Firewall policy')
                }
            }
            #endregion

            #region RuleID = 182
            $RuleID = 182
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                if ($null -ne $FirewallPolicyList) {
                    $tmpArr = @()
                    $FirewallPolicyList | ForEach-Object {
                        $item = $_
                        $FirewallSettings = @()
                        @('Domain','Public','Private') | ForEach-Object {
                            $FirewallSettings += New-Object -TypeName PSObject -Property @{'Profile' = $_; 'DisplayText' = 'Enable Windows Defender Firewall'; 'Option' = "Enable Firewall on $($_) Network"; 'Value' = $false }
                            $FirewallSettings += New-Object -TypeName PSObject -Property @{'Profile' = $_; 'DisplayText' = 'Block all incoming connections, including those in the list of allowed programs'; 'Option' = "Block all inbound traffic on $($_) Network"; 'Value' = $false }
                            $FirewallSettings += New-Object -TypeName PSObject -Property @{'Profile' = $_; 'DisplayText' = 'Notify the user when Windows Defender Firewall blocks a new program'; 'Option' = "Disable notifications on $($_) Network"; 'Value' = $false }
                        }
                        #$FirewallSettings = new-object HealthCheckClasses.ConfigMgr.CEFirewallPolicyEnabledSettingsCollection
                        foreach($itemrule in ([xml]$item.SDMPackageXML).DesiredConfigurationDigest.ConfigurationPolicy.Rules.Rule) {
                            $itemDomain = $itemrule.Annotation.DisplayName.Text.Replace('Enable Firewall on ','').Replace('Block all inbound traffic on','').Replace('Disable notifications on','').Replace('Network','').Trim()
                            $itemname = $itemrule.Annotation.DisplayName.Text
                            $itemvalue = $itemrule.Expression.Operands.ConstantValue.Value

                            ($FirewallSettings | Where-Object {($_.Profile -eq $itemDomain) -and ($_.Option -eq $itemname)}).Value = $true
                        }
                        $FirewallSettings.Items | where-object {($_.Value -eq $false) -and ($_.Option -eq 'Enable Windows Defender Firewall')} | ForEach-Object {
                            $tmpArr += New-Object -TypeName PSObject -Property @{'Name' = $item.LocalizedDisplayName; 'Option' = $_.DisplayText; 'Profile' = $_.Profile; }
                        }
                    }
                    if ($tmpArr.Count -gt 0) {
                        $tmpArr | Group-Object Name | ForEach-Object {
                            $tmpArrItem = $_
                            $tmpCount = ($tmpArrItem | where-object {$_.Name -eq $tmpArrItem.Name} | select Name -Unique | Measure-object).Count
                            $strArray = (($tmpArrItem | where-object {$_.Name -eq $tmpArrItem.Name} | select Name -Unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArrItem.Count)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3258 @($tmpCount, 'Enable Windows Defender Firewall', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Windows Defender Firewall')
                        }
                    }
                }
            }
            #endregion
        }
        #endregion

        #region RuleID = 183
        $RuleID = 183
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SwMeteringSettingsList | ForEach-Object {
                $item = $_
                $item.Props | where-object {($_.PropertyName -eq 'Auto Create Disabled Rule') -and ($_.Value -eq 1)} | ForEach-Object {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3003 @('Software Metering Auto Create Disabled Rule', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5011 'Software Metering Auto Create Disabled Rule')
                }
            }
        }
        #endregion

        #region RuleID = 184
        $RuleID = 184
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            foreach($item in ($SwMeteringRuleList | Group-Object SiteCode).Name) {
                $itemCount = ($SwMeteringRuleList | Where-Object {($_.Enabled -eq $false) -and ($_.SiteCode -eq $item)} | Measure-Object).Count
                if ($itemCount -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($itemCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3051 @($itemCount, 'Software Metering Rule(s)', $item)) -Comment (Get-RFLHealthCheckRecommendation 5032)
                }
            }
        }
        #endregion

        #region RuleID = 185
        $RuleID = 185
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BootList | Where-Object {$_.EnableLabShell -eq $true} | Group-Object EnableLabShell | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3179 @($item.Count, 'Boot Image', 'Enable command support (testing only)', 'Enabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5033 @('Boot Image', 'Enable command support (testing only)', 'disabled'))
            }
        }
        #endregion

        #region RuleID = 186
        $RuleID = 186
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $BootList | where-object {$_.DefaultImage -eq $true } | ForEach-Object {
                $Item = $_
                ($TaskSequenceReferenceList | Where-Object {$_.Content.PackageID -eq $item.PackageID}) | Select-Object -Property @{Name = 'BootName'; Expression = {$Item.Name}}, @{Name = 'BootPkgID'; Expression = {$Item.PackageID}}, @{'Name' = 'Name'; Expression = {$_.ts.Name}}, @{'Name' = 'TSPackageID'; Expression = {$_.ts.PackageID}} | group-object BootNameBootPkgID | ForEach-Object {
                    $subItem = $_
                    $strArray = (($subItem.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3181 @($subItem.Count, 'Task Sequence(s)', $Item.Name, $Item.PackageID, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5035)
                }
            }
        }
        #endregion

        #region RuleID = 187
        $RuleID = 187
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()

            $BootList | where-object {$_.DefaultImage -ne $true} | ForEach-Object {
                $Item = $_
                $refcount = ($TaskSequenceList | Where-Object {$_.BootImageID -eq $item.PackageID} | Measure-Object).Count
                if ($refCount -eq 0) {
                    $tmpArr += $item
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3182 @($tmpArr.Count, 'Boot Image', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5052 'Boot Image')
            }
        }
        #endregion

        #region RuleID = 188
        $RuleID = 188
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $bootList | Group-Object Architecture | ForEach-Object {
                #architecture 9 = x64, 0 = x32
                $item = $_
                $bootCount = ($bootList | Where-Object {($_.Architecture -eq $item.Name) -and ($_.PkgFlags -eq ($_.pkgflags -bor 0x400))} | Measure-Object).Count
                switch ($item.Name) {
                    0 { $strArch = 'x86' }
                    9 { $strArch = 'x64' }
                    default { $strArch = 'Unknown' }
                }
                if ($bootCount -gt 1) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($bootCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3053 @($bootCount, $strArch)) -Comment (Get-RFLHealthCheckRecommendation 5034 @($strArch))
                }
            }
        }
        #endregion

        #region RuleID = 189
        $RuleID = 189
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $BootList | Where-Object {($_.DefaultImage -eq $true) -and ($_.PkgFlags -eq ($_.pkgflags -bor 0x400))} | Group-Object DefaultImage | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3183 @($item.Count, 'Default Boot Image', 'Enable binary differential replication', 'Disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5033 @('Boot Image', 'Enable binary differential replication', 'enabled'))
            }
        }
        #endregion

        #region RuleID = 190
        $RuleID = 190
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $BootList | Where-Object {($_.DefaultImage -eq $true) -and ($_.ReferencedDrivers.Count -gt 0)} | Group-Object DefaultImage | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3267 @($item.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5035)
            }
        }
        #endregion

        #region RuleID = 191
        $RuleID = 191
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BootList | where-object {($_.DefaultImage -eq $false) -and (($_.pkgflags -band 0x4000000) -eq 0)} | group-object SourceSite | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3183 @($item.Count, 'Boot Image', 'Enable binary differential replication', 'Disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5033 @('Boot Image', 'Enable binary differential replication', 'enabled'))
            }
        }
        #endregion

        #region RuleID = 192
        $RuleID = 192
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BootList | Where-Object {$_.ImageOSVersion -lt $Script:MinBootVersion} | group-object SourceSite | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3184 @($item.Count, 'Boot Image', $Script:MinBootVersion, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5036 @($Script:MinBootVersion))
            }
        }
        #endregion

        #region RuleID = 193
        $RuleID = 193
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SoftwareUpdateSummarizationList | ForEach-Object {
                $Interval = $_.Interval
                switch ($_.Unit.ToString()) {
                    "Hours" { $Interval = $Interval * 60 }
                    "Days" { $Interval = $Interval * 60 * 24 }
                }

                if ($Interval -gt $Script:MaxSUPSummarizationTime) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Software Update Summarization Interval', $Interval)) -Comment (Get-RFLHealthCheckRecommendation 5093 $Script:MaxSUPSummarizationTime)
                }
            }
        }
        #endregion

        #region RuleID = 194
        $RuleID = 194
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SoftwareUpdateSummarizationList | ForEach-Object {
                $Interval = $_.Interval
                switch ($_.Unit.ToString()) {
                    "Hours" { $Interval = $Interval * 60 }
                    "Days" { $Interval = $Interval * 60 * 24 }
                }

                if ($Interval -lt $Script:MinSUPSummarizationTime) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Software Update Summarization Interval', $Interval)) -Comment (Get-RFLHealthCheckRecommendation 5094 $Script:MinSUPSummarizationTime)
                }
            }
        }
        #endregion

        #region RuleID = 195 - Software Update
        $RuleID = 195
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpSoftwareUpdateList = $SoftwareUpdateList | Where-Object {($_.IsDeployed -eq $true) -and ($_.IsSuperseded -eq $true)}
            $SUPFilterCount = ($tmpSoftwareUpdateList | Measure-Object).Count
            if ($SUPFilterCount -gt 0) {
                $strArray = (($tmpSoftwareUpdateList | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($SUPFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3013 @($SUPFilterCount, 'Superseded', '', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5039)
            }
        }
        #endregion

        #region RuleID = 196
        $RuleID = 196
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpSoftwareUpdateList = $SoftwareUpdateList | Where-Object {($_.IsDeployed -eq $true) -and ($_.IsExpired -eq $true)}
            $SUPFilterCount = ($tmpSoftwareUpdateList | Measure-Object).Count
            if ($SUPFilterCount -gt 0) {
                $strArray = (($tmpSoftwareUpdateList | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($SUPFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3013 @($SUPFilterCount, 'Expired', '', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5038)
            }
        }
        #endregion

        #region RuleID = 197
        $RuleID = 197
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpSoftwareUpdateList = $SoftwareUpdateList | Where-Object {($_.IsDeployed -eq $true) -and ($_.IsContentProvisioned -eq $false)}
            $SUPFilterCount = ($tmpSoftwareUpdateList | Measure-Object).Count
            if ($SUPFilterCount -gt 0) {
                $strArray = (($tmpSoftwareUpdateList | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($SUPFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3013 @($SUPFilterCount, '', 'without content ', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5041)
            }
        }
        #endregion

        #region RuleID = 198
        $RuleID = 198
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpSoftwareUpdateList = $SoftwareUpdateList | Where-Object {($_.IsDeployed -eq $false) -and ($_.IsContentProvisioned -eq $true)}
            $SUPFilterCount = ($tmpSoftwareUpdateList | Measure-Object).Count
            if ($SUPFilterCount -gt 0) {
                $strArray = (($tmpSoftwareUpdateList | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($SUPFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3013 @($SUPFilterCount, 'downloaded', 'not ', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5041)
            }
        }
        #endregion

        #region RuleID = 199 - Software Update Deployment List
        $RuleID = 199
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $filterCount = ($SoftwareUpdateDeploymentList | Measure-Object).Count
            if ($filterCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($filterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3069 @($filterCount)) -Comment (Get-RFLHealthCheckRecommendation 5045)
            }
        }
        #endregion

        #region RuleID = 200 - Software Update Group
        $RuleID = 200
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SoftwareUpdateGroupList | Where-Object {$_.NumberOfUpdates -gt $Script:MaxUpdateInSUPGroupWarning} | ForEach-Object {
                if ($_.NumberOfUpdates -lt $Script:MaxUpdateInSUPGroupError) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3057 @($_.LocalizedDisplayName, $_.NumberOfUpdates)) -Comment (Get-RFLHealthCheckRecommendation 5037 $Script:MaxUpdateInSUPGroupError)
                }
            }
        }
        #endregion

        #region RuleID = 201
        $RuleID = 201
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SoftwareUpdateGroupList | Where-Object {$_.NumberOfUpdates -gt $Script:MaxUpdateInSUPGroupWarning} | ForEach-Object {
                if ($_.NumberOfUpdates -ge $Script:MaxUpdateInSUPGroupError) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3057 @($_.LocalizedDisplayName, $_.NumberOfUpdates)) -Comment (Get-RFLHealthCheckRecommendation 5037 $Script:MaxUpdateInSUPGroupError)
                }
            }
        }
        #endregion

        #region RuleID = 202
        $RuleID = 202
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $SoftwareUpdateGroupList | Where-Object {$_.NumberOfUpdates -eq 0} | ForEach-Object {
                $item = $_
                $tmpArr += $item
            }
                
            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3238 @($tmpArr.Count, 'Software Update Group', '0', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5040)
            }
        }
        #endregion

        #region RuleID = 203
        $RuleID = 203
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SoftwareUpdateGroupList | Where-Object {$_.ContainsExpiredUpdates -eq $true} | ForEach-Object {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3014 @($_.LocalizedDisplayName, 'Expired')) -Comment (Get-RFLHealthCheckRecommendation 5038)
            }
        }
        #endregion

        #region RuleID = 204
        $RuleID = 204
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $SoftwareUpdateGroupList | Where-Object {$_.ContainsSupersededUpdates -eq $true} | ForEach-Object {
                $item = $_
                $tmpArr += $item
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3243 @($tmpArr.Count, 'Superseded', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5126 $script:MinSoftwareUpdateScanScheduleMinutes)
            }
        }
        #endregion

        #region RuleID = 205
        $RuleID = 205
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $SoftwareUpdateGroupList | Where-Object {($_.isDeployed -eq $true) -and ($_.isProvisioned -eq $false)} | ForEach-Object {
                $item = $_
                $tmpArr += $item
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3253 @($tmpArr.Count, 'one or more non-downloaded ', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5041)
            }
        }
        #endregion

        #region RuleID = 206
        $RuleID = 206
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SoftwareUpdateGroupList | Where-Object {($_.isDeployed -eq $false) -and ($_.isProvisioned -eq $true)} | group-object isDeployed | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3185 @($item.Count, 'Software Update Group', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5042)
            }
        }
        #endregion

        #region RuleID = 207 - Software Update Deployment
        $RuleID = 207
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $tmpArr = @()
            $SoftwareUpdateGroupDeploymentList | ForEach-Object {
                $item = $_
                $itemUpdGroup = $SoftwareUpdateGroupList | Where-Object {$_.CI_ID -eq $item.AssignedUpdateGroup}
                if ($item.Enabled -eq $false) {
                    $tmpArr += $itemUpdGroup
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3232 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5048)
            }
        }
        #endregion

        #region RuleID = 208
        $RuleID = 208
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SoftwareUpdateGroupDeploymentList | ForEach-Object {
                $item = $_
                $itemUpdGroup = $SoftwareUpdateGroupList | Where-Object {$_.CI_ID -eq $item.AssignedUpdateGroup}
                if ($item.TargetCollectionID -eq 'SMS00001') {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3066 @($itemUpdGroup.LocalizedDisplayName, 'All Systems')) -Comment (Get-RFLHealthCheckRecommendation 5021 'All Systems')
                }
            }
        }
        #endregion

        #region RuleID = 209
        $RuleID = 209
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateGroupDeploymentList) {
                $tmpArr = @()
                $SoftwareUpdateGroupDeploymentList | ForEach-Object {
                    $item = $_
                    $itemUpdGroup = $SoftwareUpdateGroupList | Where-Object {$_.CI_ID -eq $item.AssignedUpdateGroup}
                    if ($item.StateMessageVerbosity -lt 10) {
                        $tmpArr += $itemUpdGroup
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3233 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5048)
                }
            }
        }
        #endregion

        #region RuleID = 210
        $RuleID = 210
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $tmpArr = @()
                $SoftwareUpdateADRList | Where-Object {($_.AutoDeploymentEnabled -eq $false)} | ForEach-Object {
                    $item = $_
                    $tmpArr += $item
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3244 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Automatic Deployment Rule')
                }
            }
        }
        #endregion

        #region RuleID = 211
        $RuleID = 211
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $tmpArr = @()
                $SoftwareUpdateADRList | Where-Object {($_.LastErrorCode -ne 0)} | ForEach-Object {
                    $item = $_
                    $tmpArr += $item
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    $strArrayErrorCode = (($tmpArr | select-Object LastErrorCode -unique) | Foreach {"'$($_.LastErrorCode)'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3245 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5043 $strArrayErrorCode)
                }
            }
        }
        #endregion

        #region RuleID = 212
        $RuleID = 212
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $tmpArr = @()
                $SoftwareUpdateADRList | Where-Object {($_.LastRunTime -lt (Get-Date).AddDays(-$Script:ADRLastRunMaxTime))} | ForEach-Object {
                    $item = $_
                    $tmpArr += $item
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3246 @($tmpArr.Count, $Script:ADRLastRunMaxTime, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5044 $Script:ADRLastRunMaxTime)
                }
            }
        }
        #endregion

        #region RuleID = 213
        $RuleID = 213
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $tmpArr = @()
                $SoftwareUpdateADRList | Where-Object {($_.AutoDeploymentEnabled -eq $true)} | ForEach-Object {
                    $item = $_
                    $ADRDeploymentCount = ($SoftwareUpdateADRDeploymetList | Where-Object {($_.RuleID -eq $Item.AutoDeploymentID)} | Measure-Object).Count
                    $ADRDisabledDeploymentCount = ($SoftwareUpdateADRDeploymetList | Where-Object {($_.RuleID -eq $Item.AutoDeploymentID) -and ($_.Enabled -eq $false)} | Measure-Object).Count

                    if ($ADRDeploymentCount -eq $ADRDisabledDeploymentCount) {
                        $item = $_
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3268 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5046)
                }
            }
        }
        #endregion

        #region RuleID = 214
        $RuleID = 214
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    $SoftwareUpdateADRDeploymetList | Where-Object {($_.RuleID -eq $Item.AutoDeploymentID) -and ($_.CollectionName -eq 'All Systems')} | ForEach-Object {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3063 @($Item.Name, 'All Systems')) -Comment (Get-RFLHealthCheckRecommendation 5021 'All Systems')
                    }
                }
            }
        }
        #endregion

        #region RuleID = 215
        $RuleID = 215
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    if (-not [string]::IsNullOrEmpty($_.Schedule)) {
                        $Schedule = Convert-CMSchedule -ScheduleString $item.Schedule
                        if ($null -ne $Schedule) {
                            $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                            if ($scheduleToMinutes -gt $Script:MaxADRSchedule) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3117 @($item.Name, $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxADRSchedule)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 216
        $RuleID = 216
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    if (-not [string]::IsNullOrEmpty($_.Schedule)) {
                        $Schedule = Convert-CMSchedule -ScheduleString $item.Schedule
                        if ($null -ne $Schedule) {
                            $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                            if ($scheduleToMinutes -lt $Script:MinADRSchedule) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3118 @($item.Name, $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinADRSchedule)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 217
        $RuleID = 217
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    if (([string]::IsNullOrEmpty($_.Schedule)) -and ((([xml]$item.AutoDeploymentProperties).AutoDeploymentRule.AlignWithSyncSchedule -eq $false))) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3070 @($Item.Name)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Automatic Deployment Rules, Evaluation Schedule')
                    }
                }
            }
        }
        #endregion

        #region RuleID = 218
        $RuleID = 218
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $tmpArr = @()
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    $SoftwareUpdateADRDeploymetList | Where-Object {($_.RuleID -eq $Item.AutoDeploymentID)} | ForEach-Object {
                        $ItemXML = ([xml]$_.DeploymentTemplate).DeploymentCreationActionXML

                        if ($itemXML.StateMessageVerbosity -lt 10) {
                            $tmpArr += New-Object -TypeName PSObject -Property @{'Name' = $item.Name; 'CollectionName' = $_.CollectionName; }
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name,CollectionName -unique) | Foreach {"'$($_.Name.Trim()) - Collection $($_.CollectionName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3247 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5047)
                }
            }
        }
        #endregion

        #region RuleID = 219
        $RuleID = 219
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $tmpArr = @()
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    $SoftwareUpdateADRDeploymetList | Where-Object {($_.RuleID -eq $Item.AutoDeploymentID)} | ForEach-Object {
                        if ($itemXML.EnableAlert -eq $false) {
                            $item = $_
                            $tmpArr += $item
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name,CollectionName -unique) | Foreach {"'$($_.Name.Trim()) - Collection $($_.CollectionName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3248 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Automatic Deployment Rules, Alert')
                }
            }
        }
        #endregion

        #region RuleID = 220
        $RuleID = 220
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    $SoftwareUpdateADRDeploymetList | Where-Object {($_.RuleID -eq $Item.AutoDeploymentID)} | ForEach-Object {
                        if ($itemXML.EnableAlert -ne $false) {
                            $Interval = [int]$itemXML.AlertDuration
                            switch ($itemxml.AlertDurationUnits) {
                                "Hours" { $Interval = $Interval * 60 }
                                "Days" { $Interval = $Interval * 60 * 24 }
                                "Weeks" { $Interval = $Interval * 60 * 24 * 7 }
                                "Months" { $Interval = $Interval * 60 * 24 * 7 * 30 }
                            }

                            if ($Interval -gt $Script:MaxSUPAlertTime) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3119 @($Item.Name, $_.CollectionName, $Interval)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxSUPAlertTime)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 221
        $RuleID = 221
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareUpdateADRList) {
                $SoftwareUpdateADRList | ForEach-Object {
                    $item = $_
                    $SoftwareUpdateADRDeploymetList | Where-Object {($_.RuleID -eq $Item.AutoDeploymentID)} | ForEach-Object {
                        if ($itemXML.EnableAlert -ne $false) {
                            $Interval = [int]$itemXML.AlertDuration
                            switch ($itemxml.AlertDurationUnits) {
                                "Hours" { $Interval = $Interval * 60 }
                                "Days" { $Interval = $Interval * 60 * 24 }
                                "Weeks" { $Interval = $Interval * 60 * 24 * 7 }
                                "Months" { $Interval = $Interval * 60 * 24 * 7 * 30 }
                            }

                            if ($Interval -lt $Script:MinSUPAlertTime) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3120 @($Item.Name, $_.CollectionName, $Interval)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinSUPAlertTime)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 222 - Hierarchy Settings
        $RuleID = 222
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $AutoUpgradeConfigs | ForEach-Object {
                if ($_.IsProgramEnabled -eq $false) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3071 @('Hierarchy Settings, Client Auto Upgrade')) -Comment (Get-RFLHealthCheckRecommendation 5010 'Client Auto Upgrade')
                }
            }
        }
        #endregion

        #region RuleID = 222 again as it is looking for upgradeconfigerrors now
        $RuleID = 222
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($AutoUpgradeConfigsError.Count -gt 0) { #check rule ID 222
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3106 @("$($env:USERDOMAIN)\$($env:USERNAME)", $SMSProviderServer)) -Comment (Get-RFLHealthCheckRecommendation 5079)
            }
        }
        #endregion

        #region RuleID = 223
        $RuleID = 223
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $AutoUpgradeConfigs | ForEach-Object {
                if ($_.AdvertisementDuration -gt $Script:MaxClientUpgradeDays) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Hierarchy Settings, Client Auto Upgrade, Automatically upgrade clients within days', $_.AdvertisementDuration)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxClientUpgradeDays)
                }
            }
        }
        #endregion

        #region RuleID = 224
        $RuleID = 224
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($null -ne $AutoUpgradeConfigs) {
                $AutoUpgradeConfigs | ForEach-Object {
                    if ($_.AdvertisementDuration -lt $Script:MinClientUpgradeDays) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Hierarchy Settings, Client Auto Upgrade, Automatically upgrade clients within days', $_.AdvertisementDuration)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinClientUpgradeDays)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 225 - Hierarchy Settings
        $RuleID = 225
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteList | ForEach-Object {
                $item = $_
                $EmailNotificationList | Where-Object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                    if (($_.Props | Where-Object {($_.PropertyName -eq 'EnableSmtpSetting')}).Value -eq 0) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Email Notification', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Email Notification')
                    }
                }
            }
        }
        #endregion

        #region RuleID = 226
        $RuleID = 226
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteList | ForEach-Object {
                $item = $_
                $EmailNotificationList | Where-Object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                    if (($_.Props | Where-Object {($_.PropertyName -eq 'EnableSmtpSetting')}).Value -eq 0) {
                        if (($_.Props | Where-Object {($_.PropertyName -eq 'AuthenticationMethod')}).Value -ne 0) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3072 @('SMTP Server Connection Account', $item.SiteCode, 'None')) -Comment (Get-RFLHealthCheckRecommendation 5062 @('SMTP Server Connection Account', 'Use the computer account of the site server or Specify an Account'))
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 227
        $RuleID = 227
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteList | ForEach-Object {
                $item = $_
                $EmailNotificationList | Where-Object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                    if (($_.Props | Where-Object {($_.PropertyName -eq 'EnableSmtpSetting')}).Value -eq 0) {
                        if (($_.Props | Where-Object {($_.PropertyName -eq 'UseSsl')}).Value -eq 0) {
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3072 @('This server requires and encrypted connection (SSL)', $item.SiteCode, 'disable')) -Comment (Get-RFLHealthCheckRecommendation 5062 @('This server requires and ecnrypted connection (SSL)', 'enabled'))
                        }
                    }
                }
            }
        }
        #endregion

#region RuleID = 228 - Active Directory Forests
        $RuleID = 228
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ADForestDiscoveryStatusList | where-object {($_.PublishingEnabled -eq $false)} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object ForestFQDN -unique) | Foreach {"'$($_.ForestFQDN.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3277 @($item.Count, $item.Name, 'publishing', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Active Directory Forest Publishing')
            }
        }
        #endregion

        #region RuleID = 229
        $RuleID = 229
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ADForestDiscoveryStatusList | where-object {($_.DiscoveryEnabled -eq $true) -and ($_.DiscoveryStatus -eq 2)} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object ForestFQDN -unique) | Foreach {"'$($_.ForestFQDN.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3278 @($item.Count, $item.Name, 'discovery', 'access denied', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5063 'discovery')
            }
        }
        #endregion

        #region RuleID = 230
        $RuleID = 230
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ADForestDiscoveryStatusList | where-object {($_.DiscoveryEnabled -eq $true) -and ($_.DiscoveryStatus -eq 3)} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object ForestFQDN -unique) | Foreach {"'$($_.ForestFQDN.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3278 @($item.Count, $item.Name, 'discovery', 'failed', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5064)
            }
        }
        #endregion

        #region RuleID = 231
        $RuleID = 231
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ADForestDiscoveryStatusList | where-object {($_.PublishingEnabled -eq $true) -and ($_.PublishingStatus -in (2, 5))} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object ForestFQDN -unique) | Foreach {"'$($_.ForestFQDN.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3278 @($item.Count, $item.Name, 'publishing', 'failed', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5063 'publishing')
            }
        }
        #endregion

        #region RuleID = 232
        $RuleID = 232
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ADForestDiscoveryStatusList | where-object {($_.PublishingEnabled -eq $true) -and ($_.PublishingStatus -eq 0)} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object ForestFQDN -unique) | Foreach {"'$($_.ForestFQDN.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3278 @($item.Count, $item.Name, 'publishing', 'uknown', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5064)
            }
        }
        #endregion

        #region RuleID = 233
        $RuleID = 233
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ADForestDiscoveryStatusList | where-object {($_.PublishingEnabled -eq $true) -and ($_.DiscoveryStatus -eq 0) -and ($_.LastDiscoveryTime -lt (Get-Date).AddDays(-$Script:ForestDiscoveryMaxDiscoveryTime))} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object ForestFQDN -unique) | Foreach {"'$($_.ForestFQDN.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3279 @($item.Count, $item.Name, 'discovery', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:ForestDiscoveryMaxDiscoveryTime)
            }
        }
        #endregion
        
        #region Run if Hierarchy
        if (($SiteList | Measure-Object).Count -gt 1) {
            #region RuleID = 234
            $RuleID = 234
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $DatabaseReplicationStatusList | where-object {($_.LinkStatus -ne 2)} | ForEach-Object {
                    if ($_.LinkStatus -eq 9) { #link down
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3077 @($_.Site1, $_.SiteName1, $_.Site2, $_.SiteName2, 'failed')) -Comment (Get-RFLHealthCheckRecommendation 5065)
                    }
                }
            }
            #endregion

            #region RuleID = 235
            $RuleID = 235
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $DatabaseReplicationStatusList | where-object {($_.LinkStatus -ne 2)} | ForEach-Object {
                    if ($_.LinkStatus -eq 8) { #degraded
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3077 @($_.Site1, $_.SiteName1, $_.Site2, $_.SiteName2, 'degraded')) -Comment (Get-RFLHealthCheckRecommendation 5065)
                    }
                }
            }
            #endregion

            #region RuleID = 236
            $RuleID = 236
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $DatabaseReplicationStatusList | where-object {($_.LinkStatus -ne 2)} | ForEach-Object {
                    if ($_.LinkStatus -notin (8,9)) { #degraded
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3077 @($_.Site1, $_.SiteName1, $_.Site2, $_.SiteName2, "unknown ($($_.LinkStatus))")) -Comment (Get-RFLHealthCheckRecommendation 5065)
                    }
                }
            }
            #endregion

            #region RuleID = 237
            $RuleID = 237
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $DatabaseReplicationStatusList | where-object {($_.Site1ToSite2GlobalSyncTime -lt (Get-Date).AddHours(-$Script:DatabaseReplicationMaxLagTime))} | Group-Object Site1 | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object Site2 -unique) | Foreach {"'$($_.Site2.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)

                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3219 @($Item.Count, $item.Group[0].Site1, $item.Group[0].SiteName1, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5065)
                }
            }
            #endregion

            #region RuleID = 238
            $RuleID = 238
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $DatabaseReplicationStatusList | where-object {($_.Site2ToSite1GlobalSyncTime -lt (Get-Date).AddHours(-$Script:DatabaseReplicationMaxLagTime))} | Group-Object Site1 | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object Site2 -unique) | Foreach {"'$($_.Site2.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3219 @($Item.Count, $item.Group[0].Site1, $item.Group[0].SiteName1, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5065)
                }
            }
            #endregion

            #region RuleID = 239
            $RuleID = 239
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
                $tmpArr = @()
                $SiteList | ForEach-Object {
                    $item = $_

                    $SiteComponentManagerList | where-object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                        $Props = $_.Props
                        $Props | Where-Object {($_.PropertyName -eq 'Enforce Enhanced Hash Algorithm') -and ($_.Value -eq $false)} | ForEach-Object {
                            $tmpArr += $item
                        }
                    }
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3220 @($item.Count, 'Enforce Enhanced Hash Algorithm', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Require SHA-256')
                }
            }
            #endregion

            #region RuleID = 240
            $RuleID = 240
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $DatabaseReplicationScheduleList | Where-Object {$_.TypeName -eq 'LinkGeneral'} | ForEach-Object {
                    $item = $_
                    $ReplSchedule = [int]($item.Props | Where-Object {($_.PropertyName -eq 'Send History Summarize Interval')}).Value

                    if ($ReplSchedule -gt $Script:MaxLinkDatabaseReplicationSchedule) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3121 @($item.SiteCode, $ReplSchedule)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxLinkDatabaseReplicationSchedule)
                    }
                }
            }
            #endregion

            #region RuleID = 241
            $RuleID = 241
            $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
            if ($RuleIDInfo.Enabled -ne $true) {
                Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
            } else {
                Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

                $DatabaseReplicationScheduleList | Where-Object {$_.TypeName -eq 'LinkGeneral'} | ForEach-Object {
                    $item = $_
                    $ReplSchedule = [int]($item.Props | Where-Object {($_.PropertyName -eq 'Send History Summarize Interval')}).Value

                    if ($ReplSchedule -lt $Script:MinLinkDatabaseReplicationSchedule) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3122 @($item.SiteCode, $ReplSchedule)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinLinkDatabaseReplicationSchedule)
                    }
                }
            }
            #endregion
        }
        #endregion

        #region RuleID = 242 - Status Summarization for Primary Site
        $RuleID = 242
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Deployment Summarizer"} | ForEach-Object {

                if ($_.FirstIntervalMins -gt $Script:MaxAppDeploymentSummarization1) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3123 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 30 days', $_.SiteCode, $_.FirstIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxAppDeploymentSummarization1)
                }
            }
        }
        #endregion

        #region RuleID = 243
        $RuleID = 243
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Deployment Summarizer"} | ForEach-Object {

                if ($_.FirstIntervalMins -lt $Script:MinAppDeploymentSummarization1) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3124 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 30 days', $_.SiteCode, $_.FirstIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinAppDeploymentSummarization1)
                }
            }
        }
        #endregion

        #region RuleID = 244
        $RuleID = 244
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Deployment Summarizer"} | ForEach-Object {

                if ($_.SecondIntervalMins -gt $Script:MaxAppDeploymentSummarization2) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3123 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 31 to 90 days', $_.SiteCode, $_.SecondIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxAppDeploymentSummarization2)
                }
            }
        }
        #endregion

        #region RuleID = 245
        $RuleID = 245
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Deployment Summarizer"} | ForEach-Object {

                if ($_.SecondIntervalMins -lt $Script:MinAppDeploymentSummarization2) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3124 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 31 to 90 days', $_.SiteCode, $_.SecondIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinAppDeploymentSummarization2)
                }
            }
        }
        #endregion

        #region RuleID = 246
        $RuleID = 246
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Deployment Summarizer"} | ForEach-Object {

                if ($_.ThirdIntervalMins -gt $Script:MaxAppDeploymentSummarization3) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3123 @($_.Name, 'Frequency of status updates for a deplyment that was modified ove 90 days ago', $_.SiteCode, $_.ThirdIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxAppDeploymentSummarization3)
                }
            }
        }
        #endregion

        #region RuleID = 247
        $RuleID = 247
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Deployment Summarizer"} | ForEach-Object {

                if ($_.ThirdIntervalMins -lt $Script:MinAppDeploymentSummarization3) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3124 @($_.Name, 'Frequency of status updates for a deplyment that was modified ove 90 days ago', $_.SiteCode, $_.ThirdIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinAppDeploymentSummarization3)
                }
            }
        }
        #endregion

        #region RuleID = 248
        $RuleID = 248
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Statistics Summarizer"} | ForEach-Object {

                if ($_.FirstIntervalMins -gt $Script:MaxAppStatisticsSummarization1) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3123 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 30 days', $_.SiteCode, $_.FirstIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxAppStatisticsSummarization1)
                }
            }
        }
        #endregion

        #region RuleID = 249
        $RuleID = 249
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Statistics Summarizer"} | ForEach-Object {

                if ($_.FirstIntervalMins -lt $Script:MinAppStatisticsSummarization1) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3124 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 30 days', $_.SiteCode, $_.FirstIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinAppStatisticsSummarization1)
                }
            }
        }
        #endregion

        #region RuleID = 250
        $RuleID = 250
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Statistics Summarizer"} | ForEach-Object {

                if ($_.SecondIntervalMins -gt $Script:MaxAppStatisticsSummarization2) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3123 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 31 to 90 days', $_.SiteCode, $_.SecondIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxAppStatisticsSummarization2)
                }
            }
        }
        #endregion

        #region RuleID = 251
        $RuleID = 251
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Statistics Summarizer"} | ForEach-Object {

                if ($_.SecondIntervalMins -lt $Script:MinAppStatisticsSummarization2) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3124 @($_.Name, 'Frequency of status updates for a deplyment that was modified in the last 31 to 90 days', $_.SiteCode, $_.SecondIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinAppStatisticsSummarization2)
                }
            }
        }
        #endregion

        #region RuleID = 252
        $RuleID = 252
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Statistics Summarizer"} | ForEach-Object {

                if ($_.ThirdIntervalMins -gt $Script:MaxAppStatisticsSummarization3) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3123 @($_.Name, 'Frequency of status updates for a deplyment that was modified ove 90 days ago', $_.SiteCode, $_.ThirdIntervalMins)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxAppStatisticsSummarization3)
                }
            }
        }
        #endregion

        #region RuleID = 253
        $RuleID = 253
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $SiteSummarizationList | Where-Object {$_.Name -eq "Application Statistics Summarizer"} | ForEach-Object {

                if ($_.ThirdIntervalMins -lt $Script:MinAppStatisticsSummarization3) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3124 @($_.Name, 'Frequency of status updates for a deplyment that was modified ove 90 days ago', $_.SiteCode, $_.ThirdIntervalMins)e) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinAppStatisticsSummarization3)
                }
            }
        }
        #endregion

        #region RuleID = 254 - Check Account Exist
        $RuleID = 254
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $Script:AccountDoesNotExist | where-object {$_.isServiceAccount -eq $true} | ForEach-Object {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3085 @('Service', $_.AccountName))  -Comment (Get-RFLHealthCheckRecommendation 5066)
            }
        }
        #endregion

        #region RuleID = 255
        $RuleID = 255
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $Script:AccountDoesNotExist | where-object {$_.isServiceAccount -eq $false} | ForEach-Object {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3085 @('Admin', $_.AccountName))  -Comment (Get-RFLHealthCheckRecommendation 5066)
            }
        }
        #endregion

        #region RuleID = 256 - Admin Account List
        $RuleID = 256
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $FullAdminCount = ($AdminAccountList | Where-Object {$_.RoleNames -contains 'Full Administrator'} | Measure-Object).Count
            if (($FullAdminCount -ge $Script:MaxFullAdminWarning) -and ($FullAdminCount -lt $Script:MaxFullAdminError)) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3017 @($FullAdminCount))  -Comment (Get-RFLHealthCheckRecommendation 5056 $Script:MaxFullAdminError)
            }
        }
        #endregion

        #region RuleID = 257
        $RuleID = 257
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $FullAdminCount = ($AdminAccountList | Where-Object {$_.RoleNames -contains 'Full Administrator'} | Measure-Object).Count
            if ($FullAdminCount -gt $Script:MaxFullAdminError) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3017 @($FullAdminCount))  -Comment (Get-RFLHealthCheckRecommendation 5056 $Script:MaxFullAdminError)
            }
        }
        #endregion

        #region RuleID = 258 - Group Membership
        $RuleID = 258
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $GroupMembershipList | Where-Object {$_.GroupName -in $Script:GroupsNotAllowed} | sort-object -Unique | Group-Object GroupName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object DomainNetbios, AccountName) | Foreach {"'$($_.DomainNetbios.Trim())\$($_.AccountName)'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3221 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5067)
            }
        }
        #endregion

        #region RuleID = 259 - CPU Usage Time
        $RuleID = 259
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ProcessAverageTimeList | Where-Object {($_.Average -ge $Script:ErrorCPUAverageUsage)} | group-object ComputerName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3210 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5068 $CommentExtras)
            }
        }
        #endregion

        #region RuleID = 260
        $RuleID = 260
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ProcessAverageTimeList | Where-Object {($_.Average -ge $Script:WarningCPUAverageUsage) -and ($_.Average -lt $Script:ErrorCPUAverageUsage)} | group-object ComputerName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3210 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5068 $CommentExtras)
            }
        }
        #endregion

        #region RuleID = 261
        $RuleID = 261
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $ServerRegistryInformation | Where-Object {$_.ShortNameCreation -ne 1} | ForEach-Object {
                $tmpArr += $_
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Replace('\\','').Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3203 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5084)
            }
        }
        #endregion

        #region RuleID = 262
        $RuleID = 262
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ServerRegistryInformation | ForEach-Object {
                $Item = $_

                $SiteList | where-object {$_.ServerName -eq $item.ServerName} | ForEach-Object {
                    $siteitem = $_
                    if ($siteitem.InstallDir.Substring(0,2) -eq $item.ProgramFiles.Substring(0,2)) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3131 @($item.SiteCode, $item.ServerName, 'Installation folder', 'Program Files folder')) -Comment (Get-RFLHealthCheckRecommendation 5085)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 263 - Distribution Point
        $RuleID = 263
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $DistributionPointDriveInfo | where-object {($_.PercentFree -le $Script:ErrorPercentageFreeSpace)} | Group-Object SiteCode | ForEach-Object {
                $item = $_

                $strArray = (($item.Group | select-Object NALPath -unique) | Foreach {
                    $itemArr = $_
                    ($DistributionPointList | where-object{$_.NALPath -eq $itemArr.NALPath}).NetworkOSPath.Replace('\','')
                }) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3222 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5069)
            }
        }
        #endregion

        #region RuleID = 264
        $RuleID = 264
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $DistributionPointDriveInfo | where-object {($_.PercentFree -gt $Script:ErrorPercentageFreeSpace) -and ($_.PercentFree -le $Script:WarningPercentageFreeSpace)} | Group-Object SiteCode | ForEach-Object {
                $item = $_

                $strArray = (($item.Group | select-Object NALPath -unique) | Foreach {
                    $itemArr = $_
                    ($DistributionPointList | where-object{$_.NALPath -eq $itemArr.NALPath}).NetworkOSPath.Replace('\','')
                }) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3222 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5069)
            }
        }
        #endregion

        #region RuleID = 265
        $RuleID = 265
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $DistributionPointInformationList | Where-Object {($_.ServerName -eq $item.NetworkOSPath.Replace('\\','')) -and ($_.GroupCount -eq 0)} | ForEach-Object {
                        $tmpArr += $_
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Replace('\\','').Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3202 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5061)
            }
        }
        #endregion

        #region RuleID = 266
        $RuleID = 266
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_

                    $boundaryCount = ($BoundarySiteSystemsList | Where-Object {$_.ServerNALPath -like "*$($item.NetworkOSPath.Replace('\\',''))*"} | Measure-Object).Count
                    if ($boundaryCount -lt 1) {
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3201 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5061)
                }
            }
        }
        #endregion

        #region RuleID = 267
        $RuleID = 267
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props

                    $itemprops | Where-Object {($_.PropertyName -eq 'IsMulticast') -and ($_.Value -eq 1)} | ForEach-Object {
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3200 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5070)
                }
            }
        }
        #endregion

        #region RuleID = 268
        $RuleID = 268
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props

                    $itemprops | Where-Object {($_.PropertyName -eq 'IsPXE') -and ($_.Value -eq 1)} | ForEach-Object {
                        $itemprops | Where-Object {($_.PropertyName -eq 'PXEPassword') -and ($_.Value -eq 0)} | ForEach-Object {
                            $tmpArr += $item
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3199 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation  5123 'PXE Password')
                }
            }
        }
        #endregion

        #region RuleID = 269
        $RuleID = 269
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props

                    $itemprops | Where-Object {($_.PropertyName -eq 'IsPXE') -and ($_.Value -eq 1)} | ForEach-Object {
                        $itemprops | Where-Object {($_.PropertyName -eq 'SccmPXE') -and ($_.Value -eq 0)} | ForEach-Object {
                            $tmpArr += $item
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3198 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation  5123 'Incoming requests')
                }
            }
        }
        #endregion

        #region RuleID = 270
        $RuleID = 270
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props

                    $itemprops | Where-Object {($_.PropertyName -eq 'IsPXE') -and ($_.Value -eq 1)} | ForEach-Object {
                        $itemprops | Where-Object {($_.PropertyName -eq 'SupportUnknownMachines') -and ($_.Value -eq 0)} | ForEach-Object {
                            $tmpArr += $item
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3197 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5123 'Unknown requests')
                }
            }
        }
        #endregion

        #region RuleID = 271
        $RuleID = 271
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props

                    $itemprops | Where-Object {($_.PropertyName -eq 'DPMonEnabled') -and ($_.Value -eq 0)} | ForEach-Object {
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3196 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5124 'Content Validation')
                }
            }
        }
        #endregion

        #region RuleID = 272
        $RuleID = 272
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                    $itemprops | Where-Object {($_.PropertyName -eq 'DPMonEnabled') -and ($_.Value -eq 1)} | ForEach-Object {
                        $itemprops | Where-Object {($_.PropertyName -eq 'DPMonSchedule')} | ForEach-Object {
                            $Schedule = Convert-CMSchedule -ScheduleString $_.Value1
                            if ($null -ne $Schedule) {
                                $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                                if ($scheduleToMinutes -gt $Script:MaxDPContentValudationSchedule) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3123 @("Distribution Point $($RemoteComputer)", 'Content validation schedule', $item.SiteCode, $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5008 $Script:MaxDPContentValudationSchedule)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 273
        $RuleID = 273
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                    $itemprops | Where-Object {($_.PropertyName -eq 'DPMonEnabled') -and ($_.Value -eq 1)} | ForEach-Object {
                        $itemprops | Where-Object {($_.PropertyName -eq 'DPMonSchedule')} | ForEach-Object {
                            $Schedule = Convert-CMSchedule -ScheduleString $_.Value1
                            if ($null -ne $Schedule) {
                                $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                                if ($scheduleToMinutes -lt $Script:MinDPContentValudationSchedule) {
                                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3124 @("Distribution Point $($RemoteComputer)", 'Content validation schedule', $item.SiteCode, $scheduleToMinutes)) -Comment (Get-RFLHealthCheckRecommendation 5009 $Script:MinDPContentValudationSchedule)
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 274
        $RuleID = 274
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $DistributionPointList) {
                $DistributionPointList | ForEach-Object {
                    $item = $_
                    $itemprops = $item.Props

                    $itemprops | Where-Object {($_.PropertyName -eq 'DPMonPriority') -and ($_.Value -gt 6)} | ForEach-Object {
                        #4 = lowest (default), 5=low, 6=medium,7=high,8=highest
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3195 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5010 'Content Validation')
                }
            }
        }
        #endregion

        #region RuleID = 275 - Distribution Status
        $RuleID = 275
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $DistributionStatusList | where-object {($_.ObjectType -eq 258)} | ForEach-Object {
                $item = $_
                switch ($item.ObjectType) {
                    0 { $ObjectType = 'Package' }
                    3 { $ObjectType = 'Driver Package' }
                    4 { $ObjectType = 'Task Sequence' }
                    5 { $ObjectType = 'Software Updates' }
                    6 { $ObjectType = 'Device Settings' }
                    7 { $ObjectType = 'Content Package' }
                    257 { $ObjectType = 'Operating System Image' }
                    258 { $ObjectType = 'Boot Image' }
                    259 { $ObjectType = 'Operating System Installer' }
                    512 { $ObjectType = 'Application' }
                    default { $ObjectType = "Unknown - $($item.ObjectType)" }
                }

                ($BootList | where-object {($_.PackageID -eq $item.PackageID) -and ($_.DefaultImage -eq $true) -and ($item.Targeted -gt 0)}) | ForEach-Object {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3018 @($item.ObjectID, $item.SoftwareName, "Default $($objectType)", $item.Targeted)) -Comment (Get-RFLHealthCheckRecommendation 5035)
                }
            }
        }
        #endregion

        #region RuleID = 276
        $RuleID = 276
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $DistributionStatusList | where-object {($_.SoftwareName -notlike 'Microsoft Corporation Configuration Manager Easy Setup Package*') -and ($_.SoftwareName -notlike 'Microsoft Corporation Configuration Manager Client Piloting Package*') -and ($_.SoftwareName -notlike 'Microsoft Corporation Configuration Manager Client Piloting Upgrade Package*') -and ($_.ObjectType -ne 258) -and ($_.Targeted -eq 0)} | Group-Object ObjectType  | ForEach-Object {
                $item = $_
                switch ([int]$item.Name) {
                    0 { $ObjectType = 'Package' }
                    3 { $ObjectType = 'Driver Package' }
                    4 { $ObjectType = 'Task Sequence' }
                    5 { $ObjectType = 'Software Updates' }
                    6 { $ObjectType = 'Device Settings' }
                    7 { $ObjectType = 'Content Package' }
                    257 { $ObjectType = 'Operating System Image' }
                    258 { $ObjectType = 'Boot Image' }
                    259 { $ObjectType = 'Operating System Installer' }
                    512 { $ObjectType = 'Application' }
                    default { $ObjectType = "Unknown - $($item.ObjectType)" }
                }
                $strArray = (($item.Group | select-Object SoftwareName -unique) | Foreach {"'$($_.SoftwareName.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Group.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3169 @($item.Group.Count, $objectType, '0', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5057)
            }
        }
        #endregion

        #region RuleID = 277
        $RuleID = 277
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $DistributionStatusList | where-object {($_.NumberErrors -gt 0)} | Group-Object ObjectType,NumberErrors | ForEach-Object {
                $item = $_
                $itemArray = $item.Name.Split(',').Trim()
                switch ($itemArray[0]) {
                    0 { $ObjectType = 'Package' }
                    3 { $ObjectType = 'Driver Package' }
                    4 { $ObjectType = 'Task Sequence' }
                    5 { $ObjectType = 'Software Updates' }
                    6 { $ObjectType = 'Device Settings' }
                    7 { $ObjectType = 'Content Package' }
                    257 { $ObjectType = 'Operating System Image' }
                    258 { $ObjectType = 'Boot Image' }
                    259 { $ObjectType = 'Operating System Installer' }
                    512 { $ObjectType = 'Application' }
                    default { $ObjectType = "Unknown - $($itemArray[0])" }
                }
                $strArray = (($item.Group | select-Object SoftwareName -unique) | Foreach {"'$($_.SoftwareName.Trim())'"}) -join ' '

                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Group.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3170 @($item.Group.Count, $objectType, $itemArray[1], $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5058)
            }
        }
        #endregion

        #region RuleID = 278 - Application
        $RuleID = 278
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ApplicationList | where-object {$_.IsHidden -eq $true} | Group-Object IsHidden | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Group.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3171 @($item.Group.Count, 'Application', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5071)
            }
        }
        #endregion

        #region RuleID = 279
        $RuleID = 279
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ApplicationList | where-object {$_.NumberOfDevicesWithFailure -gt 0} | ForEach-Object {
                $item = $_
                $FailurePercentage = [math]::Round([int]$item.NumberOfDevicesWithFailure * 100 / [int]$ManagedDeviceCount)
                if ($FailurePercentage -ge $Script:ApplicationFailurePercentageError) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3019 @($item.LocalizedDisplayName, $item.NumberOfDevicesWithFailure, 'devices')) -Comment (Get-RFLHealthCheckRecommendation 5060)
                }
            }
        }
        #endregion

        #region RuleID = 280
        $RuleID = 280
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ApplicationList | where-object {$_.NumberOfDevicesWithFailure -gt 0} | ForEach-Object {
                $item = $_
                $FailurePercentage = [math]::Round([int]$item.NumberOfDevicesWithFailure * 100 / [int]$ManagedDeviceCount)
                if (($FailurePercentage -ge $Script:ApplicationFailurePercentageWarning) -and ($FailurePercentage -lt $Script:ApplicationFailurePercentageError)) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3019 @($item.LocalizedDisplayName, $item.NumberOfDevicesWithFailure, 'devices')) -Comment (Get-RFLHealthCheckRecommendation 5060)
                }
            }
        }
        #endregion

        #region RuleID = 281
        $RuleID = 281
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ApplicationList | where-object {$_.NumberOfUsersWithFailure -gt 0} | ForEach-Object {
                $item = $_
                $FailurePercentage = [math]::Round([int]$item.NumberOfUsersWithFailure * 100 / [int]$ManagedDeviceCount)
                if ($FailurePercentage -ge $Script:ApplicationFailurePercentageError) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3019 @($item.LocalizedDisplayName, $item.NumberOfDevicesWithFailure, 'user''s machine')) -Comment (Get-RFLHealthCheckRecommendation 5060)
                }
            }
        }
        #endregion

        #region RuleID = 282
        $RuleID = 282
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ApplicationList | ForEach-Object {
                $item = $_
                if ($item.NumberOfUsersWithFailure -gt 0) {
                    $FailurePercentage = [math]::Round([int]$item.NumberOfUsersWithFailure * 100 / [int]$ManagedDeviceCount)
                    if (($FailurePercentage -ge $Script:ApplicationFailurePercentageWarning) -and ($FailurePercentage -lt $Script:ApplicationFailurePercentageError)) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3019 @($item.LocalizedDisplayName, $item.NumberOfDevicesWithFailure, 'user''s machine')) -Comment (Get-RFLHealthCheckRecommendation 5060)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 283
        $RuleID = 283
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $ApplicationList) {
                $tmpArr += $ApplicationList | where-object {($_.NumberOfDeployments -lt 1) -and ($_.NumberOfDependentDTs -lt 1) -and ($_.NumberOfDependentTS -lt 1)}
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object LocalizedDisplayName,ModelName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim()) ($($_.ModelName.Trim()))'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3208 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5081 'Application')
            }
        }
        #endregion

        #region RuleID = 284
        $RuleID = 284
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $ApplicationList) {
                $ApplicationList | Where-Object {($_.NumberOfDeployments -lt 1) -and ($_.NumberOfDependentDTs -lt 1)} | ForEach-Object {
                    $bGenerateHealthCheckData = $false
                    $item = $_

                    $TSReferenceList = ($TaskSequenceReferenceList | Where-Object {$_.Content.ObjectID -eq $item.ModelName})
                    $TSReferenceListCount = ($TSReferenceList | Measure-Object).Count

                    if ($TSReferenceListCount -ne 0) {
                        $TSReferenceList | ForEach-Object {
                            $subItem = $_

                            $PkgInDeployedTSCount = ($DeploymentList | where-Object {($_.SoftwareName -eq $subItem.ts.Name) -and ($_.FeatureType -eq 7)} | Measure-Object).Count
                            if ($PkgInDeployedTSCount -le 0) {
                                $bGenerateHealthCheckData = $true
                            }
                        }
                    }
                    if ($bGenerateHealthCheckData) {
                        $tmpArr += $item
                    }
                }
            }
            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object LocalizedDisplayName,ModelName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim()) ($($_.ModelName.Trim()))'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3209 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5081 'Application')
            }
        }
        #endregion

        #region RuleID = 285
        $RuleID = 285
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLServerInformationList | where-object {$_.NOSMSONData -eq $false} | ForEach-Object {
                $item = $_
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3136 @($item.SiteCode, $item.ServerName, 'SQL Data')) -Comment (Get-RFLHealthCheckRecommendation 5103)
            }

            $SQLServerInformationList | where-object {$_.NOSMSONLog -eq $false} | ForEach-Object {
                $item = $_
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3136 @($item.SiteCode, $item.ServerName, 'SQL Logs')) -Comment (Get-RFLHealthCheckRecommendation 5103)
            }

        }
        #endregion

        #region RuleID = 286
        $RuleID = 286
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $PathDTInformationList | where-object {$_.Exist -eq $false} | Group-Object UserName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Folder,Application,DTName -unique) | Foreach {"'Application: $($_.Application), Deployment Type: $($_.DTName), Folder: $($_.Folder.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3223 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5073)
            }
        }
        #endregion

        #region RuleID = 287
        $RuleID = 287
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $ApplicationList | ForEach-Object {
                $item = $_
                $DeploymentTypeList | Where-Object {$_.AppModelName -eq $item.ModelName} | ForEach-Object {
                    $subItem = $_
                    if (-not [string]::IsNullOrEmpty($subItem.SDMPackageXML)) {
                        $subitemxml = [xml]$subItem.SDMPackageXML

                        $subitemxml.AppMgmtDigest.DeploymentType | ForEach-Object {
                            $tmpItem = $_

                            $DTexecutionContext = ($tmpItem.Installer.InstallAction.Args.Arg | Where-Object {$_.Name -eq 'ExecutionContext'}).'#text'
                            $DTRequiresUserInteraction = ($tmpItem.Installer.InstallAction.Args.Arg | Where-Object {$_.Name -eq 'RequiresUserInteraction'}).'#text'

                            if ($DTRequiresUserInteraction -eq $true) {
                                $tmpArr += New-Object -TypeName PSObject -Property @{'ItemName' = $item.LocalizedDisplayName; 'SubItemName' = $subItem.LocalizedDisplayName; 'DTExecutionContext' = $DTexecutionContext;  }
                            }
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object ItemName,SubItemName,DTExecutionContext -unique) | Foreach {"'Application $($_.ItemName.Trim()) - (Deployment Type $($_.SubItemName.Trim())) - (Execution Context $($_.DTExecutionContext.Trim()))'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3239 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5074)
            }
        }
        #endregion

        #region RuleID = 288 - Distribution Point Content - Not on DP Group
        $RuleID = 288
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $DPContentList | Select-Object Name,ObjectID -Unique | ForEach-Object {
                $item = $_
                $DPContentOnGroupCount = ($DPGroupContentList | Where-Object {$_.ObjectID -eq $item.ObjectID} | Measure-Object).Count
                if ($DPContentOnGroupCount -eq 0) {
                    if ($item.Name -notin $Script:HiddenPackages) {
                        $tmpArr += $item
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3189 @($tmpArr.Count, 'content', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5122)
            }
        }
        #endregion

        #region RuleID = 289
        $RuleID = 289
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $DPContentList | Select-Object Name,ObjectID -Unique | ForEach-Object {
                $item = $_
                $DPContentOnGroupCount = ($DPGroupContentList | Where-Object {$_.ObjectID -eq $item.ObjectID} | Measure-Object).Count
                if (($DPContentOnGroupCount -ne 0) -and ($DPContentOnGroupCount -ne $DPGroupList.Count)) {
                    $tmpArr += $item
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3188 @($tmpArr.Count, 'content', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5122)
            }
        }
        #endregion

        #region RuleID = 290 - Packages
        $RuleID = 290
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $PathPkgInformationList | where-object {$_.Exist -eq $false} | Group-Object UserName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Folder -unique) | Foreach {"'$($_.Folder.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3223 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5073)
            }
        }
        #endregion

        #region RuleID = 291
        $RuleID = 291
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $PackageList | where-object {($_.Name -notin $Script:HiddenPackages) -and ($_.DefaultImageFlags -ne 2) -and (-not [string]::IsNullOrEmpty($_.PkgSourcePath))} | ForEach-Object {#2=USMT package
                $Item = $_
                if ($Item.PkgSourcePath.Substring(0,1) -ne '\') {
                    $tmpArr += $item
                }
            }
            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name,PackageID -unique) | Foreach {"'$($_.Name.Trim()) ($($_.PackageID.Trim()))'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3215 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5081 'Package')
            }
        }
        #endregion

        #region RuleID = 292
        $RuleID = 292
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $PackageList | where-object {($_.Name -notin $Script:HiddenPackages) -and ($_.DefaultImageFlags -ne 2)} | ForEach-Object {#2=USMT package
                $Item = $_
                $DeploymentfilterCount = ($DeploymentList | Where-Object {$_.PackageID -eq $item.PackageID} | Measure-Object).Count

                if ($DeploymentfilterCount -le 0) {
                    $TSReferenceList = ($TaskSequenceReferenceList | Where-Object {$_.Content.PackageID -eq $item.PackageID})
                    $TSReferenceListCount = ($TSReferenceList | Measure-Object).Count
                    if ($TSReferenceListCount -eq 0) {
                        $tmpArr += $item
                    }
                }
            }
            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name,PackageID -unique) | Foreach {"'$($_.Name.Trim()) ($($_.PackageID.Trim()))'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3214 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5081 'Package')
            }
        }
        #endregion

        #region RuleID = 293
        $RuleID = 293
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $PackageList | where-object {($_.Name -notin $Script:HiddenPackages) -and ($_.DefaultImageFlags -ne 2)} | ForEach-Object { #2=USMT package
                $ReportHealthCheck = $false
                $Item = $_
                $DeploymentfilterCount = ($DeploymentList | Where-Object {$_.PackageID -eq $item.PackageID} | Measure-Object).Count
                $TSReferenceList = ($TaskSequenceReferenceList | Where-Object {$_.Content.PackageID -eq $item.PackageID})
                $TSReferenceListCount = ($TSReferenceList | Measure-Object).Count

                if ($DeploymentfilterCount -le 0) {
                    if ($TSReferenceListCount -ne 0) {
                        $TSReferenceList | ForEach-Object {
                            $subItem = $_

                            $PkgInDeployedTSCount = ($DeploymentList | where-Object {($_.SoftwareName -eq $subItem.ts.Name) -and ($_.FeatureType -eq 7)} | Measure-Object).Count
                            if ($PkgInDeployedTSCount -le 0) {
                                $ReportHealthCheck = $true
                            }
                        }
                    }
                }

                if ($ReportHealthCheck -eq $true) {
                    $tmpArr += $item
                }
            }
            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name,PackageID -unique) | Foreach {"'$($_.Name.Trim()) ($($_.PackageID.Trim()))'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3213 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5081 'Package')
            }
        }
        #endregion

        #region RuleID = 294 - Operating System
        $RuleID = 294
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $PathOSImgInformationList | where-object {$_.Exist -eq $false} | Group-Object UserName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Folder -unique) | Foreach {"'$($_.Folder.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3223 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5073)
            }
        }
        #endregion

        #region RuleID = 295
        $RuleID = 295
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $OperatingSystemImageList) {
                $tmpArr = @()
                $OperatingSystemImageList | ForEach-Object {
                    $item = $_
                    $refcount = ($TaskSequenceReferenceList | Where-Object {$_.Content.PackageID -eq $item.PackageID} | Measure-Object).Count
                    if ($refCount -eq 0) {
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3182 @($tmpArr.Count, 'Operating System Image', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5138 'Operating System Image')
                }
            }
        }
        #endregion

        #region RuleID = 296 - Operating System Installer
        $RuleID = 296
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $PathOSInstallerInformationList | where-object {$_.Exist -eq $false} | Group-Object UserName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Folder -unique) | Foreach {"'$($_.Folder.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3223 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5073)
            }
        }
        #endregion

        #region RuleID = 297
        $RuleID = 297
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $OperatingSystemInstallerList) {
                $tmpArr = @()
                $OperatingSystemInstallerList | ForEach-Object {
                    $Item = $_
                    $refcount = ($TaskSequenceReferenceList | Where-Object {$_.Content.PackageID -eq $item.PackageID} | Measure-Object).Count
                    if ($refCount -eq 0) {
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3182 @($tmpArr.Count, 'Operating System Installer', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5052 'Operating System Installer')
                }
            }
        }
        #endregion

        #region RuleID = 298 - Task Sequence
        $RuleID = 298
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $TaskSequenceList | ForEach-Object {
                $item = $_
                #does not work on 1706 the Enabled property is always empty
                if ($item.Enabled -eq $false) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3100 @('Task Sequence', $item.Name, $item.PackageID)) -Comment (Get-RFLHealthCheckRecommendation 5076 @('Task Sequence', 'enabled'))
                }
            }
        }
        #endregion

        #region RuleID = 299
        $RuleID = 299
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $TaskSequenceList) {
                $tmpArr = @()
                $TaskSequenceList | ForEach-Object {
                    $item = $_
                    #check if it does have any deployment
                    $DeploymentCount = ($DeploymentList | where-Object {($_.SoftwareName -eq $item.Name) -and ($_.FeatureType -eq 7)} | Measure-Object).Count
                    if ($DeploymentCount -lt 1) {
                        $tmpArr += $item
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3234 @($tmpArr.Count, 'Task Sequence', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5096 'Task Sequence')
                }
            }
        }
        #endregion

        #region RuleID = 300
        $RuleID = 300
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $TaskSequenceList | where-object {[string]::IsNullOrEmpty($_.BootImageID)} | ForEach-Object {
                $item = $_
                $RebootToPXECount = ($TaskSequenceRebootOptions | Where-Object {$_.Name -eq $item.Name} | Measure-Object).Count
                if ($RebootToPXECount -gt 0) {
                    $tmpArr += $item
                }
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3254 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5041)
            }
        }
        #endregion

        #region RuleID = 301
        $RuleID = 301
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $TaskSequenceList | ForEach-Object {
                $item = $_
                #boot images
                $TaskSequenceReferenceList | Where-Object {($_.content.ObjectType -eq 258) -and ($_.ts.PackageID -eq $item.PackageID) } | ForEach-Object {
                    $refitem = $_
                    if (($BootList | Where-Object {$_.PackageID -eq $refitem.PackageID}).DefaultImage -eq $true) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3101 @($item.Name, $item.PackageID, $refitem.content.SoftwareName, $refitem.content.PackageID)) -Comment (Get-RFLHealthCheckRecommendation 5035)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 302
        $RuleID = 302
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $TaskSequenceList | ForEach-Object {
                $item = $_
                $TaskSequenceReferenceList | Where-Object {$_.ts.PackageID -eq $item.PackageID } | ForEach-Object {
                    $refitem = $_
                    if ($refitem.content.Targeted -eq 0) {
                        $tmpArr += New-Object -TypeName PSObject -Property @{'Name' = $item.Name; 'PackageID' = $item.PackageID; 'RefItemName' = $refitem.content.SoftwareName; 'RefPkgID' =  $refitem.content.PackageID; }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $tmpArr | Group-Object PackageID | ForEach-Object {
                    $tmpArrItem = $_
                    
                    $strArray = (($tmpArrItem.Group | select-Object RefItemName,RefPkgID -unique) | Foreach {"'$($_.RefPkgID.Trim()) - $($_.RefItemName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArrItem.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3240 @($tmpArrItem.Group[0].Name, $tmpArrItem.Name, $tmpArrItem.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5057)
                }
            }
        }
        #endregion

        #region RuleID = 303
        $RuleID = 303
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $TaskSequenceList | ForEach-Object {
                $item = $_
                $TaskSequenceReferenceList | Where-Object {$_.ts.PackageID -eq $item.PackageID } | ForEach-Object {
                    $refitem = $_
                    if ($efitem.content.NumberErrors -gt 0) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3099 @($item.Name, $item.PackageID, $refitem.content.SoftwareName, $refitem.content.PackageID)) -Comment (Get-RFLHealthCheckRecommendation 5058)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 304 - inbox
        $RuleID = 304
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $inboxList | Where-Object {$_.FolderCount -ge $script:InboxFolderCountError} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object FolderPath -unique) | Foreach {"'$($_.FolderPath.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3224 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5080)
            }
        }
        #endregion

        #region RuleID = 305
        $RuleID = 305
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $inboxList | Where-Object {($_.FolderCount -lt $script:InboxFolderCountError) -and ($_.FolderCount -ge $script:InboxFolderCountWarning)} | Group-Object SiteCode | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object FolderPath -unique) | Foreach {"'$($_.FolderPath.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3224 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5080)
            }
        }
        #endregion

        #region RuleID = 306 - Driver Package
        $RuleID = 306
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $DriverPackageFilterCount = ($DriverPackageList | Measure-Object).Count
            if ($DriverPackageFilterCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($DriverPackageFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3126 @($DriverPackageFilterCount)) -Comment (Get-RFLHealthCheckRecommendation 5082)
            }
        }
        #endregion

        #region RuleID = 307 - Component Status (Summarizer)
        $RuleID = 307
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $ComponentSummarizerList | Where-Object {$_.Status -gt 0}  | Group-Object Status,MachineName | ForEach-Object {
                $item = $_
                $StatusName = "warning"
                $computerName = ($item.Name.split(',').trim())[1]
                if (($item.Name.split(',').trim())[0] -eq 2) { #warning
                    $StatusName = "critical"
                }
                $strArray = (($item.Group | select-Object ComponentName -unique) | Foreach {"'$($_.ComponentName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3212 @($item.Count, $ComputerName, $StatusName, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5098)
            }
        }
        #endregion

        #region RuleID = 308 - Component Message List
        $RuleID = 308
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($null -ne $ComponentStatusMessageCompletedList) {
                $ComponentStatusMessageCompletedList | ForEach-Object {
                    $item = $_
                    $Resolution = Get-RFLHealthCheckRecommendation ([int]"99$($item.MessageID)")                    
                    
                    if ($Resolution.IndexOf("Unknown Recommendation with message ID") -ge 0) {
                        $Resolution = $item.Resolution
                    }
                    if ([String]::IsNullOrEmpty($Resolution)) {
                        $Resolution = "Unknown Recommendation with message ID $($item.MessageID)"
                    }
                    
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.ItemCount)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3274 @($item.ItemCount, $item.MessageID, $item.Component, $item.Message)) -Comment ($Resolution.ToString())
                }
            }
        }
        #endregion

        #region RuleID = 309
        $RuleID = 309
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ItemName -eq 'Client Properties')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'DDR Refresh Interval'}).Value2)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Enable Heartbeat DDR'}).Value) -eq 1) {
                            if ($scheduleToMinutes -gt $Script:DDRMaxScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Heartbeat Discovery schedule', $scheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:DDRMinScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 310
        $RuleID = 310
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            foreach ($item in ($SiteList | Select-Object SiteCode | Get-Unique -AsString)) {
                foreach ($itemDiscovery in ($DiscoveryMethodList | where-object {($_.SiteCode -eq $item.SiteCode) -and ($_.ComponentName -eq 'SMS_AD_FOREST_DISCOVERY_MANAGER')})) {
                    $Schedule = Convert-CMSchedule -ScheduleString "$(($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'Startup Schedule'}).Value1)"
                    if ($null -ne $Schedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule

                        if ((($itemDiscovery.Props | Where-Object {$_.PropertyName -eq 'SETTINGS'}).Value1) -eq 'ACTIVE') {
                            if ($scheduleToMinutes -gt $Script:ForestDiscoveryMaxScheduleInMinutes) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3002 @('Forest Discovery schedule', $scheduleToMinutes, $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5008 $script:ForestDiscoveryMinScheduleInMinutes)
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 311 - Check if SQL is running 2016 SP1 instead of SP2
        $RuleID = 311
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SQLConfigurationList) {
                $SQLConfigurationList | ForEach-Object {
                    $item = $_

                    if (([version]$item.Version).Major -eq 13) { #sql server 2016
                        if (([version]$item.Version).Build -lt 5026) { #build lower than SP2 - https://sqlserverbuilds.blogspot.com/
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3134 @($item.ServerName, '2016', 'SP2')) -Comment (Get-RFLHealthCheckRecommendation 5101 @('2016', 'SP1', 'SP2'))
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 312 - Check if WSUS is running on WID
        $RuleID = 312
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SUPWIDList) {
                $SUPWIDList | ForEach-Object {
                    $item = $_
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3135 @($item.SiteCode, $item.ServerName)) -Comment (Get-RFLHealthCheckRecommendation 5102)
                }
            }
        }
        #endregion

        #region RuleID = 313 - check NO_SMS_ON_DRIVE.SMS on SystemDrive
        $RuleID = 313
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $ServerNOSMSONDriveInformation) {
                $ServerNOSMSONDriveInformation | Where-Object {$_.FileExist -eq $false} | Group-Object Folder | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3211 @($item.Count, $item.Name.replace('$',''), $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5103)
                }
            }
        }
        #endregion

        #region RuleID = 314 - Check if multiple WSUS running on same SQL
        $RuleID = 314
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SUPSQL) {
                $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    $item = $_
                    $SUPFilter = @()
                    $SUPFilter += ($SUPSQL | Where-Object {$_.SiteCode -eq $item.SiteCode})
                    if ($SUPFilter.Count -gt 1) {
                        $1StSQLServer = $SUPFilter[0].SQLServer

                        foreach ($subitem in $SUPFilter) {
                            if ($1StSQLServer.tolower() -ne $subitem.SQLServer) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3137 @($item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5104)
                                break
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 315 - Approval Request
        $RuleID = 315
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $ApprovalRequestList) {
                $ApprovalPendingCount = ($ApprovalRequestList | Where-Object {($_.LastModifiedDate -lt (Get-Date).AddDays(([int]$script:MaxApprovalRequestDate)*-1)) -and ($_.CurrentState -eq 1)} | Measure-Object).Count
                if ($ApprovalPendingCount -gt 0)
                {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3138 @($ApprovalPendingCount, $Script:MaxApprovalRequestDate)) -Comment (Get-RFLHealthCheckRecommendation 5105)
                }
            }
        }
        #endregion

        #region RuleID = 316
        $RuleID = 316
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $AutoUpgradeConfigs | ForEach-Object {
                if ($_.IsUpgradeExclusionEnabled -eq $true) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3139 @('Exclude specified clients from update', 'enabled')) -Comment (Get-RFLHealthCheckRecommendation 5106)
                }
            }
        }
        #endregion

        #region RuleID = 317
        $RuleID = 317
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $AutoUpgradeConfigs | ForEach-Object {
                if (($_.IsProgramEnabled -eq $true) -and ($_.ExcludeServers -eq $false)) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3139 @('Do not upgrade servers', 'disabled')) -Comment (Get-RFLHealthCheckRecommendation 5107)
                }
            }
        }
        #endregion

        #region RuleID = 318
        $RuleID = 318
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $AutoUpgradeConfigs | ForEach-Object {
                if ($_.AllowPrestage -eq $true) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3139 @('Automatically distribute client installation package to distribution points that are enabled for prestaged content', 'enabled')) -Comment (Get-RFLHealthCheckRecommendation 5108)
                }
            }
        }
        #endregion

        #region RuleID = 319
        $RuleID = 319
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if (($null -ne $SiteList) -and ($null -ne $SiteComponentManagerList)) {
                $tmpArr = @()
                $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    $item = $_
                    $SUPComponentSyncManager | where-object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                        $subitem = $_

                        $deviceListCount = ($DeviceList | Where-Object {$_.DeviceOS -like 'Microsoft Windows*Workstation*10.*'} | Measure-Object).Count
                        if ($deviceListCount -gt 0) {
                            $subitem.Props | Where-Object {($_.PropertyName -eq 'Sync ExpressFiles') -and ($_.Value -eq 0)} | ForEach-Object {
                                $tmpArr += $subitem
                            }
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3236 @($tmpArr.Count, 'Software Update - Download both full for all approved updates and express installation files for Windows 10', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5150)
                }
            }
        }
        #endregion

        #region RuleID = 320
        $RuleID = 320
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if (($null -ne $SiteList) -and ($null -ne $SiteComponentManagerList)) {
                $tmpArr = @()
                $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    $item = $_
                    $SUPComponent | where-object {$_.SiteCode -eq $item.SiteCode} | ForEach-Object {
                        $subitem = $_

                        $subitem.Props | Where-Object {($_.PropertyName -eq 'Call WSUS Cleanup') -and ($_.Value -eq $false)} | ForEach-Object {
                            $tmpArr += $subitem
                        }

                    }
                }
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3236 @($tmpArr.Count, 'Software Update - Run WSUS cleanup after synchronization', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5109)
                }
            }
        }
        #endregion

        #region RuleID = 321
        $RuleID = 321
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $AlertList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $AlertCount = ($AlertList | Where-Object {($_.TypeId -in (19)) -and ($_.TypeInstanceID -eq $item.SiteCode)} | Measure-Object).Count
                    if ($AlertCount -lt 1) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3140 @($item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5090 'Alerts for Software Update Point synchronisation alert')
                    }
                }
            }
        }
        #endregion

        #region RuleID = 322
        $RuleID = 322
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SiteComponentList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $cpt = $SiteComponentList | Where-Object {($_.ItemName -like "SMS_SITE_COMPONENT_MANAGER|*") -and ($_.SiteCode -eq $item.SiteCode)}
                    $cpt.Props | Where-Object {($_.PropertyName -eq 'Registration HardwareID Conflict Resolution') -and ($_.Value -eq 1)} | ForEach-Object {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3141 @($item.SiteCode, 'Conflict Records resolution ', 'Manually resolve conflicting records')) -Comment (Get-RFLHealthCheckRecommendation 5110)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 323
        $RuleID = 323
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SiteComponentList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $cpt = $SiteComponentList | Where-Object {($_.ItemName -like "SMS_SITE_COMPONENT_MANAGER|*") -and ($_.SiteCode -eq $item.SiteCode)}
                    $cpt.Props | Where-Object {($_.PropertyName -eq 'Auto Approval') -and ($_.Value -eq 0)} | ForEach-Object {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3141 @($item.SiteCode, 'Client approval method', 'Manually approve each computer')) -Comment (Get-RFLHealthCheckRecommendation 5111)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 324
        $RuleID = 324
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SiteComponentList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $cpt = $SiteComponentList | Where-Object {($_.ItemName -like "SMS_SITE_COMPONENT_MANAGER|*") -and ($_.SiteCode -eq $item.SiteCode)}
                    $cpt.Props | Where-Object {($_.PropertyName -eq 'Auto Approval') -and ($_.Value -eq 2)} | ForEach-Object {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3141 @($item.SiteCode, 'Client approval method', 'Automatically approve all computers (not recommended)')) -Comment (Get-RFLHealthCheckRecommendation 5111)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 325
        $RuleID = 325
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SiteDefinition)) {
                $tmpArr = @()
                $SiteList | ForEach-Object {
                    $item = $_
                    $cpt = $SiteDefinition | Where-Object {($_.SiteCode -eq $item.SiteCode)}
                    $cpt.Props | Where-Object {($_.PropertyName -eq 'TwoKeyApproval') -and ($_.Value -eq 0)} | ForEach-Object {
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3291 @($tmpArr.Count, 'Script authors require additional script approver', 'disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5112)
                }
            }
        }
        #endregion

        #region RuleID = 326
        $RuleID = 326
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $SiteDefinition)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $cpt = $SiteDefinition | Where-Object {($_.SiteCode -eq $item.SiteCode)}
                    $cpt.Props | Where-Object {($_.PropertyName -eq 'PreferMPInBoundaryWithFastNetwork') -and ($_.Value -eq 0)} | ForEach-Object {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3001 @('Clients prefer to use management point specified in boundary group', $item.SiteCode)) -Comment (Get-RFLHealthCheckRecommendation 5113)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 327
        $RuleID = 327
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareVersionList) {
                $SoftwareVersionList | where-object {($_.Name -notlike '*Preinstallation Environment Add-ons*') -and ($_.Name -like 'Windows Assessment and Deployment Kit*')} | ForEach-Object {
                    $item = $_
                    if ($item.version -lt $Script:MinInstalledADKVersion) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3142 @('Windows Assessment and Deployment Kit (ADK)', $item.version)) -Comment (Get-RFLHealthCheckRecommendation 5114 @($Script:MinInstalledADKVersion, $Script:MinInstalledADKVersionYMFormat))
                    }
                }
            }
        }
        #endregion

        #region RuleID = 328
        $RuleID = 328
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SoftwareVersionList) {
                $SoftwareVersionList | where-object {$_.Name -like 'Microsoft Deployment Toolkit*'} | ForEach-Object {
                    $item = $_
                    if ($item.version -lt $Script:MinMDTVersion) {
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3142 @('Microsoft Deployment Toolkit (MDT)', $item.version)) -Comment (Get-RFLHealthCheckRecommendation 5115 @($Script:MinMDTVersion))
                    }
                }
            }
        }
        #endregion

        #region RuleID = 329
        $RuleID = 329
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $ServiceList) {
                $ServiceList | where-object {$_.ServerName -eq $item.NetworkOSPath} | ForEach-Object {
                    $item = $_

                    switch ($item.Name.ToUpper()) {
                        {($_ -eq "CCMEXEC") -or ($_ -eq "SMS_EXECUTIVE") -or ($_ -eq "SMS_SITE_COMPONENT_MANAGER") -or ($_ -eq "SMS_SITE_SQL_BACKUP") -or ($_ -eq "SMS_SITE_VSS_WRITER") -or ($_ -eq "AI_UPDATE_SERVICE_POINT") -or ($_ -eq "W3SVC") -or ($_ -eq "WsusService") -or ($_ -eq "IISADMIN") -or ($_ -eq "CONFIGURATION_MANAGER_UPDATE") -or ($_ -eq "DATA_WAREHOUSE_SERVICE_POINT")} {
                            if (($item.StartMode -ne 'Auto') -or ($item.Started -ne $true)) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3143 @($item.Name, $item.StartMode, $item.State)) -Comment (Get-RFLHealthCheckRecommendation 5116 @($item.Name, $item.Caption, 'Auto', 'Running'))
                            }
                        }
                        {($_ -eq "SMS_NOTIFICATION_SERVER") -or ($_ -eq "SMS_SITE_BACKUP")} {
                            if (($subitem.StartMode -ne 'Manual')) {
                                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3143 @($item.Name, $item.StartMode, $item.State)) -Comment (Get-RFLHealthCheckRecommendation 5117 @($item.Name, $item.Caption, 'Manual'))
                            }
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 330
        $RuleID = 330
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $UserCollectionFilterCount = ($UserCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            $DeviceCollectionFilterCount = ($DeviceCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            $TotalCollectionFilterCount = $UserCollectionFilterCount + $DeviceCollectionFilterCount
            if (($TotalCollectionFilterCount -gt $script:MaxCollectionIncrementalUpdateWarning) -and ($TotalCollectionFilterCount -lt $script:MaxCollectionIncrementalUpdateError)) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($TotalCollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3032 @($TotalCollectionFilterCount, 'total')) -Comment (Get-RFLHealthCheckRecommendation 5018 $script:MaxCollectionIncrementalUpdateError)
            }
        }
        #endregion

        #region RuleID = 331
        $RuleID = 331
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $UserCollectionFilterCount = ($UserCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            $DeviceCollectionFilterCount = ($DeviceCollectionList | Where-Object {$_.RefreshType -in (4,6)} | Measure-Object).Count
            $TotalCollectionFilterCount = $UserCollectionFilterCount + $DeviceCollectionFilterCount
            if ($TotalCollectionFilterCount -gt $script:MaxCollectionIncrementalUpdateError) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($TotalCollectionFilterCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3032 @($TotalCollectionFilterCount, 'total')) -Comment (Get-RFLHealthCheckRecommendation 5018 $script:MaxCollectionIncrementalUpdateError)
            }
        }
        #endregion

        #region RuleID = 332
        $RuleID = 332
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($null -ne $DistributionStatusList) {
                $DistributionStatusList | Where-Object {($_.SoftwareName -notlike 'Microsoft Corporation Configuration Manager Client*') -and ($_.NumberInProgress -gt 0) -and ((Get-Date).AddDays(-$Script:MaxDistributionInProgressWarning) -ge $_.LastUpdateDate) -and ((Get-Date).AddDays(-$Script:MaxDistributionInProgressError)) -lt $_.LastUpdateDate} | Group-Object ObjectType | ForEach-Object {
                    $item = $_
                    switch ($item.Name) {
                        0 { $ObjectType = 'Package' }
                        3 { $ObjectType = 'Driver Package' }
                        4 { $ObjectType = 'Task Sequence' }
                        5 { $ObjectType = 'Software Updates' }
                        6 { $ObjectType = 'Device Settings' }
                        7 { $ObjectType = 'Content Package' }
                        257 { $ObjectType = 'Operating System Image' }
                        258 { $ObjectType = 'Boot Image' }
                        259 { $ObjectType = 'Operating System Installer' }
                        512 { $ObjectType = 'Application' }
                        default { $ObjectType = "Unknownn - $($item.ObjectType)" }
                    }

                    $strArray = (($item.Group | select-Object SoftwareName -unique) | Foreach {"'$($_.SoftwareName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3225 @($item.Count, $objectType, $Script:MaxDistributionInProgressWarning, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5118 @($Script:MaxDistributionInProgressWarning))
                }
            }
        }
        #endregion

        #region RuleID = 333
        $RuleID = 333
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if ($null -ne $DistributionStatusList) {
                $DistributionStatusList | Where-Object {($_.SoftwareName -notlike 'Microsoft Corporation Configuration Manager Client*') -and ($_.NumberInProgress -gt 0) -and ((Get-Date).AddDays(-$Script:MaxDistributionInProgressError)) -ge $_.LastUpdateDate} | Group-Object ObjectType | ForEach-Object {
                    $item = $_
                    switch ($item.Name) {
                        0 { $ObjectType = 'Package' }
                        3 { $ObjectType = 'Driver Package' }
                        4 { $ObjectType = 'Task Sequence' }
                        5 { $ObjectType = 'Software Updates' }
                        6 { $ObjectType = 'Device Settings' }
                        7 { $ObjectType = 'Content Package' }
                        257 { $ObjectType = 'Operating System Image' }
                        258 { $ObjectType = 'Boot Image' }
                        259 { $ObjectType = 'Operating System Installer' }
                        512 { $ObjectType = 'Application' }
                        default { $ObjectType = "Unknown - $($item.ObjectType)" }
                    }
                    $strArray = (($item.Group | select-Object SoftwareName -unique) | Foreach {"'$($_.SoftwareName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3225 @($item.Count, $objectType, $Script:MaxDistributionInProgressError, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5118 @($Script:MaxDistributionInProgressWarning))
                }
            }
        }
        #endregion

        #region RuleID = 334
        $RuleID = 334
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if (($null -ne $SiteRoleList) -and ($null -ne $PingList)) {
                $tmpArr = @()
                $SiteRoleList | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                    $TotalSuccess = ($PingList | where-object {($_.Success -eq $true) -and ($_.Destination -eq $RemoteComputer)} | Measure-Object).Count
                    if ($TotalSuccess -gt 0) {
                        $Average = [int](($PingList | where-object {($_.Success -eq $true) -and ($_.Destination -eq $RemoteComputer)} | measure-Object -Property ResponseTime -Average).Average)
                        if (($Average -ge $script:MaxPingResponseTimeWarning) -and ($Average -lt $script:MaxPingResponseTimeError)) {
                            $tmpArr += $item
                        }
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3237 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5120)
                }
            }
        }
        #endregion

        #region RuleID = 335
        $RuleID = 335
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if (($null -ne $SiteRoleList) -and ($null -ne $PingList)) {
                $tmpArr = @()
                $SiteRoleList | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                    $TotalSuccess = ($PingList | where-object {($_.Success -eq $true) -and ($_.Destination -eq $RemoteComputer)} | Measure-Object).Count
                    if ($TotalSuccess -gt 0) {
                        $Average = [int](($PingList | where-object {($_.Success -eq $true) -and ($_.Destination -eq $RemoteComputer)} | measure-Object -Property ResponseTime -Average).Average)
                        if ($Average -ge $script:MaxPingResponseTimeError) {
                            $tmpArr += $item
                        }
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\','').Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3237 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5120)
                }

            }
        }

        #region RuleID = 336
        $RuleID = 336
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if (($null -ne $SiteRoleList) -and ($null -ne $PingList)) {
                $tmpArr = @()
                $SiteRoleList | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                    $Total = ($PingList | where-object {($_.Destination -eq $RemoteComputer)} | Measure-Object).Count
                    if ($Total -gt 0) {
                        $TotalSuccess = ($PingList | where-object {($_.Success -eq $false) -and ($_.Destination -eq $RemoteComputer)} | Measure-Object).Count
                        $TotalSuccessPercent = (($TotalSuccess / $Total)*100)

                        if (($TotalSuccessPercent -ge $script:MaxPingDropPercentWarning) -and ($TotalSuccessPercent -lt $script:MaxPingDropPercentError)) {
                            $tmpArr += $item
                        }
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\','').Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3226 @($item.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5121)
                }
            }
        }
        #endregion

        #region RuleID = 337
        $RuleID = 337
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if (($null -ne $SiteRoleList) -and ($null -ne $PingList)) {
                $tmpArr = @()
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))

                    $Total = ($PingList | where-object {($_.Destination -eq $RemoteComputer)} | Measure-Object).Count
                    if ($Total -gt 0) {
                        $TotalSuccess = ($PingList | where-object {($_.Success -eq $false) -and ($_.Destination -eq $RemoteComputer)} | Measure-Object).Count
                        $TotalSuccessPercent = (($TotalSuccess / $Total)*100)

                        if ($TotalSuccessPercent -ge $script:MaxPingDropPercentError) {
                            $tmpArr += $item
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object NetworkOSPath -unique) | Foreach {"'$($_.NetworkOSPath.Replace('\','').Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3226 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5121)
                }
            }
        }
        #endregion

        #region RuleID = 338
        $RuleID = 338
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $ApplicationList) {
                $tmpArr = @()
                $ApplicationList | ForEach-Object {
                    $item = $_
                    if ($item.NumberOfDeploymentTypes -lt 1) {
                        $tmpArr += $item
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3273 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5072)
                }
            }
        }
        #endregion

        #region RuleID = 339
        $RuleID = 339
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IntuneSubscription) {
                if ($IntuneSubscription.Count -ne 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3149) -Comment (Get-RFLHealthCheckRecommendation 5128)
                }
            }
        }
        #endregion

        #region RuleID = 340
        $RuleID = 340
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Boundary) {
                $BoundaryIPSubnetCount = ($Boundary | where-object {$_.BoundaryType -eq 0} | Measure-Object).Count
                if ($BoundaryIPSubnetCount -gt 1) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3150 @($BoundaryIPSubnetCount)) -Comment (Get-RFLHealthCheckRecommendation 5128)
                }
            }
        }
        #endregion

        #region RuleID = 341
        $RuleID = 341
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $DeviceCollectionList) {
                $tmpArr = @()
                $DeviceCollectionList | Where-Object {$_.RefreshType -in (2, 6)} | ForEach-Object {
                    $item = $_
                    if ($null -ne $item.RefreshSchedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $item.RefreshSchedule
                        if ($scheduleToMinutes -lt $script:MinScheduleInMinutes) {
                            $tmpArr += $item
                        }
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3227 @($tmpArr.Count, 'device', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5131 @($script:MinScheduleInMinutes))
                }
            }
        }
        #endregion

        #region RuleID = 342
        $RuleID = 342
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $UserCollectionList) {
                $tmpArr = @()
                $UserCollectionList | Where-Object {$_.RefreshType -in (2, 6)} | ForEach-Object {
                    $item = $_
                    if ($null -ne $item.RefreshSchedule) {
                        $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $item.RefreshSchedule
                        if ($scheduleToMinutes -lt $script:MinScheduleInMinutes) {
                            $tmpArr += $item
                        }
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3227 @($tmpArr.Count, 'user', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5131 @($script:MinScheduleInMinutes))
                }
            }
        }
        #endregion

        #region RuleID = 343
        $RuleID = 343
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $Boundary) {
                $Boundary | Where-Object {($_.GroupCount -eq 0) -and ($_.Value -ne 'Default-First-Site-Name')} | Group-Object GroupCount | ForEach-Object {
                    $item = $_
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    $strArray = (($item.Group | select-Object DisplayName -unique) | Foreach {"'$($_.DisplayName.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3235 @($item.Count, 'Boundary', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5132 @($script:MinScheduleInMinutes))
                }
            }
        }
        #endregion

        #region RuleID = 344
        $RuleID = 344
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $LogicalDiskInfoList) {
                $tmpArr = @()
                $LogicalDiskInfoList | where-object {($_.DriveType -eq 3) -and ($null -ne $_.Size)} | ForEach-Object {
                    $item = $_
                    if (([int]($item.Freespace*100/$item.Size) -le $script:FreeDiskSpacePercentageWarning) -and ([int]($item.Freespace*100/$item.Size) -gt $script:FreeDiskSpacePercentageError)) {
                        $tmpArr += $item
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3228 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5133)
                }
            }
        }
        #endregion

        #region RuleID = 345
        $RuleID = 345
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $LogicalDiskInfoList) {
                $tmpArr = @()
                $LogicalDiskInfoList | where-object {($_.DriveType -eq 3) -and ($null -ne $_.Size)} | ForEach-Object {
                    $item = $_
                    if (([int]($item.Freespace*100/$item.Size) -le $script:FreeDiskSpacePercentageError)) {
                        $tmpArr += $item
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3228 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5133)
                }
            }
        }
        #endregion

        #region RuleID = 346
        $RuleID = 346
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $ComputerInformationList)) {
                $tmpArr = @()
                $SiteList | ForEach-Object {
                    $item = $_
                    $ComputerInformationList | where-object {($_.ServerName -eq $item.ServerName) -and ([int]($_.TotalPhysicalMemory/1GB) -lt $script:MinimumSiteServerRAMGB)} | ForEach-Object {
                        $tmpArr += $item
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3229 @($tmpArr.Count, 'memory RAM', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5134 @('RAM memory', "$($script:MinimumSiteServerRAMGB)GB"))
                }
            }
        }
        #endregion

        #region RuleID = 347
        $RuleID = 347
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $ComputerInformationList)) {
                $tmpArr = @()
                $SiteList | ForEach-Object {
                    $item = $_
                    $ComputerInformationList | where-object {($_.ServerName -eq $item.ServerName) -and ([int]($_.NumberOfLogicalProcessors) -lt $script:MinimumSiteServerCPUCore)} | ForEach-Object {
                        $tmpArr += $item
                    }
                }
                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3229 @($tmpArr.Count, 'CPU Core', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5134 @('CPU Core', $script:MinimumSiteServerCPUCore))
                }
            }
        }
        #endregion

        #region RuleID = 348
        $RuleID = 348
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $ComputerInformationList)) {
                $tmpArr = @()
                $RemoteComputerList = $ComputerInformationList
                $SiteList | ForEach-Object {
                    $item = $_
                    $RemoteComputerList = $RemoteComputerList | Where-Object {$_.ServerName -ne $item.ServerName}
                }

                $RemoteComputerList | where-object {([int]($_.TotalPhysicalMemory/1GB) -lt $script:MinimumRemoteServerRAMGB)} | ForEach-Object {
                    $tmpArr += $_
                }

                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3229 @($tmpArr.Count, 'memory RAM', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5134 @('RAM memory', "$($script:MinimumRemoteServerRAMGB)GB"))
                }
            }
        }
        #endregion

        #region RuleID = 349
        $RuleID = 349
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $SiteList) -and ($null -ne $ComputerInformationList)) {
                $tmpArr = @()
                $RemoteComputerList = $ComputerInformationList
                $SiteList | ForEach-Object {
                    $item = $_
                    $RemoteComputerList = $RemoteComputerList | Where-Object {$_.ServerName -ne $item.ServerName}
                }

                $RemoteComputerList | where-object {([int]($_.NumberOfLogicalProcessors) -lt $script:MinimumRemoteServerCPUCore)} | ForEach-Object {
                    $tmpArr += $_
                }
                if ($tmpArr.Count -gt 0) {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3229 @($tmpArr.Count, 'CPU Core', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5134 @('CPU Core', $script:MinimumRemoteServerCPUCore))
                }
            }
        }
        #endregion

        #region RuleID = 350
        $RuleID = 350
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $FolderInformationList) {
                $FolderInformationList | where-object {$_.IsEmpty -eq $true} | Group-Object ObjectType | ForEach-Object {
                    $item = $_
                    $ObjectType = switch ($item.Name) {
                        2 { 'Package' }
                        3 { 'Advertisement' }
                        7 { 'Query' }
                        8 { 'Report' }
                        9 { 'Metered Product Rule' }
                        11 { 'Configuration Item' }
                        14 { 'Operating System Install' }
                        17 { 'State Migration' }
                        18 { 'Operating System Image' }
                        19 { 'Boot Image' }
                        20 { 'Task Sequence' }
                        21 { 'Device Setting' }
                        23 { 'Driver Package' }
                        25 { 'Driver' }
                        224 { 'Applicagion Group' }
                        1011 { 'Software Update' }
                        2011 { 'Configuration baseline' }
                        5000 { 'Device Collection' }
                        5001 { 'User Collection' }
                        6000 { 'Application' }
                        6001 { 'Configuration Item' }
                        default { "Unknown - $($item.Name)" }
                    }
                    $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '

                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3257 @($item.Count, $ObjectType, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5135)
                }
            }
        }
        #endregion

        #region RuleID = 351
        $RuleID = 351
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $DeploymentList) {
                $DeploymentList | where-object {($_.NumberTargeted -gt 0) -and ([int]($_.NumberErrors*100/$_.NumberTargeted) -ge $script:DeploymentErrorsWarning) -and ([int]($_.NumberErrors*100/$_.NumberTargeted) -lt $script:DeploymentErrorsError)} | Group-Object FeatureType | ForEach-Object {
                    $item = $_
                    switch ($item.Name) {
                        1 { $itemType = 'Application' }
                        2 { $itemType = 'Program' }
                        3 { $itemType = 'Mobile Program' }
                        4 { $itemType = 'Script' }
                        5 { $itemType = 'Software Update' }
                        6 { $itemType = 'Configuration Baseline' }
                        7 { $itemType = 'Task Sequence' }
                        8 { $itemType = 'Content Distribution' }
                        9 { $itemType = 'Distribution Point Group' }
                        10 { $itemType = 'Distribution Point Health' }
                        11 { $itemType = 'Configuration Policy' }
                        default { $itemType = "$($_.FeatureType) unknown"}
                    }
                    $strArray = (($item.Group | select-Object SoftwareName -unique) | Foreach {"'$($_.SoftwareName.Trim())'"}) -join ' '

                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3230 @($item.Count, $itemType, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5136)
                }
            }
        }
        #endregion

        #region RuleID = 352
        $RuleID = 352
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $DeploymentList) {
                $DeploymentList | where-object {($_.NumberTargeted -gt 0) -and ([int]($_.NumberErrors*100/$_.NumberTargeted) -ge $script:DeploymentErrorsError)} | Group-Object FeatureType | ForEach-Object {
                    $item = $_
                    switch ($item.Name) {
                        1 { $itemType = 'Application' }
                        2 { $itemType = 'Program' }
                        3 { $itemType = 'Mobile Program' }
                        4 { $itemType = 'Script' }
                        5 { $itemType = 'Software Update' }
                        6 { $itemType = 'Configuration Baseline' }
                        7 { $itemType = 'Task Sequence' }
                        8 { $itemType = 'Content Distribution' }
                        9 { $itemType = 'Distribution Point Group' }
                        10 { $itemType = 'Distribution Point Health' }
                        11 { $itemType = 'Configuration Policy' }
                        default { $itemType = "$($_.FeatureType) unknown"}
                    }
                    $strArray = (($item.Group | select-Object SoftwareName -unique) | Foreach {"'$($_.SoftwareName.Trim())'"}) -join ' '

                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3230 @($item.Count, $itemType, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5136)
                }
            }
        }
        #endregion

        #region RuleID = 353
        $RuleID = 353
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $DeploymentList) -and ($null -ne $AdvertisementList)) {
                $DeploymentList | where-object {($_.FeatureType -eq 7) -and ($_.CollectionName -eq 'All Unknown Computers')} | ForEach-Object {
                    $item = $_
                    $AdvertisementList | where-object {($_.AdvertisementID -eq $item.DeploymentID) -and (-not ($_.AdvertFlags -eq ($_.AdvertFlags -bor 0x00040000)))} | ForEach-Object {
                        $subitem = $_
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3157 @($item.SoftwareName, $item.CollectionName)) -Comment (Get-RFLHealthCheckRecommendation 5137)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 354
        $RuleID = 354
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $BaselineList) {
                $tmpArr = @()
                $BaselineList | where-object {($_.IsAssigned -eq $false) -and ($_.IsEnabled -eq $true)} | ForEach-Object {
                    $item = $_
                    $tmpArr += $item
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3234 @($tmpArr.Count, 'Configuration Baseline', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5138 'Configuration Baseline')
                }
            }
        }
        #endregion

        #region RuleID = 355
        $RuleID = 355
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $BaselineList) {
                $BaselineList | where-object {($_.IsEnabled -eq $false)} | ForEach-Object {
                    $item = $_
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3161 @('Configuration Baseline', $item.LocalizedDisplayName, $item.CI_ID, 'disabled')) -Comment (Get-RFLHealthCheckRecommendation 5138 'Configuration Baseline')
                }
            }
        }
        #endregion

        #region RuleID = 356
        $RuleID = 356
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $BaselineList) {
                $BaselineList | where-object {($_.IsHidden -eq $true)} | ForEach-Object {
                    $item = $_
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3092 @('Configuration Baseline', $item.LocalizedDisplayName)) -Comment (Get-RFLHealthCheckRecommendation @('Configuration Baseline', $item.LocalizedDisplayName))
                }
            }
        }
        #endregion

        #region RuleID = 357
        $RuleID = 357
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $BaselineList) {
                $tmpArr = @()
                $tmpArr += $BaselineList | where-object {([int]($_.FailureCount) -gt 0) -and (([int]($_.FailureCount*100/(([int]$_.ComplianceCount)+([int]$_.NonComplianceCount)+([int]$_.FailureCount))) -ge $script:DeploymentErrorsWarning)) -and (([int]($_.FailureCount*100/(([int]$_.ComplianceCount)+([int]$_.NonComplianceCount)+([int]$_.FailureCount))) -lt $script:DeploymentErrorsError))}

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3216 @($tmpArr.Count, 'minimum', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5139)
                }
            }
        }
        #endregion

        #region RuleID = 358
        $RuleID = 358
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $BaselineList) {
                $tmpArr = @()
                $tmpArr += $BaselineList | where-object {([int]($_.FailureCount) -gt 0) -and (([int]($_.FailureCount*100/(([int]$_.ComplianceCount)+([int]$_.NonComplianceCount)+([int]$_.FailureCount))) -ge $script:DeploymentErrorsError))}

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object LocalizedDisplayName -unique) | Foreach {"'$($_.LocalizedDisplayName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3216 @($tmpArr.Count, 'maximum', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5139)
                }
            }
        }
        #endregion

        #region RuleID = 359
        $RuleID = 359
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $BaselineList) {
                $tmpArr = @()
                $BaselineList | where-object {([int]($_.NonComplianceCount) -ge 0)} | ForEach-Object {
                    $item = $_
                    $Total = ([int]$item.ComplianceCount)+([int]$item.NonComplianceCount)+([int]$item.FailureCount)
                    if ($Total -gt 0) {
                        if (([int]($_.NonComplianceCount*100/$Total) -ge $script:DeploymentErrorsWarning) -and ([int]($_.NonComplianceCount*100/$Total) -lt $script:DeploymentErrorsError)) {
                            $tmpArr += New-Object -TypeName PSObject -Property @{'Name' = $item.LocalizedDisplayName; }
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $tmpArr | group-object Collection | ForEach-Object {
                        $item = $_
                        $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3276 @($item.Count, $script:DeploymentErrorsWarning, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5139)
                    }
                }

            }
        }
        #endregion

        #region RuleID = 360
        $RuleID = 360
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $BaselineList) {
                $tmpArr = @()
                $BaselineList | where-object {([int]($_.NonComplianceCount) -gt 0)} | ForEach-Object {
                    $item = $_
                    $Total = ([int]$item.ComplianceCount)+([int]$item.NonComplianceCount)+([int]$item.FailureCount)
                    if ($Total -gt 0) {
                        if (([int]($_.NonComplianceCount*100/$Total) -ge $script:DeploymentErrorsError)) {
                            $tmpArr += New-Object -TypeName PSObject -Property @{'Name' = $item.LocalizedDisplayName; }
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $tmpArr | group-object Collection | ForEach-Object {
                        $item = $_
                        $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3276 @($item.Count, $script:DeploymentErrorsError, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5139)
                    }
                }
            }
        }
        #endregion

        #region RuleID = 361
        $RuleID = 361
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $BaselineDeploymentList) -and ($null -ne $BaselineList) -and ($null -ne $UserCollectionList) -and ($null -ne $DeviceCollectionList)) {
                $tmpArr = @()
                $BaselineList | where-object {($_.IsAssigned -eq $true)} | ForEach-Object {
                    $item = $_
                    $BaselineDeploymentList | where-object {$_.AssignedCIs -contains $item.CI_ID} | ForEach-Object {
                        $subitem = $_
                        $Schedule = Convert-CMSchedule -ScheduleString "$($subitem.EvaluationSchedule)"
                        if ($null -ne $Schedule) {
                            $scheduleToMinutes = Convert-CMScheduleObjectToMinutes -ScheduleObject $Schedule
                            if ($scheduleToMinutes -lt $script:MinScheduleInMinutes) {
                                $CollectionName = ($DeviceCollectionList | where-object {$_.CollectionID -eq $subitem.TargetCollectionID}).Name
                                if ($null -eq $CollectionName) {
                                    $CollectionName = ($UserCollectionList | where-object {$_.CollectionID -eq $subitem.TargetCollectionID}).Name
                                }
                                $tmpArr += New-Object -TypeName PSObject -Property @{'Name' = $item.LocalizedDisplayName; 'Collection' = $CollectionName; 'Schedule' = $scheduleToMinutes;  }
                            }
                        }
                    }
                }

                if ($tmpArr.Count -gt 0) {
                    $tmpArr | group-object Collection | ForEach-Object {
                        $item = $_
                        $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                        Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                        Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3207 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5140 @($script:MinScheduleInMinutes))
                    }
                }
            }
        }
        #endregion

        #region RuleID = 362
        $RuleID = 362
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $GroupMembershipErrorList) {
                $GroupMembershipErrorList | ForEach-Object {
                    $item = $_
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3162 @($item)) -Comment (Get-RFLHealthCheckRecommendation 5141 @($script:ADPageSize))
                }
            }
        }
        #endregion

        #region RuleID = 363
        $RuleID = 363
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $ComponentStatusMessageListError) {
                $ComponentStatusMessageListError | ForEach-Object {
                    $item = $_

                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3163 @($item)) -Comment (Get-RFLHealthCheckRecommendation 5142 @($script:ComponentStatusMessageDateOld))
                }
            }
        }
        #endregion

        #region RuleID = 364
        $RuleID = 364
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISWebServerSetting) {
                $IISWebServerSetting | where-object {($_.ClientWebServiceExist -eq $true) -and ($_.ExecutionTimeout -ne $script:IISExecutionTimeOut)} | ForEach-Object {
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @('Client Web Service, web.config', $_.ServerName, 'httpRuntime.executionTimeout', $_.ExecutionTimeout)) -Comment (Get-RFLHealthCheckRecommendation 5144 @('httpRuntime.executionTimeout', $script:IISExecutionTimeOut))
                }
            }
        }
        #endregion

        #region RuleID = 365
        $RuleID = 365
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISClientWebService) {
                $tmpArr = @()
                $IISClientWebService | where-object {($_.ClientWebServiceExist -eq $true) -and ($_.maxRequestLength -ne $script:IISExecutionTimeOut)} | ForEach-Object {
                    $item = $_
                    $tmpArr += $item
                }

                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3255 @($tmpArr.Count, 'Client Web Service, web.config', 'httpRuntime.maxRequestLength', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5144 @('httpRuntime.maxRequestLength', $script:IISExecutionTimeOut))
                }
            }
        }
        #endregion

        #region RuleID = 366
        $RuleID = 366
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISWebServerSetting) {
                $IISWebServerSetting | where-object {($_.LogFileDirectory.Tolower()[0] -eq 'c')} | Group-Object LogFileDirectory | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3187 @($item.Count, 'IIS WebSite(s)', 'Log Directory', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                }
            }
        }
        #endregion

        #region RuleID = 367
        $RuleID = 367
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISLogs) {
                $WarningInfo = $IISLogs | where-object {($_.LogCreationTime -gt (Get-Date).AddDays(-$Script:IISLogOldItemsWarning)) -and ($_.LogCreationTime -lt (Get-Date).AddDays(-$Script:IISLogOldItemsError))} | select ServerName,'IIS Site ID'  | get-unique -AsString

                $WarningInfo | group-object 'IIS Site ID' | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3206 @($item.Count, $item.Name, $Script:IISLogOldItemsWarning, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                }
            }
        }
        #endregion

        #region RuleID = 368
        $RuleID = 368
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISLogs) {
                $ErrorInfo = $IISLogs | where-object {$_.LogCreationTime -le (Get-Date).AddDays(-$Script:IISLogOldItemsError)} | select ServerName,'IIS Site ID'  | get-unique -AsString

                $ErrorInfo | group-object 'IIS Site ID' | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3206 @($item.Count, $item.Name, $Script:IISLogOldItemsError, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                }
            }
        }
        #endregion

        #region RuleID = 369
        $RuleID = 369
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISWebServerSetting) {
                $IISWebServerSetting | where-object {($_.MaxBandwidth -ne $script:IISMaxBandwidth)} | Group-Object LogFileDirectory | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3187 @($item.Count, 'IIS Server(s)', 'MaxBandwidth', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                }
            }
        }
        #endregion

        #region RuleID = 370
        $RuleID = 370
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISWebServerSetting) {
                $IISWebServerSetting | where-object {($_.ConnectionTimeout -ne $script:IISConnectionTimeout)} | select-Object LogFileDirectory,ServerName -unique | Group-Object LogFileDirectory | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3187 @($item.Count, 'IIS Sites(s)', 'ConnectionTimeout', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5165 @('ConnectionTimeout'))
                }
            }
        }
        #endregion

        #region RuleID = 371
        $RuleID = 371
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $IISWebServerSetting) {
                $IISWebServerSetting | where-object {($_.MaxBandwidth -ne $script:IISMaxConnections)} | select-Object LogFileDirectory,ServerName -unique | Group-Object LogFileDirectory | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3187 @($item.Count, 'IIS Server(s)', 'MaxConnections', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5165 @('MaxConnections'))
                }
            }
        }
        #endregion

        #region RuleID = 372
        $RuleID = 372
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $IisWebVirtualDirSetting) -and ($null -ne $IISWebServerSetting)) {
                $IIsWebServerSetting  | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_

                    $IisWebVirtualDirSetting | Where-Object {($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "$($item.Name)/ROOT")} | ForEach-Object {
                        $subItem = $_

                        $IIsApplicationPoolSetting | Where-Object {($_.CPUResetInterval -ne $script:IISWSUSAppPoolCPUResetInterval) -and ($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "W3SVC/APPPOOLS/$($subItem.AppPoolId)")} | ForEach-Object {
                            $reportItem = $_
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @("$($item.ServerComment) ($($item).Name)", $item.PSComputerName, 'CPUResetInterval', $item.CPUResetInterval)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 373
        $RuleID = 373
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $IisWebVirtualDirSetting) -and ($null -ne $IISWebServerSetting)) {
                $IIsWebServerSetting  | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_

                    $IisWebVirtualDirSetting | Where-Object {($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "$($item.Name)/ROOT")} | ForEach-Object {
                        $subItem = $_

                        $IIsApplicationPoolSetting | Where-Object {($_.PingingEnabled -ne $script:IISWSUSAppPoolPingingEnabled) -and ($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "W3SVC/APPPOOLS/$($subItem.AppPoolId)")} | ForEach-Object {
                            $reportItem = $_
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @("$($item.ServerComment) ($($item).Name)", $item.PSComputerName, 'PingingEnabled', $item.PingingEnabled)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 374
        $RuleID = 374
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $IisWebVirtualDirSetting) -and ($null -ne $IISWebServerSetting)) {
                $IIsWebServerSetting  | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_

                    $IisWebVirtualDirSetting | Where-Object {($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "$($item.Name)/ROOT")} | ForEach-Object {
                        $subItem = $_

                        $IIsApplicationPoolSetting | Where-Object {($_.AppPoolRecyclePrivateMemory -ne $script:IISWSUSAppPoolAppPoolRecyclePrivateMemory) -and ($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "W3SVC/APPPOOLS/$($subItem.AppPoolId)")} | ForEach-Object {
                            $reportItem = $_
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @("$($item.ServerComment) ($($item).Name)", $item.PSComputerName, 'AppPoolRecyclePrivateMemory', $item.AppPoolRecyclePrivateMemory)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 375
        $RuleID = 375
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $IisWebVirtualDirSetting) -and ($null -ne $IISWebServerSetting)) {
                $IIsWebServerSetting  | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_

                    $IisWebVirtualDirSetting | Where-Object {($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "$($item.Name)/ROOT")} | ForEach-Object {
                        $subItem = $_

                        $IIsApplicationPoolSetting | Where-Object {($_.AppPoolQueueLength -ne $script:IISWSUSAppPoolAppPoolQueueLength) -and ($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "W3SVC/APPPOOLS/$($subItem.AppPoolId)")} | ForEach-Object {
                            $reportItem = $_
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @("$($item.ServerComment) ($item.Name)", $_.PSComputerName, 'AppPoolQueueLength', $item.AppPoolQueueLength)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 376
        $RuleID = 376
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $IisWebVirtualDirSetting) -and ($null -ne $IISWebServerSetting)) {
                $IIsWebServerSetting  | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_

                    $IisWebVirtualDirSetting | Where-Object {($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "$($item.Name)/ROOT")} | ForEach-Object {
                        $subItem = $_

                        $IIsApplicationPoolSetting | Where-Object {($_.RapidFailProtection -ne $script:IISWSUSAppPoolRapidFailProtection) -and ($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "W3SVC/APPPOOLS/$($subItem.AppPoolId)")} | ForEach-Object {
                            $reportItem = $_
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @("$($item.ServerComment) ($($item).Name)", $item.PSComputerName, 'RapidFailProtection', $item.RapidFailProtection)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 377
        $RuleID = 377
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $IisWebVirtualDirSetting) -and ($null -ne $IISWebServerSetting)) {
                $IIsWebServerSetting  | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_

                    $IisWebVirtualDirSetting | Where-Object {($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "$($item.Name)/ROOT")} | ForEach-Object {
                        $subItem = $_

                        $IIsApplicationPoolSetting | Where-Object {($_.PeriodicRestartTime -ne $script:IISWSUSAppPoolPeriodicRestartTime) -and ($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "W3SVC/APPPOOLS/$($subItem.AppPoolId)")} | ForEach-Object {
                            $reportItem = $_
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @("$($item.ServerComment) ($($item).Name)", $item.PSComputerName, 'PeriodicRestartTime', $item.PeriodicRestartTime)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 378
        $RuleID = 378
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $IisWebVirtualDirSetting) -and ($null -ne $IISWebServerSetting)) {
                $IIsWebServerSetting  | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_

                    $IisWebVirtualDirSetting | Where-Object {($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "$($item.Name)/ROOT")} | ForEach-Object {
                        $subItem = $_

                        $IIsApplicationPoolSetting | Where-Object {($_.PeriodicRestartRequests -ne $script:IISWSUSAppPoolPeriodicRestartRequests) -and ($_.PSComputerName -eq $item.PSComputerName) -and ($_.Name -eq "W3SVC/APPPOOLS/$($subItem.AppPoolId)")} | ForEach-Object {
                            $reportItem = $_
                            Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                            Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3164 @("$($item.ServerComment) ($($item).Name)", $item.PSComputerName, 'PeriodicRestartRequests', $item.PeriodicRestartRequests)) -Comment (Get-RFLHealthCheckRecommendation 5145)
                        }
                    }
                }
            }
        }
        #endregion

        #region RuleID = 379
        $RuleID = 379
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $PackageList | Where-Object {(($_.pkgflags -band 0x4000000) -eq 0) -and ($_.Name -notlike 'Configuration Manager Client Package*') -and ($_.Name -notlike 'Configuration Manager Client Piloting Package*')} | Group-Object PackageType | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3179 @($item.Count, 'Package', 'Enable binary differential replication', 'disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5033 @('Package', 'Enable binary differential replication', 'enabled'))
            }
        }
        #endregion

        #region RuleID = 380
        $RuleID = 380
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $PackageList | Where-Object {$_.PkgFlags -eq ($_.pkgflags -bor 0x80)} | Group-Object PackageType | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3179 @($item.Count, 'Package', 'Copy the content in this package to a package share on distribution points', 'Enabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5146 @('Package', 'Copy the content in this package to a package share on distribution points', 'disabled'))
            }
        }
        #endregion

        #region RuleID = 381
        $RuleID = 381
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            if (($null -ne $SiteRoleList) -and ($null -ne $PingList)) {
                $PingList | Where-Object {$_.Success -eq $false} | Group-Object Destination | Where-Object {$_.Count -eq $script:MaxPingCount} | Group-Object Count | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3186 @($item.Count, 'server(s)', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5119)
                }
            }
        }
        #endregion

        #region RuleID = 382
        $RuleID = 382
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $BootList | Where-Object {$_.PkgFlags -eq ($_.pkgflags -bor 0x80)} | Group-Object NumOfPrograms | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3179 @($item.Count, 'Boot Image', 'Copy the content in this package to a package share on distribution points', 'Enabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5146 @('Boot Image', 'Copy the content in this package to a package share on distribution points', 'disabled'))
            }
        }
        #endregion

        #region RuleID = 383
        $RuleID = 383
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $CMSiteUpdates | Where-Object {$_.state -ne 196612} | ForEach-Object {
                $tmpArr += $_
            }

            if ($tmpArr.Count -gt 0) {
                $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3256 @($tmpArr.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5154)
            }

        }
        #endregion

        #region RuleID = 384
        $RuleID = 384
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $DeviceCollectionList) {
                $deploymentfiltercount = (($DeviceCollectionList | Where-Object {($_.RefreshType -in (2, 6)) -and ($null -eq $_.RefreshSchedule)}) | Measure-Object).Count
                if ($deploymentfiltercount -gt 0) {
                    $CollectionNameList = Get-RFLCollectionNames -CollectionList ($DeviceCollectionList | Where-Object {($_.RefreshType -in (2, 6)) -and ($null -eq $_.RefreshSchedule)})
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3167 @($deploymentfiltercount, 'device', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5148)
                }
            }
        }
        #endregion

        #region RuleID = 385
        $RuleID = 385
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $UserCollectionList) {
                $deploymentfiltercount = (($UserCollectionList | Where-Object {($_.RefreshType -in (2, 6)) -and ($null -eq $_.RefreshSchedule)}) | Measure-Object).Count
                if ($deploymentfiltercount -gt 0) {
                    $CollectionNameList = Get-RFLCollectionNames -CollectionList ($UserCollectionList | Where-Object {($_.RefreshType -in (2, 6)) -and ($null -eq $_.RefreshSchedule)})
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3167 @($deploymentfiltercount, 'device', $CollectionNameList)) -Comment (Get-RFLHealthCheckRecommendation 5148)
                }
            }
        }
        #endregion

        #region RuleID = 386
        $RuleID = 386
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $arrFeatureTemp = $DPFeatures.Split(';')
            $tmpArr = @()
            if (($null -ne $SiteRoleListWOCDP) -and ($null -ne $OptionalFeaturesList)) {
                $SiteRoleListWOCDP | Where-Object {($_.RoleName -eq 'SMS Distribution Point')} | ForEach-Object {
                    $InstalledFeature = (($OptionalFeaturesList | where-object {($_.InstallState -eq 1) -and ($_.ServerName -eq $RemoteComputer)} | select-Object Name -unique) | Foreach {$_.Name.Trim()})
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    $isServerDown = $null -ne ($Script:ServerDown | where-object {($_.ServerName -eq $RemoteComputer) -and ($_.ConnectionType -eq 'WMI (root\cimv2) OptionalFeature')})
                    if ($isServerDown -eq $false) {
                        $tmpArr += $arrFeatureTemp | select-Object @{Name='ServerName';Expression={$RemoteComputer}},@{Name='FeatureCaption';Expression={$_.Split(',')[0].Trim()}},@{Name='FeatureName';Expression={$_.Split(',')[1].Trim()}} | where-object {($_.FeatureName -notin $InstalledFeature)}
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $tmpArr | Group-Object FeatureCaption | ForEach-Object {
                    $item = $_
                    $strArray = (($item.group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Group.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3204 @($item.Group.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5149)
                }
            }
        }
        #endregion

        #region RuleID = 387
        $RuleID = 387
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $arrFeatureTemp = $MPFeatures.Split(';')
            $tmpArr = @()
            if (($null -ne $SiteRoleList) -and ($null -ne $OptionalFeaturesList)) {
                $SiteRoleList | Where-Object {($_.RoleName -eq 'SMS Management Point')} | ForEach-Object {
                    $InstalledFeature = (($OptionalFeaturesList | where-object {($_.InstallState -eq 1) -and ($_.ServerName -eq $RemoteComputer)} | select-Object Name -unique) | Foreach {$_.Name.Trim()})
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    $isServerDown = $null -ne ($Script:ServerDown | where-object {($_.ServerName -eq $RemoteComputer) -and ($_.ConnectionType -eq 'WMI (root\cimv2) OptionalFeature')})
                    if ($isServerDown -eq $false) {
                        $tmpArr += $arrFeatureTemp | select-Object @{Name='ServerName';Expression={$RemoteComputer}},@{Name='FeatureCaption';Expression={$_.Split(',')[0].Trim()}},@{Name='FeatureName';Expression={$_.Split(',')[1].Trim()}} | where-object {($_.FeatureName -notin $InstalledFeature)}
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $tmpArr | where-object {$_.FeatureCaption -eq 'Security'} | Group-Object FeatureCaption | ForEach-Object {
                    $item = $_
                    $strArray = (($item.group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Group.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3205 @($item.Group.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5149)
                }
            }
        }
        #endregion

        #region RuleID = 388
        $RuleID = 388
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SoftwareUpdateDeploymentPackage | Where-Object {($_.pkgflags -band 0x4000000) -eq 0} | group-object SourceSite | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3183 @($item.Count, 'Software Update Deployment Package', 'Enable binary differential replication', 'Disabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5033 @('Software Update Deployment Package', 'Enable binary differential replication', 'enabled'))
            }
        }
        #endregion

        #region RuleID = 389
        $RuleID = 389
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SoftwareUpdateDeploymentPackage | Where-Object {$_.PkgFlags -eq ($_.pkgflags -bor 0x80)} | Group-Object PackageType | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3179 @($item.Count, 'Software Update Deployment Package', 'Copy the content in this package to a package share on distribution points', 'Enabled', $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5146 @('Software Update Deployment Package', 'Copy the content in this package to a package share on distribution points', 'disabled'))
            }
        }
        #endregion

        #region RuleID = 390
        $RuleID = 390
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLJobs | where-object {$_.Enabled -eq 0} | Group-Object ServerName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3249 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5151)
            }
        }
        #endregion

        #region RuleID = 391
        $RuleID = 391
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLJobs | where-object {($_.Enabled -eq 1) -and ($_.Scheduled -eq 0)} | Group-Object ServerName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3250 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5151)
            }
        }
        #endregion

        #region RuleID = 392
        $RuleID = 392
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLJobs | where-object {($_.Enabled -eq 1) -and ($_.Scheduled -eq 1) -and ($_.lastrunstatus -eq 0)} | Group-Object ServerName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3251 @($item.Count, $item.Name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5152)
            }
        }
        #endregion

        #region RuleID = 393
        $RuleID = 393
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLDBWaits | where-object {($_.cpuwaits -gt $Script:MaxCPULoad)} | Group-Object InvalidColumn | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object ServerName -unique) | Foreach {"'$($_.ServerName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3252 @($item.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5153)
            }
        }
        #endregion

        #region RuleID = 394
        $RuleID = 394
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLDBInfo | where-object {(($_.DBName -eq 'TempDB') -and ($_.CountDataFile -lt 4)) -or (($_.DBName -eq 'SUSDB') -and ($_.CountDataFile -lt 2)) -or (($_.DBName -like 'CM_*') -and ($_.CountDataFile -lt 4))} | Group-Object InvalidColumn | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object DBName -unique) | Foreach {"'$($_.DBName.Trim())'"}) -join ' '
                $tmpCount = ($item.Group | select DBName -Unique | Measure-object).Count
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3259 @($tmpCount, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5155)
            }
        }
        #endregion

        #region RuleID = 395
        $RuleID = 395
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLDBInfo | where-object {(($_.DBName -eq 'TempDB') -and ($_.CountLogFile -ne 1)) -or (($_.DBName -eq 'SUSDB') -and ($_.CountLogFile -ne 1)) -or (($_.DBName -like 'CM_*') -and ($_.CountLogFile -ne 1))} | Group-Object InvalidColumn | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object DBName -unique) | Foreach {"'$($_.DBName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3260 @($item.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5155)
            }
        }
        #endregion

        #region RuleID = 396
        $RuleID = 396
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $deviceListCount = ($DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.Name -notlike '*Unknown*')} | Measure-Object).Count
            if ($deviceListCount -lt $script:ConfigMgrDBMinClients) {
                $DBSize = $Script:MinConfigMgrDBSize
            } else {
                $DBSize = [math]::Round((($deviceListCount)/$script:ConfigMgrDBMinClients))*$Script:MinConfigMgrDBSize
            }

            $SQLDBInfo | where-object {(($_.DBName -eq 'SUSDB') -and (($_.size*8*1024) -lt $Script:MinSUSDBSize)) -or (($_.DBName -like 'CM_*') -and (($_.size*8*1024) -lt $DBSize))} | Group-Object InvalidColumn | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object DBName -unique) | Foreach {"'$($_.DBName.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3261 @($item.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5160)
            }
        }
        #endregion

        #region RuleID = 397
        $RuleID = 397
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $SQLDBInfo | where-object {($_.is_percent_growth -eq $true) -or (($_.is_percent_growth -eq $false) -and ($_.growth -lt 1024))} | Group-Object InvalidColumn | ForEach-Object {
                $item = $_
                $tmpCount = ($item.Group | select DBName -Unique | Measure-object).Count
                $strArray = (($item.Group | select-Object DBName -unique) | Foreach {"'$($_.DBName)'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3260 @($tmpCount, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5156)
            }
        }
        #endregion

        #region RuleID = 398
        $RuleID = 398
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpSQLDBGrowth = @()
            $SQLDBGrowth | ForEach-Object {
                $item = $_
                $tmpSQLDBGrowth += New-Object -TypeName PSObject -Property @{'ServerName' = $item.ServerName; 'database_name' = $item.database_name; 'bkpDate' = $item.backup_finish_date.Date; 'backup_finish_date' = $item.backup_finish_date; 'backup_start_date' = $item.backup_start_date; }
            }

            $tmpArr = @()
            $tmpSQLDBGrowth | Group-Object ServerName,Database_Name,bkpDate | Where-Object {$_.Count -gt 1} | ForEach-Object {
                $item = $_
                $strArray = ($item.Group | select-Object database_name -unique)
                $strArrayServer = (($item.Group | select-Object ServerName -unique) | Foreach {"$($_.ServerName)"}) -join ' '

                $tmpArr += New-Object -TypeName PSObject -Property @{'Server' = $strArrayServer; 'DBs' = $strArray; }
            }

            if ($tmpArr.Count -gt 0) {
                $tmpArr | Group-Object Server | ForEach-Object {
                    $item = $_
                    $strArray = (($item.Group.DBs | select-Object database_name -unique) | Foreach {"'$($_.database_name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3264 @($item.Count, $item.name, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5159)
                }
            }
        }
        #endregion

        #region RuleID = 399
        $RuleID = 399
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $sitesummarytask | Where-Object {($_.TaskName -eq 'SUM Update Group Status Summarizer') -and ($_.RunInterval -gt $Script:MaxSUPGroupSummarizationTime)} | ForEach-Object {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3109 @('Software Update Group Summarization Interval', $_.RunInterval)) -Comment (Get-RFLHealthCheckRecommendation 5093 $Script:MaxSUPGroupSummarizationTime)
            }
        }
        #endregion

        #region RuleID = 400
        $RuleID = 400
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $sitesummarytask | Where-Object {($_.TaskName -eq 'SUM Update Group Status Summarizer') -and ($_.RunInterval -lt $Script:MinSUPGroupSummarizationTime)} | ForEach-Object {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue (1)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3110 @('Software Update Group Summarization Interval', $_.RunInterval)) -Comment (Get-RFLHealthCheckRecommendation 5094 $Script:MinSUPGroupSummarizationTime)
            }
        }
        #endregion

        #region RuleID = 401
        $RuleID = 401
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ManagementInsights | Where-Object {($_.ProgressCatergory -eq 0)} | group-object ProgressCatergory | ForEach-Object {
                $item = $_
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                $arrComment = @()
                $item.Group | foreach-object {
                    $subitem = $_
                    $RuleDescription = $subitem.RuleDescription
                    $indx = $RuleDescription.IndexOf('This rule ')
                    if ($indx -ge 0) {
                        $RuleDescription = $RuleDescription.Substring(0, $indx)
                    }
                    $arrComment += "'$($subitem.Name)': $($RuleDescription)" 
                }
                $strComment = $arrComment -join '[NL]'
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name)'"}) -join ' '
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3270 @($_.Count, $strArray)) -Comment $strComment
            }
        }
        #endregion

        #region RuleID = 402
        $RuleID = 402
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            $SiteFeature | Where-Object {($_.FeatureType -eq 1) -and ($_.Status -eq 0)} | group-object Status | ForEach-Object {
                $strArray = (($_.Group | select-Object Name -unique) | Foreach {"'$($_.Name)'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($_.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3269 @($_.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5162)
            }
        }
        #endregion

        #region RuleID = 403
        $RuleID = 403
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $ClientSettingsSettingsList | Where-Object {($_.SettingsName -eq 'ClientPolicy') -and ($_.Key -eq 'PolicyEnableUserPolicyPolling') -and ($_.Value -eq $false)} | Group-Object SettingsName | ForEach-Object {
                $item = $_
                $strArray = (($item.Group | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($item.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3242 @($item.Count,'ClientPolicy', 'PolicyEnableUserPolicyPolling', 'disabled',$strArray)) -Comment (Get-RFLHealthCheckRecommendation 5163 'User Policy', 'https://docs.microsoft.com/en-us/configmgr/core/clients/deploy/about-client-settings')
            }
        }
        #endregion

        #region RuleID = 404
        $RuleID = 404
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $W10Devices = $DeviceList | Where-Object {($_.IsClient -eq $true) -and ($_.DeviceOS -like 'Microsoft Windows*Workstation*10*') -and (-not [string]::IsNullOrEmpty($_.DeviceOSBuild))}
            $W10DevicesFilter = $W10Devices | select Name, DeviceOS, @{Name = "W10Version" ; Expression = { [System.Version]::Parse($_.DeviceOSBuild) } }, @{Name = "W10Build" ; Expression = { $_.DeviceOSBuild.Split('.')[2] } } | Group-Object W10Build

            $deviceListCount = (($W10DevicesFilter | Where-Object {$_.Name -le $script:W10MinBuild}) | measure-object Count -Sum).Sum                                                                                                                
            if ($deviceListCount -gt 0) {
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($deviceListCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3040 @($deviceListCount, 'expired Windows 10')) -Comment (Get-RFLHealthCheckRecommendation 5164 'Windows 10')
            }
        }
        #endregion

        #region RuleID = 405
        $RuleID = 405
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if (($null -ne $SoftwareVersionList) -and ($null -ne $SiteList)) {
                $SiteList | ForEach-Object {
                    $item = $_
                    $SoftwareVersionList | where-object {($_.Name -notlike '*Preinstallation Environment Add-ons*') -and ($_.Name -like 'Windows Assessment and Deployment Kit*') -and ($_.SiteCode = $item.SiteCode) -and ($_.ServerName -eq $item.ServerName)} | ForEach-Object {
                        $subitem = $_
                        $ADKList = ($script:ADKMatrix | ? { $_.Split(';')[0] -eq $item.BuildNumber })
                        if ($null -eq $ADKList) { #build information not in the list
                            $tmpArr += $item 
                        } else {
                            $ADKList = $ADKList.Split(';')[1]
                            $ADKList = $ADKList.Split('/')
                            $ADKVersion = [System.Version]::Parse($subitem.Version).ToString(3)
                            $bFound = $false

                            foreach($ADKItem in $ADKList) {
                                if ($ADKItem -match $ADKVersion) {
                                    $bFound = $true
                                    break
                                }
                            }

                            if (-not $bFound) {
                                $tmpArr += $item
                            }
                        }
                    }
                }
            }

            if ($tmpArr.Count -gt 0) {
                $tmpCount = ($tmpArr | select SiteCode -Unique | Measure-object).Count
                $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode)'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3275 @($tmpCount, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5114)
            }
        }
        #endregion

        #region RuleID = 406
        $RuleID = 406
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            $tmpArr = @()
            if ($null -ne $SQLServiceAccount) {
                $SQLServiceAccount | Where-Object { ($_.Name -ne 'SQLBrowser') -and (($_.Instance -eq $_.InstanceID) -or ([string]::IsNullOrEmpty($_.Instance))) -and ($_.ServiceAccount -in @('LocalSystem', 'NT AUTHORITY\LOCALSERVICE'))  } | ForEach-Object {
                    $tmpArr += $_
                }
            }

            if ($tmpArr.Count -gt 0) {
                $tmpCount = ($tmpArr | select ServerName -Unique | Measure-object).Count
                $strArray = (($tmpArr | select-Object ServerName -unique) | Foreach {"'$($_.ServerName)'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpCount)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3280 @($tmpCount, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5166)
            }
        }
        #endregion

        #region RuleID = 407
        $RuleID = 407
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"

            $InventoryDataLoader | Where-Object {($_.MaxMifSize -lt $script:MinMaxMifSize) -and ($_.Success -eq $true)} | group-object ConnectionType | ForEach-Object {
                $strArray = (($_.Group | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode)'"}) -join ' '
                Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($_.Count)
                Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3290 @($_.Count, $strArray)) -Comment (Get-RFLHealthCheckRecommendation 992719)
            }
        }
        #endregion

        #region RuleID = 408
        $RuleID = 408
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $AADTenant) -and ($null -ne $AADApplication)) {
                $tmpArr = @()
                $Warning = (Get-Date).AddDays(([int]$script:AADApplicationExpireWarning))

                $AADTenant | ForEach-Object {
                    $item = $_
                    $AADApplication | Where-Object {($_.TenantID -eq $item.ID) -and ($_.IsClientApp -eq $False) -and ($_.SecretKeyExpiry -le $Warning) -and ($_.SecretKeyExpiry -gt (Get-Date))} | ForEach-Object {
                        $tmpArr += $item
                    }
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3291 @($tmpArr.Count, "Azure Active Directory Tenant - Server Application - Secret key", "to expire in the next $($script:AADApplicationExpireWarning) days", $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5167)
                }
            }
        }
        #endregion

        #region RuleID = 409
        $RuleID = 409
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if (($null -ne $AADTenant) -and ($null -ne $AADApplication)) {
                $tmpArr = @()
                $AADTenant | ForEach-Object {
                    $item = $_
                    $AADApplication | Where-Object {($_.TenantID -eq $item.ID) -and ($_.IsClientApp -eq $False) -and ($_.SecretKeyExpiry -lt (Get-Date))} | ForEach-Object {
                        $tmpArr += $item
                    }
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3291 @($tmpArr.Count, "Azure Active Directory Tenant - Server Application - Secret key", "expired", $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5167)
                }
            }
        }
        #endregion

        #region RuleID = 410
        $RuleID = 410
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $CloudManagementGateway) {
                $tmpArr = @()
                $CloudManagementGateway | Where-Object {$_.ClientCertRevocationEnabled -eq $false} | ForEach-Object {
                    $tmpArr += $_
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3291 @($tmpArr.Count, "Cloud Management Gateway - Certificate Revocation List", "disabled", $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5168)
                }
            }
        }
        #endregion

        #region RuleID = 411
        $RuleID = 411
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $CloudManagementGateway) {
                $tmpArr = @()
                $CloudManagementGateway | Where-Object {$_.VmSize -eq 'Standard_B2s'} | ForEach-Object {
                    $tmpArr += $_
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3291 @($tmpArr.Count, "Cloud Management Gateway - VM Size", "Standard_B2s", $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5169)
                }
            }
        }
        #endregion

        #region RuleID = 412
        $RuleID = 412
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $CloudManagementGateway) {
                $tmpArr = @()
                $CloudManagementGateway | Where-Object {$_.DeploymentModel -eq 1} | ForEach-Object {
                    $tmpArr += $_
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3291 @($tmpArr.Count, "Cloud Management Gateway - Deployment Model", "Cloud service (classic)", $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5170)
                }
            }
        }
        #endregion

        #region RuleID = 413
        $RuleID = 413
        $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
        if ($RuleIDInfo.Enabled -ne $true) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule ID $($RuleIDInfo.ID) has been ignored as it is not enabled"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "Executing Rule ID $($RuleIDInfo.ID)"
            if ($null -ne $SiteComponentList) {
                $tmpArr = @()
                $SiteComponentList | Where-Object {$_.ItemName -eq 'SMS_SITE_COMPONENT_MANAGER|SMS Site Server'} | ForEach-Object {
                    $item = $_
                    $value = ($item.Props | Where-Object {$_.PropertyName -eq 'IISSSLState' }).Value

                    <#
                    31 = HTTPS no CRL
                    63 = HTTPS with CRL
                    192 = HTTP without CRL no PKI
                    224 = HTTP or HTTPS with CRL no PKI
                    448 = HTTP or HTTPS without CRL
                    480 = HTTP or HTTPS with CRL
                    1216 = eHTTP no CRL or PKI
                    1248 = eHTTP with CRL no PKI
                    1472 = eHTTP with PKI no CRL
                    1504 = eHTTP with PKI and CRL
                    #>

                    if ($value -in (192, 224, 4489, 480)) {
                        $tmpArr += $item
                    }
                }
                
                if ($tmpArr.Count -gt 0) {
                    $strArray = (($tmpArr | select-Object SiteCode -unique) | Foreach {"'$($_.SiteCode.Trim())'"}) -join ' '
                    Add-RFLHealthCheckIssueList -RuleIDInfo $RuleIDInfo -IncrementValue ($tmpArr.Count)
                    Write-RFLHealthCheckData -RuleIDInfo $RuleIDInfo -Description (Get-RFLHealthCheckIssue 3291 @($tmpArr.Count, "Communication", "not set to HTTPS or Enhanced HTTP", $strArray)) -Comment (Get-RFLHealthCheckRecommendation 5171)
                }
            }
        }
        #endregion

        #endregion

        #region Summarize Data and Save to Disk
        Write-RFLLog -logtype "Info" -logmessage "Exporting Data"
        $Script:HealthCheckData | Export-Clixml -Path "$($SaveToFolder)\HealthCheck.xml"

        #export Data for Summary:
        $Script:HealthCheckSummary = New-Object system.Data.DataTable "HealthCheckSummary"
        $newCol = New-Object system.Data.DataColumn "Category",([string])
        $Script:HealthCheckSummary.Columns.Add($newCol)
        $newCol = New-Object system.Data.DataColumn "Text",([string])
        $Script:HealthCheckSummary.Columns.Add($newCol)
        $newCol = New-Object system.Data.DataColumn "Total",([string])
        $Script:HealthCheckSummary.Columns.Add($newCol)

        $newRow = $Script:HealthCheckSummary.NewRow()
        $newRow.Category = "TotalIssues"
        $newRow.Text = "TotalIssues"
        $newRow.Total = $Script:HealthCheckData.rows.count
        $Script:HealthCheckSummary.Rows.Add($newRow)

        $DeviceList | where-object {($_.IsClient -eq $true) -and ($null -ne $_.DeviceOS)} | Group-Object DeviceOS | ForEach-Object {
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "DeviceOS"
            $newRow.Text = $_.Name
            $newRow.Total = $_.Count
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        $newRow = $Script:HealthCheckSummary.NewRow()
        $newRow.Category = "TotalServers"
        $newRow.Text = "TotalServers"
        $newRow.Total = ($SiteRoleList | Select-Object NetworkOSPath | Sort-Object NetworkOSPath -Unique | Measure-Object).Count
        $Script:HealthCheckSummary.Rows.Add($newRow)

        $newRow = $Script:HealthCheckSummary.NewRow()
        $newRow.Category = "TotalPrimarySites"
        $newRow.Text = "TotalPrimarySites"
        $newRow.Total = ($SiteList | Where-Object {$_.Type -eq 2} | Sort-Object SiteCode -Unique | Measure-Object).Count
        $Script:HealthCheckSummary.Rows.Add($newRow)

        $newRow = $Script:HealthCheckSummary.NewRow()
        $newRow.Category = "TotalSecondarySites"
        $newRow.Text = "TotalSecondarySites"
        $newRow.Total = ($SiteList | Where-Object {$_.Type -eq 1} | Sort-Object SiteCode -Unique | Measure-Object).Count
        $Script:HealthCheckSummary.Rows.Add($newRow)

        $newRow = $Script:HealthCheckSummary.NewRow()
        $newRow.Category = "TotalDiscoveredClients"
        $newRow.Text = "TotalDiscoveredClients"
        $newRow.Total = ($DeviceList | Where-Object {$_.Name -notlike '*Unknown Computer*'} | Measure-Object).Count
        $Script:HealthCheckSummary.Rows.Add($newRow)

        $newRow = $Script:HealthCheckSummary.NewRow()
        $newRow.Category = "Feature"
        $newRow.Text = "Inventory"
        $newRow.Total = 0
        $Script:HealthCheckSummary.Rows.Add($newRow)

        if ($null -ne $TaskSequenceList) {
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "Feature"
            $newRow.Text = "Operating System"
            $newRow.Total = 0
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        if (($null -ne $ApplicationList) -or ($null -ne $PackageList)) {
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "Feature"
            $newRow.Text = "Software Deployment"
            $newRow.Total = 0
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        if ($null -ne $SUPList) {
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "Feature"
            $newRow.Text = "Software Update"
            $newRow.Total = 0
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        if ($null -ne $SwMeteringRuleList) {
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "Feature"
            $newRow.Text = "Software Metering"
            $newRow.Total = 0
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        if ($null -ne $EndpointProtectionList) {
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "Feature"
            $newRow.Text = "Endpoint Protection"
            $newRow.Total = 0
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        if ($null -ne $BaselineList) {
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "Feature"
            $newRow.Text = "Compliance Settings"
            $newRow.Total = 0
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        1..25 | foreach {
            $varInfo = (Get-Variable "Cat$($_)ERROR" -ErrorAction SilentlyContinue).Value
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "IssueList"
            $newRow.Text = "$(Get-RFLHealthCheckCategory $_);ERROR"
            $newRow.Total = $varInfo
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }
        1..25 | foreach {
            $varInfo = (Get-Variable "Cat$($_)WARNING" -ErrorAction SilentlyContinue).Value
            $newRow = $Script:HealthCheckSummary.NewRow()
            $newRow.Category = "IssueList"
            $newRow.Text = "$(Get-RFLHealthCheckCategory $_);WARNING"
            $newRow.Total = $varInfo
            $Script:HealthCheckSummary.Rows.Add($newRow)
        }

        $Script:HealthCheckSummary | Export-Clixml -Path "$($SaveToFolder)\HealthCheck.xml.sum"
        #endregion

        $Script:EndExportDateTime = get-date
        Write-RFLLog -logtype "Info" -logmessage "Successfully exported Data"
    } finally {

    }
    #endregion
} catch {
    $Global:ErrorCapture += $_
    Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"    
    if ($Verbose) {
        Write-RFLLog -logtype "EXCEPTION" -logmessage "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
    }
} finally {
    #region export error information
    $Global:ErrorCapture += $Error
    $Global:ErrorCapture | Export-Clixml -Path "$($SaveToFolder)\ErrorExport.xml"
    #endregion

    $Script:EndDateTime = get-date
    $FullScriptTimeSpan = New-TimeSpan -Start $Script:StartDateTime -End $Script:EndDateTime
    if (($null -ne $Script:StartExportingDateTime) -and ($null -ne $Script:EndExportDateTime)) {
        $ExportScriptTimeSpan = New-TimeSpan -Start $Script:StartExportingDateTime -End $Script:EndExportDateTime
        Write-RFLLog -logtype "Info" -logmessage "'Export Data Stats' '$('{0:dd} days, {0:hh} hours, {0:mm} minutes, {0:ss} seconds' -f $ExportScriptTimeSpan)'"
    }
    Write-RFLLog -logtype "Info" -logmessage "'Full Script Stats' '$(('{0:dd} days, {0:hh} hours, {0:mm} minutes, {0:ss} seconds' -f $FullScriptTimeSpan))'"

    Write-RFLLog -logtype "Info" -logmessage "Cleaning up memory allocation"
}
#endregion