<#
    .SYSNOPSIS
        Generate a report of the HealthCheck analysed data

    .DESCRIPTION
        Generate a report of the HealthCheck analysed data

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
              - migrated generation of report from c# to ps1 with GenerateReport.ps1 file (word/excel format)

    Test:
        CM2111 Primary site installed on a WS2016
        CM2107 Primary site installed on a WS2019

        DocX 2.0.0.0 on Windows 11
        EPPPlus 5.8.6 on Windows 11

    Requirements:
        Word export: 
            - DocX library (https://www.nuget.org/packages/DocX)
        Excel Export: 
            - Microsoft.IO.RecyclableMemoryStream (https://www.nuget.org/packages/Microsoft.IO.RecyclableMemoryStream/)
            - EPPlus library (https://www.nuget.org/packages/epplus)

    .EXAMPLE
        Generate a report in Word Format and save it to c:\temp\report.docx using C:\temp\ReportTemplate.docx as template File. Will override the report file if it already exist and use file ConfigMgrDefaultReportValues.xml located on the same folder as the script. Will generate the report based on the healthcheck files exported to C:\temp\healthcheck\Capture

        .\GenerateReport.ps1 -Format Word -ReportFile 'c:\temp\report.docx' -ForceOverrideReport -DefaultValuesOverrideFilePath .\ConfigMgrDefaultReportValues.xml -HealthCheckFolder 'C:\temp\healthcheck\Capture' -ReportTemplateFileName 'C:\temp\ReportTemplate.docx' -ReportAuthor 'Raphael Perez' -CompanyName 'RFL Systems Ltd' -CompanyURL 'https://www.rflsystems.co.uk' -CustomerName 'Customer Name'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $False)]
    [String]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Word','Excel')]
    $Format = 'Word',

    [Parameter(Mandatory = $True)]
    [string]
    [ValidateNotNullOrEmpty()]
    $ReportFile,

    [Parameter(Mandatory = $false)]
    [switch]
    $ForceOverrideReport,

    [parameter(Mandatory=$true)]
    [ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Default Values Override File Path given: $_"}})]
    [string]
    $DefaultValuesOverrideFilePath,

    [parameter(Mandatory=$false)]
    [ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid HealthCheck Folder given: $_"}})]
    [string]    
    $HealthCheckFolder = 'C:\Temp\ConfigMgrHealthCheck',

    [parameter(Mandatory=$true)]
    [ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Report Template File Path given: $_"}})]
    [string]
    $ReportTemplateFileName,

    $ReportAuthor = 'Raphael Perez',
    $CompanyName = 'RFL Systems Ltd',
    $CompanyURL = 'https://www.rflsystems.co.uk',

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $CustomerName

)
#region Starting Script, Verbose variables
$Global:ErrorCapture = @()
$Script:StartDateTime = get-date
$Script:RemoveVariable = $true
if ($Verbose) {
    $DebugPreference = 2
    $VerbosePreference = 2
    $WarningPreference = 2
}
$Error.Clear()
$ErrorActionPreference = "Continue"
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
        Write-RFLLog -LogMessage "Unable to delete log file." -LogType ERROR
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

#region Set-RFLHealthCheckDefaultValue
function Set-RFLHealthCheckDefaultValue {
    param (
        [Parameter(Position=1, Mandatory=$true)][string]$ValueName,
        [Parameter(Position=2, Mandatory=$true)]$ValueNonExist
    )
    $ValueDetails = $Script:HealthCheckDefaultValueData.DefaultValues.DefaultValue | Where-Object {$_.Name -eq $ValueName}
    if ($null -eq $ValueDetails) {
        New-Variable -Name $ValueName -Value $ValueNonExist -Force -Option AllScope -Scope Script
    } else {
        if ($ValueDetails -is [array]) {
            $ValueDetails = $ValueDetails[0]
        }

        if ($ValueDetails.Type.tolower() -eq 'array') {
            New-Variable -Name $ValueName -Value $ValueDetails.value.Split(',') -Force -Option AllScope -Scope Script
        } else {
            New-Variable -Name $ValueName -Value $ValueDetails.value -Force -Option AllScope -Scope Script
        }
        Write-RFLLog -LogMessage "$ValueName is now set to custom default value of $((Get-Variable $ValueName).Value)"
    }
}
#endregion

#region Insert-RFLBoldParagraph
function Insert-RFLBoldParagraph {
    param (
        [Parameter(Mandatory=$true)]$Paragraph,
        [Parameter(Mandatory=$true)]$Text,
        [Parameter(Mandatory=$true)]$Alignment
    )
    if (-not [string]::IsNullOrEmpty($Text)) {
        $iFinish = $Text.IndexOf("[/BOLD]")
        if ($iFinish -ge 0) {
            $p.Append($Text.Substring(0, $iFinish)).Bold().Alignment = $Alignment
            $p.Append($Text.Substring($iFinish).Replace("[/BOLD]", "")).Alignment = $Alignment
        } else {
            $p.Append($Text).Alignment = $Alignment
        }
    }
}
#endregion

#endregion

#region Variables
$script:ScriptVersion = '2.0'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'GenerateReport.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
add-type -AssemblyName system.drawing
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -LogMessage "*** Starting ***"
    Write-RFLLog -LogMessage "Script version $($script:ScriptVersion)"
    Write-RFLLog -LogMessage "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -LogMessage "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    if (Test-Path -Path $ReportFile -PathType Leaf) {
        if ($ForceOverrideReport -ne $true) {
            Write-RFLLog -LogMessage "File $($ReportFile) exist and the paramter 'ForceOverrideReport' was not set. Report has not been generated" -LogType ERROR
            return        
        } else {
            Write-RFLLog -LogMessage "File $($ReportFile) exist and the paramter 'ForceOverrideReport' was set. File will be override" -LogType WARNING
        }
    }

    #region Initial Validation
    if (-not (Test-Path -Path ("$($HealthCheckFolder)\HealthCheck.xml") -PathType Leaf)) {
        Write-RFLLog -LogMessage "File $($HealthCheckFolder)\HealthCheck.xml does not exist. Report has not been generated" -LogType ERROR
        return        
    }

    if (-not (Test-Path -Path ("$($HealthCheckFolder)\HealthCheck.xml.sum") -PathType Leaf)) {
        Write-RFLLog -LogMessage "File $($HealthCheckFolder)\HealthCheck.xml.sum does not exist. Report has not been generated" -LogType ERROR
        return        
    }

    if ($Format -eq 'Word') {
        if (-not (Get-Package -Name DocX -ErrorAction SilentlyContinue)) {
            Write-RFLLog -LogMessage "Package 'DocX' does not exist. Information on how to install can be found at https://www.nuget.org/packages/DocX. Report has not been generated" -LogType ERROR
            return
        }
    }

    if ($Format -eq 'Excel') {
        if (-not (Get-Package -Name Microsoft.IO.RecyclableMemoryStream -ErrorAction SilentlyContinue)) {
            Write-RFLLog -LogMessage "Package 'Microsoft.IO.RecyclableMemoryStream' does not exist. Information on how to install can be found at https://www.nuget.org/packages/Microsoft.IO.RecyclableMemoryStream/. Report has not been generated" -LogType ERROR
            return
        }

        if (-not (Get-Package -Name EPPlus -ErrorAction SilentlyContinue)) {
            Write-RFLLog -LogMessage "Package 'EPPlus' does not exist. Information on how to install can be found at https://www.nuget.org/packages/epplus. Report has not been generated" -LogType ERROR
            return
        }
    }
    #endregion

    #region Import DocX DLLs
    if ($Format -eq 'Word') {
        Write-RFLLog -LogMessage "Importing DocX Module DLLs" 
        $PackagePath = ([System.IO.FileInfo]((Get-Package -Name DocX).Source)).Directory.FullName
        $DLL = Resolve-Path "$($PackagePath)\lib\net40\Xceed.Document.NET.dll"
        Write-RFLLog -LogMessage "Importing $($DLL)" 
        [System.Reflection.Assembly]::LoadFrom($DLL) | Out-Null

        $DLL = Resolve-Path "$($PackagePath)\lib\net40\Xceed.Words.NET.dll"
        Write-RFLLog -LogMessage "Importing $($DLL)" 
        [System.Reflection.Assembly]::LoadFrom($DLL) | Out-Null
    }
    #endregion

    #region Import EPPlus DLLs
    if ($Format -eq 'Excel') {
        Write-RFLLog -LogMessage "Importing Microsoft.IO.RecyclableMemoryStream Module DLLs" 
        $PackagePath = ([System.IO.FileInfo]((Get-Package -Name Microsoft.IO.RecyclableMemoryStream).Source)).Directory.FullName
        $DLL = Resolve-Path "$($PackagePath)\lib\net462\Microsoft.IO.RecyclableMemoryStream.dll"
        Write-RFLLog -LogMessage "Importing $($DLL)" 
        [System.Reflection.Assembly]::LoadFrom($DLL) | Out-Null

        Write-RFLLog -LogMessage "Importing EPPlus Module DLLs" 
        $PackagePath = ([System.IO.FileInfo]((Get-Package -Name EPPlus).Source)).Directory.FullName
        $DLL = Resolve-Path "$($PackagePath)\lib\net40\EPPlus.dll"
        Write-RFLLog -LogMessage "Importing $($DLL)" 
        [System.Reflection.Assembly]::LoadFrom($DLL) | Out-Null

#[System.Reflection.Assembly]::LoadFrom('C:\Temp\Library\lib\net40\Microsoft.IO.RecyclableMemoryStream.dll') | Out-Null
#[System.Reflection.Assembly]::LoadFrom('C:\Temp\Library\lib\net40\EPPlus.dll') | Out-Null
    }

    #endregion

    #region Default Values
    Write-RFLLog -LogMessage "Default Values Database"
    $Script:HealthCheckDefaultValueData = [xml](get-content $DefaultValuesOverrideFilePath)
    #endregion

    #region Set Default Variables
    Write-RFLLog -LogMessage "Setting Default Report Variables"
    #Report Only
	Set-RFLHealthCheckDefaultValue -ValueName 'SummaryFormat' -ValueNonExist '[BOLD]@@OEMNAME@@[/BOLD] has completed a @@MODULETITLE@@ health check for [BOLD]@@CUSTOMERNAME@@[/BOLD] on @@DATETIME@@ by running a suite of tools to collect key data from @@MODULENAME@@ and its dependent systems.[NL][NL][BOLD]@@OEMNAME@@[/BOLD] has found a total of [BOLD]@@TOTALISSUE@@[/BOLD] issues/misconfiguration and a break down can be seen in the table(s) below:'
	Set-RFLHealthCheckDefaultValue -ValueName 'SummaryNote' -ValueNonExist "[NL]Please note, the findings and guidance provided by this assessment is based on our best practices database that was built over the years by our team of experts that have conducted over thousands of customers assessments. [BOLD]@@OEMNAME@@[/BOLD] has made every attempt to ensure the accuracy and reliability of the information provided on this report. However, the information is provided 'as is' without warranty of any kind. [BOLD]@@OEMNAME@@[/BOLD] does not accept any responsibility or liability for the accuracy, content, completeness, legality, or reliability of the information contained on this report."
	Set-RFLHealthCheckDefaultValue -ValueName 'SummaryNoteBlank' -ValueNonExist ''
	Set-RFLHealthCheckDefaultValue -ValueName 'ReportHeader' -ValueNonExist 'This section contains all issues and recommendations for [BOLD]@@OEMNAME@@[/BOLD] consideration.[NL]'
    Set-RFLHealthCheckDefaultValue -ValueName 'SortReport' -ValueNonExist '@{Expression = "Classification"; Descending = $false}, @{Expression = "CriticalityID"; Descending = $false}, @{Expression = "RuleID"; Descending = $false}, @{Expression = "CategoryID"; Descending = $false}'
	Set-RFLHealthCheckDefaultValue -ValueName 'ExportDateFormat' -ValueNonExist 'dd/MM/yyyy HH:mm:ss'

	Set-RFLHealthCheckDefaultValue -ValueName 'Excel_HeaderBackgroundColour' -ValueNonExist "#ff70ad47"
	Set-RFLHealthCheckDefaultValue -ValueName 'Excel_HeaderFontColour' -ValueNonExist "#ff000000"
	Set-RFLHealthCheckDefaultValue -ValueName 'Excel_TitleCell' -ValueNonExist "A1"
	Set-RFLHealthCheckDefaultValue -ValueName 'Excel_LicensedToCell' -ValueNonExist "J14"
	Set-RFLHealthCheckDefaultValue -ValueName 'Excel_DateTimeCell' -ValueNonExist "J15"
	Set-RFLHealthCheckDefaultValue -ValueName 'Excel_OEMCell' -ValueNonExist "J16"

	Set-RFLHealthCheckDefaultValue -ValueName 'Word_HeaderColour' -ValueNonExist "#ff70ad47"
    Set-RFLHealthCheckDefaultValue -ValueName 'Word_Column1Size' -ValueNonExist 90
	Set-RFLHealthCheckDefaultValue -ValueName 'Word_Column2Size' -ValueNonExist 350

	Set-RFLHealthCheckDefaultValue -ValueName 'CategoryError' -ValueNonExist "#ff8b0000"
	Set-RFLHealthCheckDefaultValue -ValueName 'CategoryWarning' -ValueNonExist "#ffffa500"
	Set-RFLHealthCheckDefaultValue -ValueName 'CriticalityHigh' -ValueNonExist "#ff8b0000"
	Set-RFLHealthCheckDefaultValue -ValueName 'CriticalityMedium' -ValueNonExist "#ffffa500"
	Set-RFLHealthCheckDefaultValue -ValueName 'CriticalityLow' -ValueNonExist "#ff00cc00"
	Set-RFLHealthCheckDefaultValue -ValueName 'AddRuleID' -ValueNonExist $true
	Set-RFLHealthCheckDefaultValue -ValueName 'ExportComments' -ValueNonExist $true
    #endregion

    #region Variables
    Write-RFLLog -LogMessage "Preparing variables"
    $Script:AlignLeft = [Xceed.Document.NET.Alignment]::left
    $script:TableDesign = [Xceed.Document.NET.TableDesign]::TableGrid
    $script:TableAutoFitWindow = [Xceed.Document.NET.AutoFit]::Window
    $script:TableAutoFitColumn = [Xceed.Document.NET.AutoFit]::ColumnWidth
    $Script:stringSeparators = @( "[BOLD]" )
    $Fields = @("Category","Classification", "Criticality", "Description")
    if ($script:AddRuleID -eq $true) { $Fields = @("RuleID") + $Fields }
    if ($script:ExportComments -eq $true) { $Fields = $Fields + @("Comment")}
    $TodayDateTime = get-date -Format $script:ExportDateFormat

	$ExcelHeaderBackgroundColour = [System.Drawing.ColorTranslator]::FromHtml($script:Excel_HeaderBackgroundColour)
	$ExcelHeaderFontColour = [System.Drawing.ColorTranslator]::FromHtml($script:Excel_HeaderFontColour)

    $WordHeaderColour = [System.Drawing.ColorTranslator]::FromHtml($script:Word_HeaderColour)
    $ErrorColour = [System.Drawing.ColorTranslator]::FromHtml($script:CategoryError)
    $WarningColour = [System.Drawing.ColorTranslator]::FromHtml($script:CategoryWarning)
    $HighColour = [System.Drawing.ColorTranslator]::FromHtml($script:CriticalityHigh)
    $MediumColour = [System.Drawing.ColorTranslator]::FromHtml($script:CriticalityMedium)
    $LowColour = [System.Drawing.ColorTranslator]::FromHtml($script:CriticalityLow)
    #endregion

    Write-RFLLog -LogMessage "Opening HealthCheck report file"
    $dtHealthCheck = Import-Clixml "$($HealthCheckFolder)\HealthCheck.xml"

    Write-RFLLog -LogMessage "Opening HealthCheck summary report file"
    $dtHealthCheckSummary = Import-Clixml "$($HealthCheckFolder)\HealthCheck.xml.sum"

    Write-RFLLog -LogMessage "Preparing Summary"
    $Summary = $script:SummaryFormat
    $Summary = $Summary.Replace("@@OEMNAME@@", $CompanyName)
    $Summary = $Summary.Replace("@@MODULETITLE@@", 'Microsoft Endpoint Configuration Manager')
    $Summary = $Summary.Replace("@@MODULENAME@@", 'Configuration Manager')
    $Summary = $Summary.Replace("@@CUSTOMERNAME@@", $CustomerName)
    $Summary = $Summary.Replace("@@DATETIME@@", $TodayDateTime)
    $Summary = $Summary.Replace("@@TOTALISSUE@@", ($dtHealthCheckSummary | Where-Object {$_.Text -eq 'TotalIssues'}).Total)

    Write-RFLLog -LogMessage "Preparing Summary Note"
    $TableSummaryNote = $Script:SummaryNote
    $TableSummaryNote = $TableSummaryNote.Replace("@@OEMNAME@@", $CompanyName)
    $TableSummaryNote = $TableSummaryNote.Replace("@@MODULETITLE@@", 'Microsoft Endpoint Configuration Manager')
    $TableSummaryNote = $TableSummaryNote.Replace("@@MODULENAME@@", 'Configuration Manager')
    $TableSummaryNote = $TableSummaryNote.Replace("@@CUSTOMERNAME@@", $CustomerName)
    $TableSummaryNote = $TableSummaryNote.Replace("@@DATETIME@@", $TodayDateTime)
    $TableSummaryNote = $TableSummaryNote.Replace("@@TOTALISSUE@@", ($dtHealthCheckSummary | Where-Object {$_.Text -eq 'TotalIssues'}).Total)

    Write-RFLLog -LogMessage "Preparing Report Header"
    $TableReportHeader = $Script:ReportHeader
    $TableReportHeader = $TableReportHeader.Replace("@@OEMNAME@@", $CompanyName)
    $TableReportHeader = $TableReportHeader.Replace("@@MODULETITLE@@", 'Microsoft Endpoint Configuration Manager')
    $TableReportHeader = $TableReportHeader.Replace("@@MODULENAME@@", 'Configuration Manager')
    $TableReportHeader = $TableReportHeader.Replace("@@CUSTOMERNAME@@", $CustomerName)
    $TableReportHeader = $TableReportHeader.Replace("@@DATETIME@@", $TodayDateTime)
    $TableReportHeader = $TableReportHeader.Replace("@@TOTALISSUE@@", ($dtHealthCheckSummary | Where-Object {$_.Text -eq 'TotalIssues'}).Total)

    if ($Format -eq 'Word') {
        #region Export to Word
        Write-RFLLog -LogMessage "Creating Word doc based on template $($ReportTemplateFileName)"
        $docx = [Xceed.Words.NET.DocX]::Load($ReportTemplateFileName)

        Write-RFLLog -LogMessage "Adding custom properties"
        $docx.AddCustomProperty([Xceed.Document.NET.CustomProperty]::new("ReportTitle", "Microsoft Endpoint Configuration Manager - HealthCheck"))
        $docx.AddCustomProperty([Xceed.Document.NET.CustomProperty]::new("ReportGeneratedOn", "HealthCheck Report generated on $($TodayDateTime)"))
        $docx.AddCustomProperty([Xceed.Document.NET.CustomProperty]::new("ReportAuthor",$ReportAuthor ))
        $docx.AddCustomProperty([Xceed.Document.NET.CustomProperty]::new("CompanyName", $CompanyName))
        $docx.AddCustomProperty([Xceed.Document.NET.CustomProperty]::new("CompanyURL", $CompanyURL))

        #paragraphs
        foreach($dPar in $docx.Paragraphs) {
            if ($dPar.Text.IndexOf("@@SUMMARY@@") -ge 0) {
                Write-RFLLog -LogMessage "Adding Summary"

                $p = $dPar.InsertParagraphBeforeSelf("")
                $Summary = $Summary.Replace("[NL]", [System.Environment]::NewLine)
                $arrSummary = $Summary.Split($stringSeparators, [System.StringSplitOptions]::None) | ForEach-Object {
                    $item = $_
                    Insert-RFLBoldParagraph -Paragraph $p -Text $item -Alignment $Script:AlignLeft
                }
                $dPar.RemoveText(0)
            } elseif ($dPar.Text.IndexOf("@@TABLEBREAKDOWN@@") -ge 0) {
                Write-RFLLog -LogMessage "Adding table breakdown"
                $dv = $dtHealthCheckSummary | Where-Object {($_.Category -eq 'IssueList') -and ($_.Total -gt 0)} | Select-Object @{n="Category";e={$_.Text.Split(';')[0]}},@{n="Classification";e={$_.Text.Split(';')[1]}},@{n="Total";e={[int]$_.Total}} | Sort-Object @{Expression = "Classification"; Descending = $false}, @{Expression = "Total"; Descending = $true}

                $p = $dPar
                $dTable = $docx.AddTable($dv.Count + 1, 3)
                $dTable.Design = $script:TableDesign
                $dTable.AutoFit = $script:TableAutoFitWindow

                $i = 0
                Write-RFLLog -LogMessage "Adding table header"
                @("Category", "Classification", "Total of Issues/Misconfiguration") | ForEach-Object {
                    $Column = $dTable.Rows[0].Cells[$i].Paragraphs[0]
                    $Column.Alignment = $Script:AlignLeft
                    $Data = $Column.Append($_).Bold()
                    $dTable.Rows[0].Cells[$i].FillColor = $WordHeaderColour
                    $i++
                }

                [int]$i = 1
                Write-RFLLog -LogMessage "Adding content"
                $dv | ForEach-Object {
                    $item = $_
                    $j = 0
                    $dv | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty"} | Select Name | ForEach-Object {
                        $objMember = $_.Name

                        $Column = $dTable.Rows[$i].Cells[$j].Paragraphs[0]
                        $Column.Alignment = $Script:AlignLeft

                        if ($item.$objMember -eq 'ERROR') {
                            $Data = $Column.Append($item.$objMember.Trim()).Color($ErrorColour)
                        } elseif($item.$objMember -eq 'WARNING') {
                            $Data = $Column.Append($item.$objMember.Trim()).Color($WarningColour)
                        } else {
                            $Data = $Column.Append($item.$objMember.ToString().Trim())
                        }
                        $j++
                    }
                    Write-RFLLog -LogMessage "Content $($i) of $($dv.count) added"
                    $i++
                }
                Write-RFLLog -LogMessage "Adding table to the doc"
                $Data = $dPar.InsertTableBeforeSelf($dTable)

                #add summary note
                if (-not ([String]::IsNullOrEmpty($script:SummaryNote))) {
                    Write-RFLLog -LogMessage "Adding summary note"
                    $p = $dPar.InsertParagraphBeforeSelf("");
                    $TableSummaryNote = $TableSummaryNote.Replace("[NL]", [System.Environment]::NewLine)
                    $arrSummaryNote = $TableSummaryNote.Split($stringSeparators, [System.StringSplitOptions]::None) | ForEach-Object {
                        $item = $_
                        Insert-RFLBoldParagraph -Paragraph $p -Text $item -Alignment $Script:AlignLeft
                    }
                }
                $dPar.RemoveText(0)
            } elseif ($dPar.Text.IndexOf("@@REPORT@@") -ge 0) {
                Write-RFLLog -LogMessage "Adding report header"
                $p = $dPar.InsertParagraphBeforeSelf("");
                $TableReportHeader = $TableReportHeader.Replace("[NL]", [System.Environment]::NewLine)
                $arrReportHeader = $TableReportHeader.Split($stringSeparators, [System.StringSplitOptions]::None) | ForEach-Object {
                    $item = $_

                    if (-not [string]::IsNullOrEmpty($item)) {
                        $iFinish = $item.IndexOf("[/BOLD]")
                        if ($iFinish -ge 0) {
                            $p.Append($item.Substring(0, $iFinish)).Bold().Alignment = $Script:AlignLeft
                            $p.Append($item.Substring($iFinish).Replace("[/BOLD]", "")).Alignment = $Script:AlignLeft
                        } else {
                            $p.Append($item).Alignment = $Script:AlignLeft
                        }
                    }
                }

                Write-RFLLog -LogMessage "Adding report tables"
                $Numbers = 1
                $sortReportExpression = @()
                $sortReport.Split('@{') | ForEach-Object {
                    $sortReportExpressionItem = $_
                    if (-not ([string]::IsNullOrEmpty($sortReportExpressionItem))) {
                        $sortReportExpressionItem = $sortReportExpressionItem.Replace('},','').Replace('}','')
                        $arr = $sortReportExpressionItem.Split(';')
                        
                        $sortReportExpression += [PSObject]@{
                            Expression = "$($arr[0].Trim().Replace('Expression = "','').Replace('"',''))"
                            Descending = [System.Convert]::ToBoolean($arr[1].Trim().Replace('Descending = $',''))
                        }
                    }
                }

                $dtHealthCheck | Sort-Object -Property $sortReportExpression | ForEach-Object {
                    Write-RFLLog -LogMessage "Adding Content $($Numbers) of $($dtHealthCheck.count)"
                    $item = $_
                    $dTable = $docx.AddTable($Fields.Count, 2);
                    $dTable.Design = $script:TableDesign
                    $dTable.AutoFit = $script:TableAutoFitWindow
                    $dTable.SetColumnWidth(0, $script:Word_Column1Size)
                    $dTable.SetColumnWidth(1, $script:Word_Column2Size)

                    $i = 0;
                    $Fields | ForEach-Object {
                        $Field = $_
                        $FieldText = $Field
                        if ($Field -eq 'RuleID') { 
                            $FieldText = 'Rule ID' 
                        } elseif ($Field -eq 'Description') { 
                            $FieldText = 'Issue '
                        } elseif ($Field -eq 'Comment') { 
                            $FieldText = 'Resolution' 
                        }

                        $Column = $dTable.Rows[$i].Cells[0].Paragraphs[0];
                        $Column.Alignment = $Script:AlignLeft
                        $data = $Column.Append($FieldText).Bold();
                        $dTable.Rows[$i].Cells[0].FillColor = $WordHeaderColour;
                        $columnValue = $dTable.Rows[$i].Cells[1].Paragraphs[0];
                        $columnValue.Alignment = $Script:AlignLeft

                        if ($Field -ne "Comment") {
                            $text = $item.$Field.ToString().Trim().Replace("[NL]", [Environment]::NewLine)
                            if ($item.$Field -eq 'ERROR') {
                                $Data = $columnValue.Append($text).Color($ErrorColour)
                            } elseif($item.$Field -eq 'WARNING') {
                                $Data = $columnValue.Append($text).Color($WarningColour)
                            } elseif($item.$Field -eq 'HIGH') {
                                $Data = $columnValue.Append($text).Color($HighColour)
                            } elseif($item.$Field -eq 'MEDIUM') {
                                $Data = $columnValue.Append($text).Color($MediumColour)
                            } elseif($item.$Field -eq 'LOW') {
                                $Data = $columnValue.Append($text).Color($LowColour)
                            } else {
                                $Data = $columnValue.Append($text)
                            }
                        } else {
                            ##comment
                            $columnValue = $dTable.Rows[$i].Cells[1].Paragraphs[0];
                            $columnValue.Alignment = $Script:AlignLeft
                            
                            $Script:HLSeparators = @( "[HL]" )
                            $arrSummary = $item.$Field.Replace("[NL]", [Environment]::NewLine).Split($Script:HLSeparators, [System.StringSplitOptions]::None) | ForEach-Object {
                                $itemText = $_

                                if (-not [string]::IsNullOrEmpty($itemText)) {
                                    $iFinish = $itemText.Trim().IndexOf("[/HL]")
                                    if ($iFinish -ge 0) {
                                        $HyperLink = $itemText.Trim().Substring(0, $iFinish);
                                        $hyp = $docx.AddHyperlink($HyperLink, [System.Uri]($HyperLink))
                                        $data = $columnValue.AppendHyperlink($hyp);
                                        $data = $columnValue.Append($itemText.Substring($iFinish).Replace("[/HL]", "").Trim()).Alignment = $Script:AlignLeft
                                    } else {
                                        $data = $columnValue.Append($itemText).Alignment = $Script:AlignLeft
                                    }
                                }
                            }
                        }
                        $i++;
                    }

                    $data = $dPar.InsertTableBeforeSelf($dTable);
                    $data = $dPar.InsertParagraphBeforeSelf("");
                    $Numbers++
                }

                $dPar.RemoveText(0);
            }
        }
        Write-RFLLog -LogMessage "Saving report file"
        $docx.SaveAs($ReportFile)
       #endregion
    } elseif ($Format -eq'Excel') {
        #region Export to Excel
        Write-RFLLog -LogMessage "Creating Excel spreadsheet based on template $($ReportTemplateFileName)"
        $package = [OfficeOpenXml.ExcelPackage]::New($ReportTemplateFileName)

        $package.Workbook.Worksheets | ForEach-Object {
            $worksheet = $_
            switch ($worksheet.Name.tolower()) {
                "cover" {
                    $worksheet.Cells[$script:Excel_TitleCell].Value = "Microsoft Endpoint Configuration Manager - HealthCheck"
                    $worksheet.Cells[$script:Excel_LicensedToCell].Value = $CustomerName
                    $worksheet.Cells[$script:Excel_DateTimeCell].Value = $TodayDateTime
                    $worksheet.Cells[$script:Excel_OEMCell].Value = $CompanyName
                }
                "summary" {
                    $dv = $dtHealthCheckSummary | Where-Object {($_.Category -eq 'IssueList') -and ($_.Total -gt 0)} | Select-Object @{n="Category";e={$_.Text.Split(';')[0]}},@{n="Classification";e={$_.Text.Split(';')[1]}},@{n="Total";e={[int]$_.Total}} | Sort-Object @{Expression = "Classification"; Descending = $false}, @{Expression = "Total"; Descending = $true}
                    $i = 1
                    Write-RFLLog -LogMessage "Adding table header"
                    @("Category", "Classification", "Total of Issues/Misconfiguration") | ForEach-Object {
                        $worksheet.Cells[1, $i].Value = $_
                        $worksheet.Cells[1, $i].Style.Font.Color.SetColor($ExcelHeaderFontColour)
                        $worksheet.Cells[1, $i].Style.Font.Bold = $true
                        $worksheet.Cells[1, $i].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                        $worksheet.Cells[1, $i].Style.Fill.BackgroundColor.SetColor($ExcelHeaderBackgroundColour)
                        $i++
                    }
                    $i = 1
                    $dv | ForEach-Object {
                        Write-RFLLog -LogMessage "Content $($i) of $($dv.count) added"
                        $i++
                        $item = $_
                        $j = 1
                        $dv | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty"} | Select Name | ForEach-Object {
                            $objMember = $_.Name
                            $worksheet.Cells[$i, $j].Value = $item.$objMember.ToString().Trim()
                            if ($item.$objMember -eq 'ERROR') {
                                $Data = $worksheet.Cells[$i, $j].Style.Font.Color.SetColor($ErrorColour)
                            } elseif($item.$objMember -eq 'WARNING') {
                                $Data = $worksheet.Cells[$i, $j].Style.Font.Color.SetColor($WarningColour)
                            }
                            $j++
                        }
                    }
                    $worksheet.Cells[1, 1, 1, 3].AutoFilter = $true
                    try {
                        $worksheet.Cells.AutoFitColumns()
                    } catch {

                    }
                }
                "report" {
                    Write-RFLLog -LogMessage "Adding report tables"
                    $i = 1;
                    $Fields | ForEach-Object {
                        $Field = $_
                        $FieldText = $Field
                        if ($Field -eq 'RuleID') { 
                            $FieldText = 'Rule ID' 
                        } elseif ($Field -eq 'Description') { 
                            $FieldText = 'Issue '
                        } elseif ($Field -eq 'Comment') { 
                            $FieldText = 'Resolution' 
                        }

                        $worksheet.Cells[1, $i].Value = $FieldText;
                        $worksheet.Cells[1, $i].Style.Font.Color.SetColor($ExcelHeaderFontColour)
                        $worksheet.Cells[1, $i].Style.Font.Bold = $true
                        $worksheet.Cells[1, $i].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                        $worksheet.Cells[1, $i].Style.Fill.BackgroundColor.SetColor($ExcelHeaderBackgroundColour)
                        $i++
                    }

                    $sortReportExpression = @()
                    $sortReport.Split('@{') | ForEach-Object {
                        $sortReportExpressionItem = $_
                        if (-not ([string]::IsNullOrEmpty($sortReportExpressionItem))) {
                            $sortReportExpressionItem = $sortReportExpressionItem.Replace('},','').Replace('}','')
                            $arr = $sortReportExpressionItem.Split(';')
                        
                            $sortReportExpression += [PSObject]@{
                                Expression = "$($arr[0].Trim().Replace('Expression = "','').Replace('"',''))"
                                Descending = [System.Convert]::ToBoolean($arr[1].Trim().Replace('Descending = $',''))
                            }
                        }
                    }

                    $Numbers = 1
                    $dtHealthCheck | Sort-Object -Property $sortReportExpression | ForEach-Object {
                        Write-RFLLog -LogMessage "Adding Content $($Numbers) of $($dtHealthCheck.count)"
                        $Numbers++
                        $item = $_
                        $j = 1;
                        $Fields | ForEach-Object {
                            $Field = $_
                            $worksheet.Cells[$Numbers, $j].Value = $item.$Field.ToString().Trim().Replace("[NL]", [Environment]::NewLine).Replace("[HL]", "").Replace("[/HL]", "").Replace("[BOLD]", "").Replace("[/BOLD]", "")

                            if ($item.$Field -eq 'ERROR') {
                                $Data = $worksheet.Cells[$Numbers, $j].Style.Font.Color.SetColor($ErrorColour)
                            } elseif($item.$Field -eq 'WARNING') {
                                $Data = $worksheet.Cells[$Numbers, $j].Style.Font.Color.SetColor($WarningColour)
                            } elseif($item.$Field -eq 'HIGH') {
                                $Data = $worksheet.Cells[$Numbers, $j].Style.Font.Color.SetColor($HighColour)
                            } elseif($item.$Field -eq 'MEDIUM') {
                                $Data = $worksheet.Cells[$Numbers, $j].Style.Font.Color.SetColor($MediumColour)
                            } elseif($item.$Field -eq 'LOW') {
                                $Data = $worksheet.Cells[$Numbers, $j].Style.Font.Color.SetColor($LowColour)
                            }
                            $j++;
                        }
                    }
                    $worksheet.Cells[1, 1, 1, $Fields.Count].AutoFilter = $true
                    try {
                        $worksheet.Cells.AutoFitColumns()
                    } catch {

                    }
                }
            }
        }
        Write-RFLLog -LogMessage "Saving report file"
        $package.SaveAs($ReportFile)
        $package.Dispose()
        #endregion
    }
} catch {
    Write-RFLLog -LogMessage "An error occurred $($_)" -LogType ERROR
    Exit 3000
} finally {
    $Script:EndDateTime = get-date
    $FullScriptTimeSpan = New-TimeSpan -Start $Script:StartDateTime -End $Script:EndDateTime
    Write-RFLLog -LogMessage "Full Script Stats $('{0:dd} days, {0:hh} hours, {0:mm} minutes, {0:ss} seconds' -f $FullScriptTimeSpan)"
    Write-RFLLog -LogMessage "*** Ending ***"
}
#endregion