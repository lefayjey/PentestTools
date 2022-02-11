# AppLocker Bypass Checker (Default Rules) v2.0
#
# One of the Default Rules in AppLocker allows everything in the folder C:\Windows to be executed.
# A normal user shouln't have write permission in that folder, but that is not always the case.
# This script lists default ACL for the "BUILTIN\users" group looking for write/createFiles & execute authorizations
#
# @Author: Sparc Flow in "How to Hack a Fashion Brand"
#
# NOTE: change the group and root_folder variables to suit your needs

$group = "*Users*"
$root_folder = "C:\windows"
write-output "[*] Processing folders recursively in $root_folder"
foreach($_ in (Get-ChildItem $root_folder -recurse -ErrorAction SilentlyContinue)){
    if($_.PSIsContainer)
    {
		try{
			$res = Get-acl $_.FullName 
		} catch{
			continue
		}
		foreach ($a in $res.access){
			if ($a.IdentityReference -like $group){
				if ( ($a.FileSystemRights -like "*Write*" -or $a.FileSystemRights -like "*CreateFiles*" ) -and $a.FileSystemRights -like "*ReadAndExecute*" ){
					write-host "[+] " $_.FullName -foregroundcolor "green"
				}
				
			}
		}
    }
}
