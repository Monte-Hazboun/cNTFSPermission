﻿Function Get-TargetResource  {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Account,

        [Parameter(Mandatory = $true)]
    	[ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles","ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes","ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttributes","WriteData","WriteExtendedAttributes",IgnoreCase=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Rights,
        
        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [String]$Ensure = "Present",
        
        [Parameter()]
        [ValidateSet("Allow", "Deny")]
        [String]$Access = "Allow",

        [Parameter()]
        [Bool]$NoInherit = $false
    )

    $InheritFlag = if($NoInherit){ "None" }else{ "ContainerInherit, ObjectInherit" }

    $DesiredRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $Rights, $InheritFlag, "None", $Access)

    $CurrentACL = (Get-Item $Path).GetAccessControl("Access")
    $CurrentRules = $CurrentACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
    $Match = $CurrentRules | Where-Object { ($DesiredRule.IdentityReference -eq $_.IdentityReference) -and 
                                            ($DesiredRule.FileSystemRights -eq $_.FileSystemRights)   -and 
                                            ($DesiredRule.AccessControlType -eq $_.AccessControlType) -and 
                                            ($DesiredRule.InheritanceFlags -eq $_.InheritanceFlags ) 
                                          }
    
    $Presence = if($Match) { "Present" } else { "Absent" }

    $output = @{
                Ensure = $Presence;
                Path = $Path;
                Account = $Account;
                Rights = $Rights;
                Access = $Access;
                NoInherit = $NoInherit;
                }

    return $output
}

Function Test-TargetResource {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Account,

        [Parameter(Mandatory = $true)]
	    [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles","ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes","ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttributes","WriteData","WriteExtendedAttributes",IgnoreCase=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Rights,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [String]$Ensure = "Present",
        
        [Parameter()]
        [ValidateSet("Allow", "Deny")]
        [String]$Access = "Allow",

        [Parameter()]
        [Bool]$NoInherit = $false
    )

    $InheritFlag = if($NoInherit){ "None" }else{ "ContainerInherit, ObjectInherit" }

    $DesiredRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $Rights, $InheritFlag, "None", $Access)

    $CurrentACL = (Get-Item $Path).GetAccessControl("Access")
    $CurrentRules = $CurrentACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
    $Match = $CurrentRules |Where-Object { ($DesiredRule.IdentityReference -eq $_.IdentityReference) -and 
                                           ($DesiredRule.FileSystemRights -eq $_.FileSystemRights)   -and 
                                           ($DesiredRule.AccessControlType -eq $_.AccessControlType) -and  
                                           ($DesiredRule.InheritanceFlags -eq $_.InheritanceFlags ) 
                                         }

    $Presence = if( $Match ){ "Present" } else { "Absent" }
    return $Presence -eq $Ensure
}

Function Set-TargetResource {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Account,

        [Parameter(Mandatory = $true)]
	    [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles","ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes","ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttributes","WriteData","WriteExtendedAttributes",IgnoreCase=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Rights,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [String]$Ensure = "Present",
        
        [Parameter()]
        [ValidateSet("Allow", "Deny")]
        [String]$Access = "Allow",

        [Parameter()]
        [Bool]$NoInherit = $false
    )

    $InheritFlag = if($NoInherit){ "None" }else{ "ContainerInherit, ObjectInherit" }

    $DesiredRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $Rights, $InheritFlag, "None", $Access)
    $CurrentACL = (Get-Item $Path).GetAccessControl("Access")

    Switch ($Ensure) {
        "Present" {
            $CurrentACL.AddAccessRule($DesiredRule)
            Set-Acl $Path $CurrentACL
        }
        "Absent" {
            $CurrentRules = $CurrentACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $Match = $CurrentRules | Where-Object { ($DesiredRule.IdentityReference -eq $_.IdentityReference) -and 
                                                    ($DesiredRule.FileSystemRights -eq $_.FileSystemRights)   -and 
                                                    ($DesiredRule.AccessControlType -eq $_.AccessControlType) -and  
                                                    ($DesiredRule.InheritanceFlags -eq $_.InheritanceFlags ) 
                                                  }

            $Match | % {[void]$CurrentACL.RemoveAccessRule($_)}
            Set-Acl $Path $CurrentACL
        }
    }
}

Export-ModuleMember -Function *-TargetResource