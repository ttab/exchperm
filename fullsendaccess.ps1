# Powershell script created by chralp

########### Load necessary module and snapin
############################################
import-module ActiveDirectory

if ((Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction SilentlyContinue) -eq $null ){

    add-pssnapin Microsoft.Exchange.Management.PowerShell.E2010

}
########### Variables
$domain = "domain.tld\"
$dcserver = "DCdomain"
$OU = "OU=exampel,DC=DCdomain"

########### Get all groups from specific OU
$Groups = Get-ADGroup -Properties * -Filter * -SearchBase $OU

########### Loop all groups AS SECGROUP
Foreach($SECGROUP In $Groups){
  ########### Get all members from group, only SamAccountName
  $SEC = Get-ADGroupMember -Identity $SECGROUP.Name | Select SamAccountName
  ########### Check to see if Description field is empty on group
  if($SECGROUP.Description -eq $null){}else{
    ########### Select Description from Group witch equals the email adress to the mailbox we want to work with
    ########### Due some issues when serching for proxyAddresses im adding "stmp:" + email adress in a new variable
    $smtp = "smtp:" + $SECGROUP.Description
    $AdDn = Get-ADuser -Properties proxyAddresses -Filter {(proxyAddresses -eq $smtp)} | Select DistinguishedName
    write-host $SECGROUP.Name  :::  $SECGROUP.Description  ::: $AdDn.DistinguishedName
    ########### Get Propertie uSNChanged from group to se if group have been edited, and from specific dc server. Since uSNChanged does not replicate.
    $SEC_changed = Get-ADGroup -Identity $SECGROUP.Name -Properties uSNChanged -server $dcserver | Select uSNChanged
    ########### Get uSNChanged from ad object (mailbox) witch i add in Description to match if its updated or not
    $AD_changed = Get-ADuser -Identity $AdDn.DistinguishedName -Properties Description -server $dcserver | Select-Object Description
    $uSNC = $SEC_changed.uSNChanged
    ########### Check if group uSNChanged equals ad-obejct Description.
    if($SEC_changed.uSNChanged -eq $AD_changed.Description){

      write-host SEC group aldready updated: $SECGROUP.Name -ForegroundColor Green
      write-host "SEC:" $SEC_changed.uSNChanged
      write-host "AD:" $AD_changed.Description

    }else{

      write-host SEC group need to update: $SECGROUP.Name -ForegroundColor Yellow
      write-host "SEC:" $SEC_changed.uSNChanged
      write-host "AD:" $AD_changed.Description
      ########### Set the group uSNChanged value into ad-object Description field
      Set-ADUser $AdDn.DistinguishedName -Replace @{Description="$uSNC";} -server $dcserver

      ForEach($users in $SEC){
        if ($users -eq $null){}else{

          $username = $domain + $users.SamAccountName
          ########### Check if user have SEND as permissions
          $sendaccess = Get-ADPermission -Identity $AdDn.DistinguishedName | Where-Object {($_.User -Like "$username")}

          if($sendaccess){

            write-host $users.SamAccountName - "SendAccess in AD: OK" -foreground Green

          }else{
            ########### Add SEND as permissions
            Add-ADPermission -Identity $AdDn.DistinguishedName -User $username -ExtendedRights "Send-as" | Out-Null
            write-host $users.SamAccountName - "SendAccess in AD: Added" -foreground Green

          }
          ########### Check if user have fullaccess permissions
          $fullaccess = Get-MailboxPermission -Identity $AdDn.DistinguishedName | Where-Object {($_.AccessRights -Like "FullAccess") -And ($_.IsInherited -Like "False") -And ($_.User -Like "$username")}

          if($fullaccess){

            write-host $users.SamAccountName - "FullAccess on EXCH: OK" -foreground Green

          }else{
            ########### Add fullaccess permissions
            Add-MailboxPermission -Identity $AdDn.DistinguishedName -User $username -AccessRights "FullAccess" | Out-Null
            write-host $users.SamAccountName - "FullAccess on EXCH: Added" -foreground Green

          }
        }
      }

      #######################################################
      ########### Remove users permissions if user -
      ########### isnt a member in sec group
      #######################################################


      ########### Get all users with Send AS permissions
      $AD = Get-ADPermission -Identity $AdDn.DistinguishedName | Where-Object {($_.ExtendedRights -Like "Send-As") -and -not ($_.User -like "NT AUTHORITY*")} | Select-Object | select user
      ########### Gel all users with Fullaccess Permissions
      $EX = Get-MailboxPermission -Identity $AdDn.DistinguishedName | Where-Object {($_.AccessRights -Like "Fullaccess") -and -not ($_.User -like "NT AUTHORITY*") -and ($_.IsInherited -like "false")} | Select User

      ForEach($users in $AD){

        if($users -eq $null){}else{
          ########### Remove Domain from username
          $signature = $users.user -creplace '(?s)^.*\\', ''
          ########### Check if user ( that have SEND as on mailbox ) exists in group
          $MemberInSecSend = Get-ADGroupMember -Identity $SECGROUP.Name | Where-Object {($_.SamAccountName -eq "$signature")}

          if($MemberInSecSend){

            write-host $signature - "Send AS in AD: OK" -foreground Green

          }else{
            ########### IF user does not exist then remove SEND as permissions
            Remove-ADPermission -Identity $AdDn.DistinguishedName -User $users.user -InheritanceType 'All' -ExtendedRights 'send-as' -ChildObjectTypes $null -InheritedObjectType $null -Properties $null -Confirm:$false
            write-host $signature - "Send AS in AD: Delete" -foreground Red
          }
        }
      }

      ForEach($users in $EX){

        if($users -eq $null){}else{
          ########### Remove Domain from username
          $signature = $users.user -creplace '(?s)^.*\\', ''
          ########### Check if user ( that have Fullaccess as on mailbox ) exists in group
          $MemberInSecfull = Get-ADGroupMember -Identity $SECGROUP.Name|  Where-Object {($_.SamAccountName -eq "$signature")}

            if ($MemberInSecfull){

              write-host $signature - "FullAccess: OK" -foreground Green

            }else{
              ########### IF user does not exist then remove Fullaccess permissions
              Remove-MailboxPermission -Identity $AdDn.DistinguishedName -User $users.user -AccessRights 'FullAccess' -Confirm:$false
              write-host $signature - "Fullaccess: Delete" -foreground Red

            }
          }
        }
      }
    }
  }
