#Created 11/18/2021
#By: Alan Newingham
#Get all failed login attempts. Export to CSV. Email CSV. Delete CSV after Email.


Function Get-FailedLogin {
    [CmdletBinding(
        DefaultParameterSetName = 'All'
    )]
    Param (
        [Parameter(
            ValueFromPipeline = $true,
            ParameterSetName = 'ByUser'
        )]
        [string]$DomainController = (Get-ADDomain).PDCEmulator
        ,
        [datetime]$StartTime
        ,
        [datetime]$EndTime
    )
    Begin {
        $LogonType = @{
            '2' = 'Interactive'
            '3' = 'Network'
            '4' = 'Batch'
            '5' = 'Service'
            '7' = 'Unlock'
            '8' = 'Networkcleartext'
            '9' = 'NewCredentials'
            '10' = 'RemoteInteractive'
            '11' = 'CachedInteractive'
        }
        $filterHt = @{
            LogName = 'Security'
            ID = 4625
        }
        if ($PSBoundParameters.ContainsKey('StartTime')){
            $filterHt['StartTime'] = $StartTime
        }
        if ($PSBoundParameters.ContainsKey('EndTime')){
            $filterHt['EndTime'] = $EndTime
        }
        # Query the event log just once instead of for each user if using the pipeline
        $events = Get-WinEvent -ComputerName $DomainController -FilterHashtable $filterHt
    }
    Process {
        if ($PSCmdlet.ParameterSetName -eq 'ByUser'){
            $user = Get-ADUser $Identity
            # Filter for the user
            $output = $events | Where-Object {$_.Properties[5].Value -eq $user.SamAccountName}
        } else {
            $output = $events
        }
        foreach ($event in $output){
            [pscustomobject]@{
                TargetAccount = $event.properties.Value[5]
                LogonType = $LogonType["$($event.properties.Value[10])"]
                CallingComputer = $event.Properties.Value[13]
                IPAddress = $event.Properties.Value[19]
                TimeStamp = $event.TimeCreated
            }
        }
    }
    End{}
}
#End of function, let's do this.
$date = (Get-Date -Format "yyyy-MM-dd")

#Run function, Pipe to csv with date, notype, and out-null helps with determining if the command finished running. It is not necessary, it's just habbit.
Get-FailedLogin | Export-Csv -Path C:\temp\FailedLogin$date.csv -NoTypeInformation | Out-Null

#What is the file location appended with my date format?
$file = 'C:\temp\ADUserBadPasswords' + $date + '.csv'

#Wait till file is completed, then continue.
while (!(Test-Path $file)) { Start-Sleep 10 }

#All for email
$username = "user1@constoso.com"
$password = "AFDHSKJ@#%$(Y@)UJGA SD:KN!@#%$(Y)U"
$sstr = ConvertTo-SecureString -string $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -argumentlist $username, $sstr
$Attachment = 'C:\temp\ADUserBadPasswords' + $date + '.csv'
$body = "<h1> IT Failed Login Report</h1><br><br>"
$body += "Attached is a queried list of failed login attemps for the last two days.<br>"
$body += "<br><br><br><br><br><br><br>"
$body += '<br>'
$body += 'Should you find the automation is failing in any way please let me know at <a href = "mailto: user1@constoso.com">user1@constoso.com</a><br>'
$body += "<br><br><br><br><br><br><br>"
$body += "Report Ran: $date"
Send-MailMessage -To "user1@constoso.com" -from "donotreply@constoso.com" -Subject 'AD Failed Login Report' -Body $body -BodyAsHtml -Attachments $Attachment -smtpserver smtp.office365.com -usessl -Credential $cred -Port 587


#Waste not, delete the file after sending.
Remove-Item $file
