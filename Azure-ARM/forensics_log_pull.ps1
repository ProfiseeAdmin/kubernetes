mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Config" 
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Gateway"
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Attachments"
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Auth"
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Governance"
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Monolith"
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Workflows"
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Web"
mkdir "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Webportal"
mkdir "$env:TEMP\all-Logs\$DT\EventViewerLogs"
mkdir "$env:TEMP\all-Logs\$DT\TCPLogs"
mkdir "$env:TEMP\all-Logs\$DT\IISLogs"
robocopy "$env:SystemRoot\System32\winevt\Logs\" "$env:TEMP\all-Logs\$DT\EventViewerLogs" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\configuration\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Config" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\gateway\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Gateway" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\services\attachments\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Attachments" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\services\auth\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Auth" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\services\governance\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Governance" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\services\monolith\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Monolith" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\services\workflows\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Workflows" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\web\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Web" /E /COPYALL /DCOPY:T
robocopy "c:\profisee\webportal\logfiles" "$env:TEMP\all-Logs\$DT\ProfiseeLogs\Webportal" /E /COPYALL /DCOPY:T
robocopy "c:\inetpub\logs\LogFiles\W3SVC1" "$env:TEMP\all-Logs\$DT\IISLogs" /E /COPYALL /DCOPY:T

#Compress and copy to fileshare
compress-archive -Path "$env:TEMP\all-Logs\$DT\" -DestinationPath "$env:TEMP\all-Logs-$DT.zip"
copy "$env:TEMP\all-Logs-$DT.zip" "C:\fileshare\"

#delete older zipped log files more than 30 days
Get-ChildItem -Path C:\Fileshare\* -Include all-logs-*.zip -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} | Remove-Item