New-Item -Path "C:\" -Name "modelfiles" -ItemType "directory" -ErrorAction Ignore
New-Item -Path "C:\" -Name "Tools" -ItemType "directory" -ErrorAction Ignore
Invoke-WebRequest -outfile "./modelfiles/model.archive" -usebasicparsing -Uri https://raw.githubusercontent.com/chuckthompsonprofisee/kubernetespublic/main/smallmodel.archive
Invoke-WebRequest -outfile "./modelfiles/model.maestromodel" -usebasicparsing -Uri https://raw.githubusercontent.com/chuckthompsonprofisee/kubernetespublic/main/smallmodel.maestromodel
Invoke-WebRequest -outfile "./modelfiles/Product.maestroform" -usebasicparsing -Uri https://raw.githubusercontent.com/chuckthompsonprofisee/kubernetespublic/main/Product.maestroform
Invoke-WebRequest -outfile "./modelfiles/Product.portalapplication" -usebasicparsing -Uri https://raw.githubusercontent.com/chuckthompsonprofisee/kubernetespublic/main/Product.portalapplication
Invoke-WebRequest -outfile "./modelfiles/Product.presentationview" -usebasicparsing -Uri https://raw.githubusercontent.com/chuckthompsonprofisee/kubernetespublic/main/Product.presentationview
Invoke-WebRequest -outfile "./Tools/Profisee.Platform.Utilities.Internal.EncryptDecrypt.zip" -usebasicparsing -Uri https://raw.githubusercontent.com/chuckthompsonprofisee/kubernetespublic/main/Profisee.Platform.Utilities.Internal.EncryptDecrypt.zip
Expand-Archive -LiteralPath 'C:\Tools\Profisee.Platform.Utilities.Internal.EncryptDecrypt.zip' -DestinationPath C:\Tools -force
$sqlQuery = "SELECT ClientID FROM [meta].[tUser] WHERE NAME LIKE '$env:ProfiseeAdminAccount'"
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection;
$SqlConnection.ConnectionString = 'Data Source={0};database={1};User ID={2};Password={3}' -f $env:ProfiseeSqlServer,$env:ProfiseeSqlDatabase,$env:ProfiseeSqlUserName,$env:ProfiseeSqlPassword;
$SqlConnection.Open();
$SqlCmd = New-Object System.Data.SqlClient.SqlCommand;
$SqlCmd.CommandText = $sqlQuery;$SqlCmd.Connection = $SqlConnection;
$encryptedclientid = $SqlCmd.ExecuteScalar();$SqlConnection.Close();
$encryptedclientid 
Start-Process -FilePath "./Tools/Profisee.Platform.Utilities.Internal.EncryptDecrypt.exe" -WorkingDirectory "./Tools" -ArgumentList " DECRYPT $encryptedclientid"  -NoNewWindow -PassThru -Wait
$ClientID=cat .\Tools\out.txt
$ClientID
$cluexe="C:\Profisee\Utilities\Profisee.MasterDataMaestro.Utilities.exe"
$url = $env:ProfiseeExternalDNSUrl + "/" + $env:ProfiseeWebAppName + "/api/";
$url;
$clientidAndUrl = "/ClientID:"+$ClientID+" /URL:"+$url;
$allImportParms =" /IMPORT /FILE:C:\modelfiles /TYPE:ALL";
$dataImportParms =" /DeployData /FILE:C:\modelfiles\model.archive";
$allArgs=$clientidAndUrl + $allImportParms;
Start-Process -FilePath $cluexe  -ArgumentList $allArgs  -NoNewWindow -PassThru -Wait;
$allArgs=$clientidAndUrl + $dataImportParms;
Start-Process -FilePath $cluexe  -ArgumentList $allArgs  -NoNewWindow -PassThru -Wait;
