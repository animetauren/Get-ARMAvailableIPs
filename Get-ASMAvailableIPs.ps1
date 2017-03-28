<#

.SYNOPSIS 
    Retrieves and outputs to a .csv file all Available and Non-available IP Addresses
    for every subnet in your Azure Subscription.

.DESCRIPTION
	
    Will obtain your VNET config.xml for your azure subscription, then will parse
    though the .xml file and retrieve all or a specific subnet IP Addresses.

.Credits
    New-IPRange - https://gallery.technet.microsoft.com/scriptcenter/New-IPRange-Build-an-array-51362259
    Get-Broadcast - https://ficility.net/tag/get-broadcast/

.PARAMETER Scope
    ALL : Runs script against all Subnets
    SubNet: Specifies that you want to scan through a specific SubNet
    Mandatory parameter
    No default value.

.PARAMETER SourceSub
	Name of the subnet that this script will be run against.
    No default value.

.PARAMETER SourceVNET
	Name of the VNet that this script will be run against.
    No default value.

.PARAMETER Path
	Literal Path of where to save the CSV file results. If none is provided, then the save location will be C:\Temp\AvailableIPs
    No default value.
        

.EXAMPLE
    PS C:\> .\Get-ASMAvailableIPs -Scope ALL
	PS C:\> .\Get-ASMAvailableIPs -Scope SUBNET -SOURCESUB subnetname -SOURCEVNET Vnetname
    PS C:\> .\Get-ASMAvailableIPs -Scope ALL -Path "D:\IPResults"

.NOTES
    File Name   : Get-ASMAvailableIPs.ps1
    Author      : Henry Robalino - https://anmtrn.com & Rafael Yactayo
    Version     : 1.0 - Mar 28, 2017
#>

param(
		[parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$Scope,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
		[String]$SourceSUB,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
		[String]$SourceVNET,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
		[String]$Path

)

#Functions to retrieve list of all IPs in a subnet using CIDR

function New-IPRange ($start, $end) {
 # created by DTW, MVP PowerShell
 $ip1 = ([System.Net.IPAddress]$start).GetAddressBytes()
 [Array]::Reverse($ip1)
 $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address
 $ip2 = ([System.Net.IPAddress]$end).GetAddressBytes()
 [Array]::Reverse($ip2)
 $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address
 for ($x=$ip1; $x -le $ip2; $x++) {
 $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
 [Array]::Reverse($ip)
 $ip -join '.'
 }
}

function New-IPv4toBin ($ipv4){
 $BinNum = $ipv4 -split '\.' | ForEach-Object {[System.Convert]::ToString($_,2).PadLeft(8,'0')}
 return $binNum -join ""
}

function Get-Broadcast ($addressAndCidr){
 $addressAndCidr = $addressAndCidr.Split("/")
 $addressInBin = (New-IPv4toBin $addressAndCidr[0]).ToCharArray()
 for($i=0;$i -lt $addressInBin.length;$i++){
 if($i -ge $addressAndCidr[1]){
 $addressInBin[$i] = "1"
 } 
 }
 [string[]]$addressInInt32 = @()
 for ($i = 0;$i -lt $addressInBin.length;$i++) {
 $partAddressInBin += $addressInBin[$i] 
 if(($i+1)%8 -eq 0){
 $partAddressInBin = $partAddressInBin -join ""
 $addressInInt32 += [Convert]::ToInt32($partAddressInBin -join "",2)
 $partAddressInBin = ""
 }
 }
 $addressInInt32 = $addressInInt32 -join "."
 return $addressInInt32
}

$vm = Get-AzureVM

if(!$Path){
    $Path = 'C:\Temp\AvailableIPs'
    $Pathxml = 'C:\Temp\AvailableIPs\VnetConfig.xml'        
}

if(!(Test-Path -LiteralPath $Path)){
    New-Item -Path $Path -ItemType Directory | Out-Null
    $Pathxml = "$Path\VnetConfig.xml"

}

Write-Host "Location of CSV file is the following: $Path"

switch($Scope)
{
ALL
{ 

#Create Directory and output VNET Config.xml to the directory
New-Item -Path $Path -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Get-AzureVNetConfig -ExportToFile $Pathxml | Out-Null
Write-Host "Created Vnetconfig.xml file in path $Path" -Foregroundcolor Green `n

#Will retrieve all IPs for all running VMs and store them in $VMIPAddresses to compare later

        $ServiceName = @(($vm).ServiceName)
        $vmName = @(($vm).Name)
        $count = $vm.count
        $m=0

#Parsing the .xml file to get Subnets, and IPs

$xml = [xml](Get-Content $Pathxml)
$i=1 #index for each VNET in the .xml File
$j=0 #index for each Subnet in a VNet in the .xml File
$k=0 #index for the Subnet name for outputing the .csv File with the subnet name
$x=0 #index for output for .csv
$n=0 #index for the array that holds All the IP addresses in the array $allSubIPs
$table = @() #Array to hold the object to output to a .csv File
$VMNames = @() #This will store all VM Names in the array if no VM name exists N/A will be added
$TFTable =@() #Array to hold if IPAddress is available or not available


$XMLArray = $xml.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites.VirtualNetworkSite |
select @{ L = 'VNetName';      E = { $_.Name } },
       @{ L = 'SubnetName';   E = { $_.Subnets.Subnet.Name } },
       @{ L = 'Subnets';   E = { $_.Subnets.Subnet.AddressPrefix } }
       
       $subnetarray = $XMLArray.Subnets #Array of CIDR IPADDRESS
       $XMLArrayCount = $XMLArray.VNetName.Count
       $subnetnamearray = $XMLArray.SubnetName #Array of Subnet Names

while($XMLArrayCount -ne 0) #Goes through all VNETS in the .xml file
{
        Write-Host "Checking subnets in VNET:" $XMLArray[$i].VNetName -Foregroundcolor Green `n
        Write-Host "************************************************************************"
        $subnetnamecount = $XMLArray[$i].SubnetName.Count
        
        while($subnetnamecount -ne 0) #Goes through all Subnets in the .xml file
        {     
           
        Write-Host "Checking Availability for IP Addresses in subnet:" $subnetnamearray[$k] `n
                foreach($IPAddress in $XMLArray[$i].Subnets[$j])
                {
                $IPMod = $IPAddress.Split("/")

                $allSubIPs = @(New-IPRange $IPMod (Get-Broadcast $IPAddress)) #Will retrieve ALL IP ADDRESSES in the subnet
                $allsubcount = $allSubIPs.Count
                $allsubcountmfour = $allSubIPs.Count - 4 #The first 4 Ips for azure are always reserved
                $numIPTaken = 0
                $numIPNotTaken = 0


                    while($allsubcount -gt $allsubcountmfour) #Goes through the first 4 IPs and sets as Reserved
                    {
                    Write-Host $allSubIPs[$n] "is RESERVED FOR AZURE" -ForegroundColor Red
                    $TFTable += "Reserved-for-Azure"
                    $VMNames += "Reserved-for-Azure"
                    $allsubcount --
                    $n++
                    }

                    while($allsubcountmfour -ne 1) #Goes through all IPs 
                    {

                    $Address = Test-AzureStaticVNetIP -VNetName $XMLArray[$i].VNetName -IPAddress $allSubIPs[$n] -ErrorAction SilentlyContinue #Check if IPAddress is available

                        If ($Address.IsAvailable –eq $False) #IF IP is not available find the VMNAME if any that is associated with the IPAddress
                        { 
                            Write-Host $allSubIPs[$n] "is not available" -ForegroundColor Red 
                            $TFTable += "Not-Available"
                            $numIPTaken ++ #Counts how many IPs are taken
                            $countchecker = $count

                                 while ($count -ne 0)
                                     {  
                                      $VMNameText = $VMName[$m]
                                      $VMServiceName = $ServiceName[$m]
                                      
                                      $IPAddress2 = ($vm | where {($_.ServiceName -eq $VMServiceName) -and ($_.Name -eq $VMNameText)}).IpAddress
                                        
                                        if($IPAddress2 -eq $allSubIPs[$n] )
                                           {
                                           $VMNames += $VMNameText
                                           Write-Host "VM:" $VMNameText "Is using this IP" -ForegroundColor Yellow
                                           $n++
                                           break
                                           }
                                        else
                                           {
                                           $Checker++
                                            if($Checker -eq $countchecker)
                                                {
                                                $checkTF = 1
                                                }
                                            else
                                                {
                                                $checkTF = 0
                                                }
                                           }
                                        
                                      $count--
                                      $m++ 
                                     }
                                     $m=0 
                                    $count = $countchecker
                                       if($checkTF -eq 1)
                                          {
                                           $VMNames += "No-VM-Present"
                                           Write-Host "No VM Present for this IP" -ForegroundColor Yellow
                                           $n++
                                          }
                                        $Checker = $null
                                        
                        } 
                        else 
                        { 
                            Write-Host $allSubIPs[$n] "is available" -ForegroundColor Green
                            $numIPNotTaken ++ #Counts how many IPs are not taken
                            $TFTable += "Available"                      
                            $VMNames += "N/A"
                            $n++
                        }
                    $allsubcountmfour--
                    }
                    
                    if($allsubcountmfour -eq 1) #Last IP is always Reserved
                    {
                    Write-Host $allSubIPs[$n] "is RESERVED FOR AZURE" -ForegroundColor Red
                    $TFTable += "Reserved-for-Azure"
                    $VMNames += "Reserved-for-Azure"
                    $allsubcountmfour --
                    $n++
                    }

                    $allsubcountmfour = 0 
                    $n = 0            
                
                #Store all arrays into $objAverage 
                  $allsubcount = $allSubIPs.Count #Set count back to original
                  while($allsubcount -ne 0)
                        {
                            $objIPTable = New-Object System.Object
                            $objIPTable | Add-Member -type NoteProperty -name IPAddress -value $allSubIPs[$x]
                            $objIPTable | Add-Member -type NoteProperty -name Availability -value $TFTable[$x]
                            $objIPTable | Add-Member -type NoteProperty -name VMName -value $VMNames[$x]
                            $table += $objIPTable

                            $allsubcount --
                            $x++  
                        } 
                        $x=0                         
                }
                #Writes to Console Number of IPs Avail and Not Avail in Subnet
                $numIPTaken += 5 #Adds5 because total of five IPs are reserved by Azure and by system.
                Write-Host "`nThis Subnet:" $subnetnamearray[$k] "has $numIPNotTaken Available IP(s) and $numIPTaken Not Available IP(s).`n"
                #Outputs the Availability for each subnet to a .csv file
                $subnetnameIndex = $subnetnamearray[$k]
                $file = "$Path\AvailableIps-for-$subnetnameIndex.csv"
                $table | Select-Object IPAddress,Availability,VMName | Export-Csv -Path $file -NoTypeInformation | Out-Null
                Write-Host "Created .csv for Subnet:"  $subnetnamearray[$k]
                Write-Host "-----------------------------------------------------------------------"`n
                $table = @()
                $TFTable = @()
                $VMNames = @()
                $compare = $null
                $j++
                $k++
                
                $subnetnamecount--         
        }  
        
 $i++
 $j=0
 $XMLArrayCount--
}

} 
SUBNET
{
If (($SourceSUB) -and ($sourceVNET))
{

#Create Directory and output VNET Config.xml to the directory
New-Item -Path $Path -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Get-AzureVNetConfig -ExportToFile $Pathxml | Out-Null
Write-Host "Created Vnetconfig.xml file in path $Path" -Foregroundcolor Green `n

#Will retrieve all IPs for all running VMs and store them in $VMIPAddresses to compare later

        $ServiceName = @(($vm).ServiceName)
        $vmName = @(($vm).Name)
        $count = $vm.count
        $m=0

#Parsing the .xml file to get Subnets, and IPs

$xml = [xml](get-content $Pathxml)
$i=0 #index for each VNET in the .xml File
$j=0 #index for each Subnet in a VNet in the .xml File
$k=0 #index for the Subnet name for outputing the .csv File with the subnet name
$x=0 #index for output for .csv
$n=0 #index for the array that holds All the IP addresses in the array $allSubIPs
$m=0
$o=0
$table = @() #Array to hold the object to output to a .csv File
$VMNames = @() #This will store all VM Names in the array if no VM name exists N/A will be added
$TFTable =@() #Array to hold if IPAddress is available or not available


$XMLArray = $xml.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites.VirtualNetworkSite |
select @{ L = 'VNetName';      E = { $_.Name } },
       @{ L = 'SubnetName';   E = { $_.Subnets.Subnet.Name } },
       @{ L = 'Subnets';   E = { $_.Subnets.Subnet.AddressPrefix } }
       
       $subnetarray = $XMLArray.Subnets #Array of CIDR IPADDRESS
       $XMLArrayCount = $XMLArray.VNetName.Count
       $XMLArrayVNET = $XMLArray.VNetName
       $subnetnamearray = $XMLArray.SubnetName #Array of Subnet Names

while($XMLArray[$i].VNetName -ne $SourceVNET)
{
$i++
}

while($XMLArray[$i].SubnetName[$j] -ne $SourceSUB)
{
$j++
}
$subnetnamearray = $XMLArray[$i].SubnetName[$j]
$IPAddress = $XMLArray[$i].Subnets[$j]

     Write-Host "Checking Availability for IP Addresses in subnet:" $subnetnamearray `n
                $IPMod = $IPAddress.Split("/")
                $allSubIPs = @(New-IPRange $IPMod (Get-Broadcast $IPAddress)) #Will retrieve ALL IP ADDRESSES in the subnet
                $allsubcount = $allSubIPs.Count
                $allsubcountmfour = $allSubIPs.Count - 4 #The first 4 Ips for azure are always reserved
                $numIPTaken = 0
                $numIPNotTaken = 0

                    while($allsubcount -gt $allsubcountmfour) #Goes through the first 4 IPs and sets as Reserved
                    {
                    Write-Host $allSubIPs[$n] "is RESERVED FOR AZURE" -ForegroundColor Red
                    $TFTable += "Reserved-for-Azure"
                    $VMNames += "Reserved-for-Azure"
                    $allsubcount --
                    $n++
                    }

                    while($allsubcountmfour -ne 1) #Goes through all IPs 
                    {

                    $Address = Test-AzureStaticVNetIP -VNetName $XMLArray[$i].VNetName -IPAddress $allSubIPs[$n] #Check if IPAddress is available

                        If ($Address.IsAvailable –eq $False) #IF IP is not available find the VMNAME if any that is associated with the IPAddress
                        { 
                            Write-Host $allSubIPs[$n] "is not available" -ForegroundColor Red 
                            $TFTable += "Not-Available"
                            $numIPTaken ++ #Counts how many IPs are taken
                            $countchecker = $count

                                 while ($count -ne 0)
                                     {  
                                      $VMNameText = $VMName[$m]
                                      $VMServiceName = $ServiceName[$m]
                                      
                                      $IPAddress2 = ($vm | where {($_.ServiceName -eq $VMServiceName) -and ($_.Name -eq $VMNameText)}).IpAddress 
                                        
                                        if($IPAddress2 -eq $allSubIPs[$n] )
                                           {
                                           $VMNames += $VMNameText
                                           Write-Host "VM:" $VMNameText "is using this IP" -ForegroundColor Yellow
                                           $n++
                                           break
                                           }
                                        else
                                           {
                                           $Checker++
                                            if($Checker -eq $countchecker)
                                                {
                                                $checkTF = 1
                                                }
                                            else
                                                {
                                                $checkTF = 0
                                                }
                                           }
                                        
                                      $count--
                                      $m++ 
                                     }
                                     $m=0 
                                    $count = $countchecker
                                       if($checkTF -eq 1)
                                          {
                                           $VMNames += "No-VM-Present"
                                           Write-Host "No VM Present for this IP" -ForegroundColor Yellow
                                           $n++
                                          }
                                        $Checker = $null
                                        
                        } 
                        else 
                        { 
                            Write-Host $allSubIPs[$n] "is available" -ForegroundColor Green
                            $numIPNotTaken ++ #Counts how many IPs are not taken
                            $TFTable += "Available"                      
                            $VMNames += "N/A"
                            $n++
                        }
                    $allsubcountmfour--
                    }
                    
                    if($allsubcountmfour -eq 1) #Last IP is always Reserved
                    {
                    Write-Host $allSubIPs[$n] "is RESERVED FOR AZURE" -ForegroundColor Red
                    $TFTable += "Reserved-for-Azure"
                    $VMNames += "Reserved-for-Azure"
                    $allsubcountmfour --
                    $n++
                    }

                    $allsubcountmfour = 0 
                    $n = 0  

                  #Store all arrays into $objAverage 
                  $allsubcount = $allSubIPs.Count #Set count back to original
                  while($allsubcount -ne 0)
                        {
                            $objIPTable = New-Object System.Object
                            $objIPTable | Add-Member -type NoteProperty -name IPAddress -value $allSubIPs[$x]
                            $objIPTable | Add-Member -type NoteProperty -name Availability -value $TFTable[$x]
                            $objIPTable | Add-Member -type NoteProperty -name VMName -value $VMNames[$x]
                            $table += $objIPTable

                            $allsubcount --
                            $x++  
                        } 

                        $x=0                         
                #Writes to Console Number of IPs Avail and Not Avail in Subnet
                $numIPTaken += 5 #Adds5 because total of five IPs are reserved by Azure and by system.
                Write-Host "`nThis Subnet:" $subnetnamearray[$k] "has $numIPNotTaken Available IP(s) and $numIPTaken Not Available IP(s).`n"

                #Outputs the Availability for each subnet to a .csv file
                $subnetnameIndex = $subnetnamearray
                $file = "$Path\AvailableIps-for-$subnetnameIndex.csv"
                $table | Select-Object IPAddress,Availability,VMName | Export-Csv -Path $file -NoTypeInformation | Out-Null
                Write-Host "Created .csv for Subnet:"  $subnetnamearray                    
          
    
}
else
{
Write-Host -foregroundcolor Red "Request for Available IPs for a Subnet reporting failed due to missing cmdline option"
}
}
}
