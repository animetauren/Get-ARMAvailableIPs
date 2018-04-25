<#
.SYNOPSIS 
    Retrieves and outputs to screen and a .csv file all the Available and Non-available IP Addresses
    for every subnet in your Azure Subscription.
.Credits
    New-IPRange - https://gallery.technet.microsoft.com/scriptcenter/New-IPRange-Build-an-array-51362259
    Get-Broadcast - https://ficility.net/tag/get-broadcast/
.DESCRIPTION
	Will obtain your VNET config for your azure subscription, then will parse
    though the configuration  and retrieve all or a specific subnet IP Addresses.
	
    This currently only checks against the following:
    -VM NICs IP
    -ILB IPs
    -Orphan NICs that do not have VMs attached to them.
    -VPN Gateways with BGP Peering, get's the IP for the BGP Peering
    -Added support for Multi-IP NICs

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
    PS C:\> .\Get-ARMAvailableIPs -Scope ALL --- Get's the IPs for every single VNET and Subnet in the subscription.
    PS C:\> .\Get-ARMAvailableIPs -Scope SUBNET -SOURCESUB SubnetName -SOURCEVNET VNETName --- Get's the IPs for the specified VNET and Subnet in that subscription.
    PS C:\> .\Get-ARMAvailableIPs -Scope ALL -Path "D:\IPResults" --- Get's the IPs for every single VNET and Subnet in the subscription and places them inside the D:\IPResults

.NOTES
    File Name   : Get-ARMAvailableIPs.ps1
    Author      : Henry Robalino - https://anmtrn.com
    Version     : 1.1.3 - Mar 28, 2017
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

function New-IPv4toBin ($ipv4){
 $BinNum = $ipv4 -split '\.' | ForEach-Object {[System.Convert]::ToString($_,2).PadLeft(8,'0')}
 return $binNum -join ""
}

#region Global Variables

Write-Host "Checking if AzureRM Module is installed..."
if((Get-Module -ListAvailable -Name AzureRM.*)) {
    Write-Host "Module exists continuing...`n"
}
else{
    Write-Host "Module does not exist...installing Module"
    Install-Module -Name AzureRM
    . $profile
    Import-Module -Name AzureRM
    Write-Host "AzureRM Module has been installed!`n"
}

$vnetObjects = (Get-AzureRmVirtualNetwork)
$nicObjects = (Get-AzureRmNetworkInterface)
$ilbObjects = (Get-AzureRmLoadBalancer -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

if(!$Path){
    $Path = 'C:\Temp\AvailableIPs'        
}

if(!(Test-Path -LiteralPath $Path)){
    New-Item -Path $Path -ItemType Directory | Out-Null
}

Write-Host "Location of CSV file is the following: $Path"

$table = @()
$ipTable = @()
$availTable = @()
$nameTable= @()

$css = @"
<style>
h1, h5, th { text-align: center; font-family: Segoe UI; }
table { margin: auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
th { background: #0046c3; color: #fff; max-width: 400px; padding: 5px 10px; }
td { font-size: 11px; padding: 5px 20px; color: #000; }
tr { background: #b8d1f3; }
tr:nth-child(even) { background: #dae5f4; }
tr:nth-child(odd) { background: #b8d1f3; }
</style>
"@

#endregion

switch($Scope)
{
ALL
{ 

$nicVNET = $nicObjects.IpConfigurations.Subnet.Id
$tableIndex = 0

foreach($vnet in $vnetObjects){

$vnetname = $vnet.Name
$subnetNames = @($vnet.Subnets.Name)
Write-Host "`nChecking Subnets in VNET: $vnetname" -ForegroundColor Green
Write-Host "****************************************************"

#Get's the IPs of NICs that are in the VNET we are checking.
foreach ($nic in $nicObjects){
    if(($nic.IpConfigurations.Subnet.Id) -match $vnetname){
        #Checking if Multi-IP NIC
        $nicIPList = $nic.IpConfigurations.PrivateIPAddress
        if($nicIPList.count -gt 1){
            foreach($multiSingleIP in $nicIPList.split("")){
                $nicArray += ,$multiSingleIP
            }
        }
        else{
            $nicArray += ,$nicIPList
        }
    }   
}

#Get's the IPs of ILBs that are in the VNET we are checking.
foreach ($ilb in $ilbObjects){
    if(($ilb.FrontendIPConfigurations.Subnet.Id) -match $vnetname){
        $ilbIPArray += ,$ilb.FrontendIPConfigurations.PrivateIpAddress
    }   
}

#The index here is needed for the IPRangesArray to work properly
$reservedIndex = 0

######### Subnet Foreach #########
foreach($subnet in $subnetNames){
Write-Host "`nChecking Availability for IP Addresses in Subnet: $subnet`n"

$vnetAddress = $vnet.AddressSpace.AddressPrefixes
$vnetSubnetsCIDR = @($vnet.Subnets.AddressPrefix)
$numofSubnets = $vnetSubnetsCIDR.Count
$tableIndex = 0

#This foreach loop gets me the subnet address without the cidr notation.
foreach($prefix in $vnetSubnetsCIDR){
    $subnetPrefixMod += ,($prefix.Substring(0,$prefix.Length-3))   
}

#This foreach loop gets me the subnet address broadcast ip.
foreach($vnetSubnetItem in $vnetSubnetsCIDR){
    $broadcastArray += ,(Get-Broadcast $vnetSubnetItem)
}

#region ArrayofIPRanges for Subnets

$i = 0
$j = 0 

#Creates Array of Arrays filled with IP Ranges
while($numofSubnets -gt 0){

    $IPRangesArray += ,@(New-IPRange $subnetPrefixMod[$i] $broadcastArray[$j])
    $i++
    $j++
    
    $numofSubnets--
}

#endregion ArrayofIPRanges for Subnets

#Get's the index for the broadcast IP
$tableCountIndex = $IPRangesArray[$reservedIndex].Length
$lenghtofArrayBroadCast = $IPRangesArray[$reservedIndex].Length - 1

#Index for IPs inside IPRangesArray
$k = 0

#Get's the First 3 IPs that are reserved for Azure
while($k -lt 4){
        $IPReserved = $IPRangesArray[$reservedIndex][$k]
        Write-Host "$IPReserved is RESERVED FOR AZURE" -ForegroundColor Red
        $k++ 
        $ipTable += ,$IPReserved
        $availTable += ,"False"
        $nameTable += ,"Reserved for Azure"
}

#If the Subnet is the GatewaySubnet then we look to see if it is BGP Enabled and grab the IP of it.
if($subnet -eq "GatewaySubnet"){

    $rgNameofVNET = $vnet.ResourceGroupName
    $gw = (Get-AzureRmVirtualNetworkGateway -ResourceGroupName $rgNameofVNET)
    $gwIP = $gw.BgpSettings.BgpPeeringAddress
    $gwName = $gw.Name
}

#Compares the IPs from NICs to those from IP Block.
$ipAvail = 0
$vmIndex = 0
$ilbIndex = 0
$azureBlockedIndex = 0

$IPBroadCast = $IPRangesArray[$reservedIndex][$lenghtofArrayBroadCast]

foreach($ip in $IPRangesArray[$reservedIndex]){
    if($azureBlockedIndex -lt 4){
    $azureBlockedIndex++
    }
    elseif($ip -eq $IPBroadCast){
        #Writes the BroadCast IP that is reserved for Azure
        Write-Host "$IPBroadCast is RESERVED FOR AZURE" -ForegroundColor Red
        Write-Host "`nThere are $ipAvail IPs available for this subnet: $subnet" -ForegroundColor Yellow
        
        $ipTable += ,$IPBroadCast
        $availTable += ,"False"
        $nameTable += ,"Reserved for Azure"             
    }
    else{
        if($nicArray -contains $ip){
            foreach ($nic in $nicObjects){
                $nicIP = $nic.IpConfigurations.PrivateIPAddress
                if($nicIP -eq $ip){
                    if($nic.VirtualMachine -ne $null){
                        $nicVMName = $nic.VirtualMachine.Id.Split("/")[-1]
                    }
                    else{
                        $nicVMName = "Orphan_NIC.$($nic.Name)"
                    } 
                }      
            }
            #Checks to see if NIC is orphaned.
            if($nicVMName.Split(".")[0] -eq "Orphan_NIC"){
                Write-Host "$ip is being used by an ORPHAN NIC - $($nicVMName.Split(".")[1])" -ForegroundColor Red
            }
            else{
                Write-Host "$ip is being used by a NIC on this VM - $nicVMName" -ForegroundColor Red
            }

            $ipTable += ,$ip
            $availTable += ,"False"
            $nameTable += ,$nicVMName
        }
        elseif($ilbIPArray -contains $ip){
            foreach ($ilb in $ilbObjects){
                $ilbIP = $ilb.FrontendIPConfigurations.PrivateIpAddress
                if($ilbIP -eq $ip){
                    $ilbName = $ilb.name
                    }                   
            }
            Write-Host "$ip is being used by an ILB - $ilbName" -ForegroundColor Red
            $ipTable += ,$ip
            $availTable += ,"False"
            $nameTable += ,$ilbName
        }
        elseif($gwIP -contains $ip){
            Write-Host "$ip is being used by a GW - $gwName" -ForegroundColor Red
            $ipTable += ,$ip
            $availTable += ,"False"
            $nameTable += ,$gwName
        }
        else{
            Write-Host "$ip is available" -ForegroundColor Green
            $ipAvail++
            $ipTable += ,$ip
            $availTable += ,"True"
            $nameTable += ,"N/A"
        }
    }
}

$IPRangesArray = $null
$IPReserved = $null
$reservedIndex++
$ipAvail = $null
$vmIndex = $null

###############
while($tableCountIndex -ne 0){

$objIPTable = New-Object System.Object
$objIPTable | Add-Member -type NoteProperty -name IPAddress -value $ipTable[$tableIndex]
$objIPTable | Add-Member -type NoteProperty -name Availability -value $availTable[$tableIndex]
$objIPTable | Add-Member -type NoteProperty -name ResourceName -value $nameTable[$tableIndex]
$table += $objIPTable

$tableIndex++
$tableCountIndex--
}
##############

$file = "$Path\AvailableIps-for-Vnet-$vnetname-Subnet-$subnet.csv"
$table | Select-Object IPAddress,Availability,ResourceName | Export-Csv -Path $file -NoTypeInformation | Out-Null

#Import-CSV $file | ConvertTo-Html -Head $css -Body "<h1>Source VNET: $SourceVNET - Source Subnet: $SourceSUB</h1>" | Out-File "C:\temp\test.html"

#
$table = @()
$ipTable = @()
$availTable = @()
$nameTable= @()
#

} #Closes the foreach for subnets
######### Subnet Foreach #########

#The following need to be nulled or else their values affect the arrays created in the subnet loop.
$reservedIndex = $null
$subnetPrefixMod = $null
$broadcastArray =$null
$nicArray = $null
$nicVMName = $null
$ilbIPArray = $null
$ilbName = $null
$ilbIP = $null
$gwIP = $null
$gwName = $null
} #Closes the foreach for vnets

}
SUBNET
{

If (($SourceSUB) -and ($sourceVNET)){

$prefixIndex = 0 
$tableIndex = 0

#region VNET Locating
foreach($vnet in $vnetObjects){
    if($vnet.Name -eq $SourceVNET){
        $vnetChosen = $vnet
    }    
}

if(!$vnetChosen){
        Write-Host "`nVNET Does not Exist in VNET Configuration. Try again with correct VNET Name." -ForegroundColor Red
        exit
}

#endregion VNET Locating

#region Subnet IP Prefix Locating
$subnetNames = @($vnetChosen.Subnets.Name)
    foreach($subnet in $subnetNames){                
        if($subnet -eq $SourceSUB){
            $numofAddressPrefix = $vnetChosen.Subnets.AddressPrefix.count
            if($numofAddressPrefix -gt 1){            
                $subnetPrefix = $vnetChosen.Subnets.AddressPrefix[$prefixIndex]
            }
            else{
                $subnetPrefix = $vnetChosen.Subnets.AddressPrefix
            }
        }
        else{
            $prefixIndex++
        }
    }

$prefixIndex = $null

if(!$subnetPrefix){
        Write-Host "`nSubnet Does not Exist in VNET Configuration. Try again with correct Subnet Name." -ForegroundColor Red
        exit
}

#endregion Subnet IP Prefix Locating

#Get's the IPs of NICs that are in the VNET we are checking.
foreach ($nic in $nicObjects){
    $nicVNETName = $nic.IpConfigurations.Subnet.Id.Split("/")[-3]
    if($nicVNETName -eq $sourceVNET){
        #Checking if Multi-IP NIC
        $nicIPList = $nic.IpConfigurations.PrivateIPAddress
        if($nicIPList.count -gt 1){
            foreach($multiSingleIP in $nicIPList.split("")){
                $nicArray += ,$multiSingleIP
            }
        }
        else{
            $nicArray += ,$nicIPList
        }
    }      
}

#Get's the IPs of ILBs that are in the VNET we are checking.
foreach ($ilb in $ilbObjects){
    if(($ilb.FrontendIPConfigurations.Subnet.Id) -match $sourceVNET){
        $ilbIPArray += ,$ilb.FrontendIPConfigurations.PrivateIpAddress
    }   
}

#Get's the IPs of GW BGP that are in the SUBNET/VNET we are checking.

if($SourceSUB -eq "GatewaySubnet"){

    $rgNameofVNET = $vnetChosen.ResourceGroupName
    $gw = (Get-AzureRmVirtualNetworkGateway -ResourceGroupName $rgNameofVNET)
    $gwIP = $gw.BgpSettings.BgpPeeringAddress
    $gwName = $gw.Name
}
 
#Below we do Subnet Mod and get IPRanges
$subnetPrefixMod = ($subnetPrefix.Substring(0,$subnetPrefix.Length-3))   
$subnetPrefixBR = Get-Broadcast $subnetPrefix
$IPRangesArray = @(New-IPRange $subnetPrefixMod $subnetPrefixBR)

#Get's the index for the broadcast IP
$tableCountIndex = $IPRangesArray.Length
$lenghtofArrayBroadCast = $IPRangesArray.Length - 1

Write-Host "`nChecking Subnet: $SourceSUB in VNET: $SourceVNET" -ForegroundColor Green
Write-Host "****************************************************"

#Index for IPs inside IPRangesArray
$k = 0

#Get's the First 3 IPs that are reserved for Azure
while($k -lt 4){
        $IPReserved = $IPRangesArray[$k]
        Write-Host "$IPReserved is RESERVED FOR AZURE" -ForegroundColor Red
        $k++ 
        $ipTable += ,$IPReserved
        $availTable += ,"False"
        $nameTable += ,"Reserved for Azure"
}

###############
#Compares the IPs from NICs to those from IP Block.
$ipAvail = 0
$azureBlockedIndex = 0
$IPBroadCast = $IPRangesArray[$lenghtofArrayBroadCast]

foreach($ip in $IPRangesArray){
    if($azureBlockedIndex -lt 4){
        $azureBlockedIndex++
    }
    elseif($ip -eq $IPBroadCast){
        #Writes the BroadCast IP that is reserved for Azure        
        Write-Host "$IPBroadCast is RESERVED FOR AZURE" -ForegroundColor Red
        Write-Host "`nThere are $ipAvail IPs available for this subnet: $SourceSUB" -ForegroundColor Yellow 

        $ipTable += ,$IPBroadCast
        $availTable += ,"False"
        $nameTable += ,"Reserved for Azure"               
    }
    else{
        if($nicArray -contains $ip){
            foreach ($nic in $nicObjects){
                $nicIP = $nic.IpConfigurations.PrivateIPAddress
                if($nicIP -eq $ip){
                    if($nic.VirtualMachine -ne $null){
                        $nicVMName = $nic.VirtualMachine.Id.Split("/")[-1]
                    }
                    else{
                        $nicVMName = "Orphan_NIC.$($nic.Name)"
                    }      
                }
            }
            #Checks to see if NIC is orphaned.
            if($nicVMName.Split(".")[0] -eq "Orphan_NIC"){
                Write-Host "$ip is being used by an ORPHAN NIC - $($nicVMName.Split(".")[1])" -ForegroundColor Red
            }
            else{
                Write-Host "$ip is being used by a NIC on this VM - $nicVMName" -ForegroundColor Red
            }

            $ipTable += ,$ip
            $availTable += ,"False"
            $nameTable += ,$nicVMName
        }
        elseif($ilbIPArray -contains $ip){
            foreach ($ilb in $ilbObjects){
                $ilbIP = $ilb.FrontendIPConfigurations.PrivateIpAddress
                if($ilbIP -eq $ip){
                    $ilbName = $ilb.name
                    }   
                
            }
            Write-Host "$ip is being used by an ILB - $ilbName" -ForegroundColor Red
            $ipTable += ,$ip
            $availTable += ,"False"
            $nameTable += ,$ilbName
        }
        elseif($gwIP -contains $ip){
            Write-Host "$ip is being used by a GW - $gwName" -ForegroundColor Red
            $ipTable += ,$ip
            $availTable += ,"False"
            $nameTable += ,$gwName
        }
        else{
            Write-Host "$ip is available" -ForegroundColor Green
            $ipAvail++
            $ipTable += ,$ip
            $availTable += ,"True"
            $nameTable += ,"N/A"
        }
    }
}
###############

$nicArray = $null
$nicVMName = $null
$ilbIPArray = $null
$ilbName = $null
$gwIP = $null
$gwName = $null

###############
while($tableCountIndex -ne 0){

$objIPTable = New-Object System.Object
$objIPTable | Add-Member -type NoteProperty -name IPAddress -value $ipTable[$tableIndex]
$objIPTable | Add-Member -type NoteProperty -name Availability -value $availTable[$tableIndex]
$objIPTable | Add-Member -type NoteProperty -name ResourceName -value $nameTable[$tableIndex]
$table += $objIPTable

$tableIndex++
$tableCountIndex--
}
##############

$file = "$Path\AvailableIps-for-Vnet-$SourceVNET-Subnet-$SourceSUB.csv"
$table | Select-Object IPAddress,Availability,ResourceName | Export-Csv -Path $file -NoTypeInformation | Out-Null

Import-CSV $file | ConvertTo-Html -Head $css -Body "<h1>Source VNET: $SourceVNET - Source Subnet: $SourceSUB</h1>" | Out-File "C:\temp\test.html"

} #closes First If Loop checking Sub & VNET info.

}
}
