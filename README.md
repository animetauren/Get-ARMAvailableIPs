# Get-AzureAvailableIPs

- Get-ARMAvailableIPs - Gets the available IPs for Azure Resource Manager Resources.
- Get-ASMAvailableIPs - Gets the available IPs for Azure Service Manager Resources.

## Features - ARM

- VM NICs IP
- ILB IPs
- Orphan NICs that do not have VMs attached to them.
- VPN Gateways with BGP Peering, get's the IP for the BGP Peering
- Added support for Multi-IP NICs

## Features - ASM

- VM IP

## Requirements

- [Azure](https://github.com/Azure/azure-powershell)

## Example - ARM

```powershell
.\Get-ARMAvailableIPs.ps1 -Scope ALL
.\Get-ARMAvailableIPs.ps1 -Scope ALL -Path "D:\IPResults"
.\Get-ARMAvailableIPs.ps1 -Scope SUBNET -SOURCESUB SubnetName -SOURCEVNET VNETName
```
## Example - ASM

```powershell
.\Get-ASMAvailableIPs.ps1 -Scope ALL
.\Get-ASMAvailableIPs.ps1 -Scope ALL -Path "D:\IPResults"
.\Get-ASMAvailableIPs.ps1 -Scope SUBNET -SOURCESUB SubnetName -SOURCEVNET VNETName
```

## ARM Sample Run

![image](https://cloud.githubusercontent.com/assets/1291811/24418883/7be5ec22-13bb-11e7-9414-e15d74b0cabb.png)

## Copyright

Copyright Henry Robalino

Licensed under MIT
