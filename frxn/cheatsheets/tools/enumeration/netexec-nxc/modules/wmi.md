---
tags:
  - wmi
  - netexec
  - enumeration
  - credential-dumping
  - privilege-escalation
---

# WMI

### Low Privilege Modules

#### Enumeration

| Module          | Description                                                                    |
| --------------- | ------------------------------------------------------------------------------ |
| `ioxidresolver` | This module helps you to identify hosts that have additional active interfaces |
| `spooler`       | Detect if print spooler is enabled or not                                      |
| `zerologon`     | Module to check if the DC is vulnerable to Zerologon aka CVE-2020-1472         |

### High Privilege Modules

#### Enumeration

| Module               | Description                                                             |
| -------------------- | ----------------------------------------------------------------------- |
| `bitlocker`          | Enumerating BitLocker Status on target(s) If it is enabled or disabled. |
| `enum_dns`           | Uses WMI to dump DNS from an AD DNS Server                              |
| `get_netconnections` | Uses WMI to query network connections.                                  |

#### Credential Dumping

| Module          | Description                                                                             |
| --------------- | --------------------------------------------------------------------------------------- |
| `ntds-dump-raw` | Extracting the ntds.dit, SAM, and SYSTEM files from DC by accessing the raw hard drive. |

#### Privilege Escalation

| Module | Description          |
| ------ | -------------------- |
| `rdp`  | Enables/Disables RDP |
