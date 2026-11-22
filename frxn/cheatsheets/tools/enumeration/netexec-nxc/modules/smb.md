---
tags:
  - netexec
  - smb
  - enumeration
  - credential-dumping
  - privilege-escalation
---

# SMB

### Low Privilege Modules

#### Enumeration

| Module            | Description                                                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `enum_av`         | Gathers information on all endpoint protection solutions installed on the remote host(s) via LsarLookupNames (no privilege needed).     |
| `enum_ca`         | Anonymously uses RPC endpoints to hunt for ADCS CAs.                                                                                    |
| `gpp_privileges`  | Extracts privileges assigned via GPOs and resolves SIDs via LDAP.                                                                       |
| `ioxidresolver`   | Helps identify hosts that have additional active interfaces.                                                                            |
| `ms17-010`        | MS17-010 — EternalBlue. **NOT TESTED OUTSIDE LAB ENVIRONMENT.**                                                                         |
| `nopac`           | Checks whether the DC is vulnerable to CVE-2021-42278 and CVE-2021-42287, which may allow DA impersonation from a standard domain user. |
| `ntlm_reflection` | Attempts to check whether the OS is vulnerable to CVE-2025-33073 (NTLM Reflection attack).                                              |
| `petitpotam`      | **REMOVED.** Module to check if the DC is vulnerable to PetitPotam. Credit: @topotam.                                                   |
| `printerbug`      | **REMOVED.** Module to check if the target is vulnerable to PrinterBug. Set the listener IP for coercion.                               |
| `printnightmare`  | Checks whether the host is vulnerable to PrintNightmare.                                                                                |
| `remove-mic`      | Checks whether the host is vulnerable to CVE-2019-1040.                                                                                 |
| `sccm-recon6`     | Checks whether the target is a Distribution Point or Primary Site Server through winreg (RECON-6).                                      |
| `shadowcoerce`    | **REMOVED.** Module to check if the target is vulnerable to ShadowCoerce. Credit: @Shutdown and @topotam.                               |
| `smbghost`        | Checks for SMB dialect 3.1.1 and compression capability, an indicator for the SMBGhost vulnerability (CVE-2020-0796).                   |
| `spooler`         | Detects whether the Print Spooler service is enabled.                                                                                   |
| `webdav`          | Checks whether the WebClient service is running on the target.                                                                          |
| `zerologon`       | Checks whether the DC is vulnerable to Zerologon (CVE-2020-1472).                                                                       |

#### Credential Dumping

| Module            | Description                                                                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `aws-credentials` | Searches for AWS credential files.                                                                                                          |
| `gpp_autologin`   | Searches the domain controller for `Registry.xml` to find autologon information and returns the username and password.                      |
| `gpp_password`    | Retrieves plaintext passwords and other information for accounts pushed through Group Policy Preferences.                                   |
| `spider_plus`     | Lists files recursively and saves JSON share-file metadata to the configured `OUTPUT_FOLDER`. See module options for further configuration. |

#### Privilege Escalation

| Module            | Description                                                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `add-computer`    | Adds or deletes a domain computer.                                                                                                            |
| `backup_operator` | Exploits a user in the Backup Operators group to dump NTDS. Credit: @mpgn\_x64.                                                               |
| `change-password` | Changes or resets user passwords via various protocols.                                                                                       |
| `coerce_plus`     | Checks whether the target is vulnerable to coercion vulnerabilities. Set the listener IP for coercion.                                        |
| `dfscoerce`       | **REMOVED.** Module to check if the DC is vulnerable to DFSCoerce. Credits: @filip\_dragovic, @Wh04m1001 and @topotam.                        |
| `drop-library-ms` | Creates and uploads an arbitrary `.library-ms` file on writable shares, leveraging CVE-2025-24054 to obtain an NTLMv2 hash.                   |
| `drop-sc`         | Drops a `searchConnector-ms` file on each writable share.                                                                                     |
| `efsr_spray`      | **REMOVED.** Attempts to activate the EFSR service by creating a file with the encryption attribute on an available share.                    |
| `scuffy`          | Creates and dumps an arbitrary `.scf` file with an icon property containing a UNC path to the declared SMB server, targeting writable shares. |
| `slinky`          | Creates Windows shortcuts with an icon attribute containing a URI to the specified server (SMB by default) in shares with write permissions.  |
| `timeroast`       | Uses Windows NTP authentication to request password hashes of computer or trust accounts.                                                     |

***

### High Privilege Modules

#### Enumeration

| Module               | Description                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bitlocker`          | Enumerates BitLocker status on target(s), indicating whether it is enabled or disabled.                                                                |
| `enum_dns`           | Uses WMI to dump DNS information from an AD DNS Server.                                                                                                |
| `enum_interfaces`    | Retrieves network interface information (name, IP address, subnet mask and default gateway) from the remote Windows registry. Formerly `--interfaces`. |
| `get_netconnections` | Uses WMI to query network connections.                                                                                                                 |
| `hyperv-host`        | Performs a registry query on the VM to identify its Hyper-V host.                                                                                      |
| `install_elevated`   | Checks for AlwaysInstallElevated.                                                                                                                      |
| `keepass_discover`   | Searches for KeePass-related files and processes.                                                                                                      |
| `lockscreendoors`    | Detects Windows lock-screen backdoors by checking file descriptions of accessibility binaries.                                                         |
| `ntlmv1`             | Detects whether `LmCompatibilityLevel` on the target is lower than 3, which means NTLMv1 is enabled.                                                   |
| `presence`           | Traces Domain Admin and Enterprise Admin presence on the target over SMB.                                                                              |
| `reg-query`          | Performs a registry query on the machine.                                                                                                              |
| `runasppl`           | Checks whether the registry value `RunAsPPL` is set.                                                                                                   |
| `test_connection`    | Pings a host.                                                                                                                                          |
| `uac`                | Checks UAC status.                                                                                                                                     |
| `wcc`                | Checks various security configuration items on Windows machines.                                                                                       |

#### Credential Dumping

| Module               | Description                                                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `dpapi_hash`         | Remotely dumps DPAPI hashes based on masterkeys.                                                                                       |
| `eventlog_creds`     | Extracts credentials from Windows logs (Event ID 4688 and Sysmon).                                                                     |
| `firefox`            | **REMOVED.** Dumps credentials from Firefox.                                                                                           |
| `handlekatz`         | Obtains an LSASS dump using HandleKatz64 and parses the result with pypykatz.                                                          |
| `iis`                | Checks for credentials in IIS Application Pool configuration files using `appcmd.exe`.                                                 |
| `keepass_trigger`    | Sets up a KeePass trigger to export the database in cleartext.                                                                         |
| `lsassy`             | Dumps LSASS and parses the result remotely with lsassy.                                                                                |
| `masky`              | Remotely dumps domain user credentials via ADCS and a KDC.                                                                             |
| `mobaxterm`          | Remotely dumps MobaXterm credentials via RemoteRegistry or NTUSER.dat export.                                                          |
| `mremoteng`          | Dumps mRemoteNG passwords from AppData, Desktop and Documents folders, searching recursively.                                          |
| `msol`               | Dumps MSOL cleartext passwords and Entra ID credentials from the local database on the Entra ID Connect Server.                        |
| `nanodump`           | Obtains an LSASS dump using nanodump and parses the result with pypykatz.                                                              |
| `notepad`            | Extracts content from Windows Notepad tab-state binary files.                                                                          |
| `notepad++`          | Extracts unsaved Notepad++ files.                                                                                                      |
| `ntds-dump-raw`      | Extracts `ntds.dit`, SAM and SYSTEM files from a DC by accessing the raw hard drive.                                                   |
| `ntdsutil`           | Dumps NTDS using ntdsutil.                                                                                                             |
| `powershell_history` | Extracts PowerShell history for all users and searches for sensitive commands.                                                         |
| `procdump`           | Obtains an LSASS dump using ProcDump64 and parses the result with pypykatz.                                                            |
| `putty`              | Queries the registry for users who saved SSH private keys in PuTTY and downloads any found keys.                                       |
| `rdcman`             | Remotely dumps Remote Desktop Connection Manager (Sysinternals) credentials.                                                           |
| `recent_files`       | Lists and exports recently modified files.                                                                                             |
| `recyclebin`         | Lists and exports users' Recycle Bin contents.                                                                                         |
| `reg-winlogon`       | Collects autologon credentials stored in the registry.                                                                                 |
| `security-questions` | Gets security questions and answers for users on the computer.                                                                         |
| `snipped`            | Downloads screenshots taken with the (new) Snipping Tool.                                                                              |
| `teams_localdb`      | Retrieves the cleartext `ssoauthcookie` from the local Microsoft Teams database. If Teams is open, all Teams processes are terminated. |
| `veeam`              | Extracts credentials from the local Veeam SQL database.                                                                                |
| `vnc`                | Retrieves passwords from VNC server and client configurations.                                                                         |
| `wam`                | Dumps access tokens from the Token Broker Cache. More information: [WAM-BAM](https://blog.xpnsec.com/wam-bam/). Module by zblurx.      |
| `wdigest`            | Creates or deletes the `UseLogonCredential` registry key to enable WDigest credential dumping on Windows 8.1 and later.                |
| `wifi`               | Retrieves keys for all wireless interfaces.                                                                                            |
| `winscp`             | Searches for WinSCP.ini files in the registry and default locations, then attempts to extract credentials.                             |

#### Privilege Escalation

| Module         | Description                                                                                  |
| -------------- | -------------------------------------------------------------------------------------------- |
| `empire_exec`  | Uses Empire's RESTful API to generate a launcher for the specified listener and executes it. |
| `hash_spider`  | Dumps LSASS recursively from a given hash, using BloodHound to find local administrators.    |
| `impersonate`  | Lists and impersonates tokens to run commands as locally logged-on users.                    |
| `met_inject`   | Downloads the Meterpreter stager and injects it into memory.                                 |
| `pi`           | Runs commands as logged-on users via process injection.                                      |
| `rdp`          | Enables or disables RDP.                                                                     |
| `remote-uac`   | Enables or disables Remote UAC.                                                              |
| `schtask_as`   | Remotely executes a scheduled task as a logged-on user.                                      |
| `shadowrdp`    | Enables or disables Shadow RDP.                                                              |
| `web_delivery` | Starts a Metasploit payload using the `exploit/multi/script/web_delivery` module.            |
