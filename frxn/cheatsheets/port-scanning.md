# Port Scanning

### Escaneo Inicial

```bash
> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <ip>
```

`Desglose`:

* `-p-` indica que el scan se realice sobre todos los puertos (0-65535)
* `--open` indica que se reporten solo los puertos abiertos
* `-sS` indica que se realice un scaneo "stealth" (No 3 Way Handshake)
* `--min-rate 5000` indica que se tramiten paquetes no más lentos de 5000 paquetes de segundos (irá mucho mas rapido)
* `-n` indica que no se aplique resolución DNS
* `-Pn` indica que no se aplique Host Discovery

### Escaneo exhaustivo

```bash
> nmap -p<ports> -sC -sV <ip>
```

`Desglose`:

* `-p` indica los puertos especificos sobre los que lanzar el scan
* `-sC` indica que lance un scripts básicos de reconocimiento (los más populares)
* `-sV` indica que aplique la detección del servicio y versión que corren bajo los puertos

