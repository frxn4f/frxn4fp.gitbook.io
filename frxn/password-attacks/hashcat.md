# Hashcat

### Metodología

**Identificación de un hash** (Longitud y formato)

```bash
nth --text 'e4f779a01b503a38dec0beeae4ac46c2222b2d91'
```

```bash
nth --text '$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC'
```

Name-That-Hash permite identificar posibles algoritmos a partir del formato y longitud del hash. No siempre devuelve un resultado único, por lo que conviene contrastar las posibilidades.

Para instalar nth:

```bash
pipx install name-that-hash
```

Alternativas: `hashid`, `hash-identifier`.

***

**Identificar el módulo de Hashcat**

Una vez identificado el tipo de hash, necesitamos conocer su módulo correspondiente en Hashcat.

```bash
hashcat --identify <HASH_FILE>
```

Alternativa, para consultar todos los módulos disponibles:

```bash
hashcat -hh
```

Ejemplos:

| Tipo de hash | Módulo |
| ------------ | -----: |
| MD5          |      0 |
| SHA1         |    100 |
| SHA256       |   1400 |
| NTLM         |   1000 |
| bcrypt       |   3200 |

***

### Mutación de wordlist

* **Crear una regla de mutación de wordlist**

```bash
echo '$1 c $!' > name.rule
```

* Cada función se escribe en la misma línea, separada por espacio → se aplican todas en cadena a cada contraseña.
* Si se escriben en líneas separadas, Hashcat las trata como reglas independientes (una contraseña mutada por cada línea).
* Escapar `$` si se usa `echo` sin comillas simples (en bash expande variables).
* Las funciones se aplican de izquierda a derecha: el orden en que las escribís cambia el resultado final.

**Funciones básicas**

| Función               | Efecto                                                        | Ejemplo                   |
| --------------------- | ------------------------------------------------------------- | ------------------------- |
| `$X`                  | Agrega `X` al final                                           | `$1` → `password1`        |
| `^X`                  | Agrega `X` al principio                                       | `^3` → `3password`        |
| `c`                   | Capitaliza la primera letra y convierte el resto a minúsculas | `c` → `Password`          |
| `$1 c $!` (combinada) | Agrega "1", capitaliza y agrega "!" en ese orden              | `password` → `Password1!` |

**Ejemplo real**

```bash
cat demo3.rule
```

```
$1 c $!
$2 c $!
$1 $2 $3 c $!
```

Resultado:

```
$1 c $!           →  example  →  Example1!
$2 c $!           →  example  →  Example2!
$1 $2 $3 c $!     →  example  →  Example123!
```

* Cada línea del `.rule` genera una variante distinta por palabra de la wordlist (3 variantes × N palabras).

***

* **Listar reglas de mutación**

```bash
ls -la /usr/share/hashcat/rules
```

***

* **Mutar una wordlist** (sin crackear contraseñas, solo para obtener la lista de contraseñas mutadas)

```bash
hashcat -a 0 --stdout <wordlist_path> -r /usr/share/hashcat/rules/<rule>.rule
```

También podemos guardar el resultado directamente en un archivo:

```bash
hashcat -a 0 --stdout <wordlist_path> -r /usr/share/hashcat/rules/<rule>.rule > mutated.txt
```

***

* **Crackear una contraseña con regla de mutación de wordlist**

```bash
hashcat -m 0 -a 0 <inputfile_hash> <wordlist_path> -r /usr/share/hashcat/rules/<rule>.rule
```

* `-m` establece el tipo de hash (En este caso, al ser 0, es MD5).
* `-a` establece el modo de ataque (En este caso, 0 corresponde a Straight / Wordlist).
* `-r` establece la regla de mutación que se va a aplicar.
* `--force` ignora los warnings, pero no soluciona los problemas que los generan. No se recomienda utilizarlo por defecto.

***

### John The Ripper

**Crackear KeePass utilizando una regla de mutación**

```bash
john --format=keepass keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt --rules=rockyou-30000
```

En este caso utilizamos John The Ripper en lugar de Hashcat. La regla `rockyou-30000` pertenece a los conjuntos de reglas disponibles en John Jumbo y debe estar definida en su configuración.
