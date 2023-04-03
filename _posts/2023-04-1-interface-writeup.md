---
title: Interface WriteUp
author: H4ckerLite 
date: 2023-04-1 00:00:00 +0800
categories: [hackthebox, machine, writeup]
tags: [linux, hackthebox, writeup, medium, RCE]
image:
  path: ../../assets/img/commons/interface-writeup/Interface.png 
  alt: Inject WriteUp
pin: true
---

Interface es una máquina de [HackTheBox](https://app.hackthebox.com/machines/527) con una dificultad media. Para acceder usaremos una CVE de  la herramienta dompdf  que cuenta con un RCE y para la escalada nos aprovecharemos de una tarea cron que nos permite poner la bash con permiso SUID.

## Enumeración
### Escaneo de puertos
Empezamos con un escaneo nmap.

```bash
❯ nmap 10.10.11.200
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-01 00:29 -04
Nmap scan report for prd.m.rendering-api.interface.htb (10.10.11.200)
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.62 seconds
```
Si intentamos ver la página web

![Hacker ]({{ 'assets/img/commons/interface-writeup/1.png' | relative_url }}){: .center-image }
_Sitio en mantenimineto_

Si aplicamos fuzzing no encontramos nada, así que probaremos con burpsuite

![Hacker ]({{ 'assets/img/commons/interface-writeup/2.png' | relative_url }}){: .center-image }
_Burp Suite

Si agregamos ese dominio al /etc/passwd
```bash
echo '10.10.11.200       http://prd.m.rendering-api.interface.htb'  | tee -a /etc/hosts
```

Si le aplicamos un curl nos dira que el código de estado es 404.

```bash
❯ curl -i http://prd.m.rendering-api.interface.htb
HTTP/1.1 404 Not Found
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 01 Apr 2023 04:49:09 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive

File not found.
```

Aplicamos Fuzzing.

```bash
❯ wfuzz -c  --hh=182 -t 300 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  http://prd.m.rendering-api.interface.htb/FUZZ 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/FUZZ
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000001467:   403        1 L      2 W        15 Ch       "vendor"                                                                                                               
```






## Intrusión
### CVE-2022-28368






## Escalada de privilegios