---
title: RootMe Tryhackme writeup
author: HackerCloud
date: 2022-08-28 00:00:00 +0800
categories: [Tryhackme, machine, writeup]
tags: [tryhackme, writeup]
pin: true
---

Para empezar hacemos un escaneo para ver los puertos abiertos de la máquina:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/nmap-scan.png' | relative_url }}){: .center-image }

Como veo que están los puertos 22 (SSH) y 80 (HTTP) voy a hacer un escaneo sobre esos dos puertos con los scripts básicos de reconocimiento que aplica Nmap:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/nmap-scan2.png' | relative_url }}){: .center-image }

Vamos a revisar el contenido de la web de el puerto 80:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/website-capture.png' | relative_url }}){: .center-image }

No vemos nada en el código fuente así que vamos a enumerar directorios con gobuster:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/gobuster-scan.png' | relative_url }}){: .center-image }

Vemos el directorio Uploads y el directorio Panel, vamos a revisar el Panel:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/uploads-page-normal.png' | relative_url }}){: .center-image }

Se ve que podemos subir archivos, yo probaré con php ya que es lo que interpreta el servidor:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/upload-failed-php.png' | relative_url }}){: .center-image }

No nos permite subirlo, vamos a probar con la extensión phtml que también interpreta php:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/success-upload.png' | relative_url }}){: .center-image }

  
Nos ha dejado subirlo, podemos aprovechar para subir una reverse shell e ir al directorio uploads para comprobar la subida:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/uploads-page.png' | relative_url }}){: .center-image }

Al ver que se ha subido lo único que tenemos que hacer es ponernos en escucha con netcat y dar click en el archivo desde el directorio uploads:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/reverse-shell-done.png' | relative_url }}){: .center-image }

Nos ha llegado la reverse shell así que lo siguiente es tratarla:

```bash
script /dev/null -c bash
Ctrl + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

Lo siguiente es encontrar la flag de usuario, no está en "/home/rootme/user.txt" ni en "/home/test/user.txt" así que vamos a revisar en "/var/www":

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/got-user-flag.png' | relative_url }}){: .center-image }

Vamos a ver si existen binarios SUID con propietario root:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/find-perms.png' | relative_url }}){: .center-image }

Vemos que el binario de Python tiene permisos SUID así que lo buscamos en [GTFObins](https://gtfobins.github.io):

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

Encontramos un oneliner que nos da una shell de root así que lo probamos:

![Marcamos como usuario comprometido]({{ 'assets/img/commons/rootme-writeup/got-root.png' | relative_url }}){: .center-image }

Y con eso terminamos la máquina RootMe.
