---
title: Precious WriteUp
author: H4ckerLite 
date: 2023-01-17 00:00:00 +0800
categories: [hackthebox, machine, writeup]
tags: [hackthebox, writeup, rce]
pin: true
image:
  path: ../../assets/img/commons/shoppy-writeup/Shoppy.png 
  alt: Shoppy WriteUp
---

Les explicaré comó comprometer la máquina [Precious](https://app.hackthebox.com/machines/513) de HackTheBox. En esta máquina nos enfretaremos a una versión vulnerable de `pdfkit` con la cual ganaremos acceso por una reverse shell y para la escalada cargaremos un archivo para convertir la BASH en SUID.
