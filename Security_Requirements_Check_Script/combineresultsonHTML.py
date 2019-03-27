#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import re
import codecs
from django.template import Template,Context, Engine
#path = "//172.16.3.2/General/15. Usuarios/=JVG/2. Scripts seguridad/results/"
path = os.path.dirname(__file__) +"/"

def main():

    listaFichero=obtenerFicheros()
    obtenerInformacion(listaFichero)


def obtenerInformacion(listaFichero):
    #Cargamos el fichero Template
    textoTemplate = cargarFicheroTexto(path+"template.html")

    #Creamos el objeto template para nuestro texto
    template = Engine().from_string(textoTemplate)

    
    datosFinal=Context()
    array=[]
    for nombreFichero in listaFichero:
        datosTemplate=Context()
        textoEntrada=cargarFicheroTexto(path+nombreFichero)
        buscarPatrones(textoEntrada,datosTemplate)
        datosTemplate["nameFile"]=nombreFichero.replace("_","").replace(".txt","")
        array.append(datosTemplate)


    datosFinal['Ficheros'] = array
    renderizarPlantilla(template,datosFinal,path + "index.html")


def cargarFicheroTexto(ruta):
    fichero = codecs.open(ruta, 'r', encoding='utf-8')
    texto = fichero.read()
    fichero.close()
    return texto

def renderizarPlantilla(plantilla,datos,ruta):

    ficheroSalida =codecs.open(ruta, "w",encoding='utf-8')
    ficheroSalida.write(plantilla.render(datos))
    ficheroSalida.close()

def buscarPatrones(textoEntrada,datosTemplate):
    listaPatrones=[[r'Computer Name:(.*)','computerName'],
				   [r'Date:(.*)','date'],
                   [r'Kaspersky:(.*)','antivirusInst',(changeIcon)],
                   [r'Firewall:(.*)','firewall',(changeIcon)],
                   [r'AutoUpdate Enabled:(.*)','autoupdate',(changeIcon)],
                   [r'KeePass Instaled:(.*)','keepass',(changeIcon)],
				   [r'KeePass State:(.*)','keepassState'],
                   [r'OS Version:(.*)','osVersion'],
                   [r'Processor:(.*)','processor'],
				   [r'MAC Integrada:(.*)','macIntegrada'],
				   [r'MAC WLAN:(.*)','macWlan'],
                   [r'Office Version:(.*)','office'],
                   [r'Username:(.*)','username'],
				   [r'State:(.*)','state'],
                   [r'Administrator Privileges:(.*)','admin',(changeIcon)],
                   [r'Last Update Date:(.*)','lastupdate'],
                   [r'Guest Account Enabled:(.*)','guestAcc',(changeIcon)],
                   [r'Listening Ports:(.*)','listPorts'],
                   [r'KeyPass Enforced:(.*)','enforced',(changeIcon)],
                   [r'Shared Folders:(.*)','folders',(insertEnters)]]
    for patron in listaPatrones:
        if re.search(patron[0],textoEntrada):
            m=re.search(patron[0], textoEntrada)
            try:
                textoRenderizar=patron[2](m)
            except IndexError:
                textoRenderizar=m.group(1)
            datosTemplate[patron[1]]=textoRenderizar 

def changeIcon(m):
    textosalida=m.group(1)
    if textosalida.find("True")==0:
        textosalida="done"
    elif textosalida.find("False")==0: 
        textosalida="clear"
    return textosalida
    

def insertEnters(m):
    textosalida=m.group(1)
    return (textosalida.replace(",","<br>"))

def obtenerFicheros():
    # Lista vacia para incluir los ficheros
    lstFiles = []
    # Lista con todos los ficheros del directorio:
    lstDir = os.walk(path)  # os.walk()Lista directorios y ficheros

    # Crea una lista de los ficheros htm que existen en el directorio y los incluye a la lista.
    for root, dirs, files in lstDir:
       for fichero in files:
          (nombreFichero, extension) = os.path.splitext(fichero)
          if (extension == ".txt"):
            lstFiles.append(nombreFichero + extension)
    return lstFiles



main()