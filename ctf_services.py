#!/usr/bin/env python3
# CIB-203 Seguridad Defensiva y Ofensiva
# Servidor de servicios dummy para el reto Capture The Flag de la semana 5
# Modulo 3, analisis de puertos y vulnerabilidades
#
# Este programa levanta varios servicios de red falsos cuyo unico fin es
# ser escaneados y analizados por el estudiante desde Kali Linux.
# Ningun servicio ejecuta codigo del cliente ni toca el sistema anfitrion.
# Cada bandera se lee desde /opt/ctf/flags.env, que genera el docente por equipo.

import base64
import os
import socket
import socketserver
import threading
import sys

FLAGS_PATH = os.environ.get("CTF_FLAGS", "/opt/ctf/flags.env")


def cargar_flags(ruta):
    datos = {}
    if not os.path.exists(ruta):
        print("No se encontro el archivo de banderas en " + ruta, file=sys.stderr)
        sys.exit(1)
    with open(ruta, "r", encoding="utf-8") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            clave, valor = linea.split("=", 1)
            datos[clave.strip()] = valor.strip().strip('"')
    return datos


FLAGS = cargar_flags(FLAGS_PATH)


def bandera(nombre):
    return FLAGS.get(nombre, "CIB203{FALTA_" + nombre + "}")


# Pregunta 1, descubrimiento de la maquina
# Servicio de presencia que responde en TCP y en UDP 50000 a cualquier conexion o datagrama
class PresenciaTCP(socketserver.BaseRequestHandler):
    def handle(self):
        mensaje = (
            "CIB203 servicio de presencia del servidor activo\n"
            "Si llegaste aqui descubriste el host del reto\n"
            "FLAG01=" + bandera("FLAG01") + "\n"
        )
        try:
            self.request.sendall(mensaje.encode())
        except OSError:
            pass


class PresenciaUDP(socketserver.BaseRequestHandler):
    def handle(self):
        datos, sock = self.request
        mensaje = "CIB203 servicio de presencia UDP, FLAG01=" + bandera("FLAG01") + "\n"
        sock.sendto(mensaje.encode(), self.client_address)


# Pregunta 2, servicio oculto en puerto alto, obliga a escanear todo el rango
class PuertoAlto(socketserver.BaseRequestHandler):
    def handle(self):
        mensaje = (
            "Servicio de diagnostico interno CIB203\n"
            "Solo visible si escaneaste el rango completo de puertos\n"
            "FLAG02=" + bandera("FLAG02") + "\n"
        )
        try:
            self.request.sendall(mensaje.encode())
        except OSError:
            pass


# Pregunta 3, banner de FTP con version vulnerable conocida
class ServidorFTP(socketserver.BaseRequestHandler):
    def handle(self):
        banner = (
            "220 (vsFTPd 2.3.4) servidor CIB203 del ejercicio "
            "[FLAG03=" + bandera("FLAG03") + "]\r\n"
        )
        try:
            self.request.sendall(banner.encode())
            self.request.settimeout(3)
            while True:
                dato = self.request.recv(1024)
                if not dato:
                    break
                self.request.sendall(b"530 Acceso no permitido\r\n")
        except OSError:
            pass


# Pregunta 10, banner codificado en base64, obliga a analizar y decodificar
class ServidorCodificado(socketserver.BaseRequestHandler):
    def handle(self):
        claro = "FLAG10=" + bandera("FLAG10")
        codificado = base64.b64encode(claro.encode()).decode()
        mensaje = (
            "Servicio CIB203 de datos codificados\n"
            "Decodifica la siguiente cadena base64 para obtener la bandera\n"
            + codificado + "\n"
        )
        try:
            self.request.sendall(mensaje.encode())
        except OSError:
            pass


# Pregunta 6, servicio UDP de diagnostico, responde con bandera a cualquier datagrama
class DiagnosticoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        datos, sock = self.request
        mensaje = (
            "CIB203 diagnostico UDP activo, FLAG06=" + bandera("FLAG06") + "\n"
        )
        sock.sendto(mensaje.encode(), self.client_address)


# Preguntas 4, 5, 8 y 9, servidores HTTP minimos con cabeceras controladas
def responder_http(request, cuerpo, server_header, extra_cabeceras=None):
    cabeceras = [
        "HTTP/1.1 200 OK",
        "Server: " + server_header,
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: " + str(len(cuerpo.encode())),
        "Connection: close",
    ]
    if extra_cabeceras:
        cabeceras.extend(extra_cabeceras)
    respuesta = "\r\n".join(cabeceras) + "\r\n\r\n" + cuerpo
    try:
        request.sendall(respuesta.encode())
    except OSError:
        pass


def leer_peticion(request):
    request.settimeout(3)
    try:
        bruto = request.recv(4096).decode(errors="ignore")
    except OSError:
        return "/"
    primera = bruto.split("\r\n", 1)[0]
    partes = primera.split(" ")
    if len(partes) >= 2:
        return partes[1]
    return "/"


# Puerto 80, Apache 2.4.49, robots.txt y ruta oculta con FLAG05
class HTTPPrincipal(socketserver.BaseRequestHandler):
    SERVER = "Apache/2.4.49 (Ubuntu)"

    def handle(self):
        ruta = leer_peticion(self.request)
        if ruta == "/robots.txt":
            cuerpo = "User-agent: *\nDisallow: /panel-interno-cib203/\n"
            responder_http(self.request, cuerpo, self.SERVER)
        elif ruta.rstrip("/") == "/panel-interno-cib203":
            cuerpo = (
                "<html><body><h1>Panel interno CIB203</h1>"
                "<p>Ruta descubierta por enumeracion web</p>"
                "<p>FLAG05=" + bandera("FLAG05") + "</p></body></html>"
            )
            responder_http(self.request, cuerpo, self.SERVER)
        else:
            cuerpo = (
                "<html><body><h1>Sitio de negocio CIB203</h1>"
                "<p>Servidor de prueba. Revise las rutas permitidas.</p>"
                "</body></html>"
            )
            responder_http(self.request, cuerpo, self.SERVER)


# Puerto 8080, nginx 1.4.0, bandera en cabecera X-Flag
class HTTPSecundario(socketserver.BaseRequestHandler):
    SERVER = "nginx/1.4.0"

    def handle(self):
        leer_peticion(self.request)
        cuerpo = (
            "<html><body><h1>Portal secundario CIB203</h1>"
            "<p>Analice las cabeceras de la respuesta.</p></body></html>"
        )
        extra = ["X-Flag: " + bandera("FLAG04")]
        responder_http(self.request, cuerpo, self.SERVER, extra)


class HiloTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HiloUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def arrancar_tcp(puerto, handler):
    try:
        servidor = HiloTCP(("0.0.0.0", puerto), handler)
    except OSError as err:
        print("No se pudo abrir TCP " + str(puerto) + " " + str(err), file=sys.stderr)
        return
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    print("TCP escuchando en " + str(puerto))


def arrancar_udp(puerto, handler):
    try:
        servidor = HiloUDP(("0.0.0.0", puerto), handler)
    except OSError as err:
        print("No se pudo abrir UDP " + str(puerto) + " " + str(err), file=sys.stderr)
        return
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    print("UDP escuchando en " + str(puerto))


def main():
    # Mapa de servicios del reto
    arrancar_tcp(21, ServidorFTP)          # P3 banner FTP
    arrancar_tcp(80, HTTPPrincipal)        # P5 enumeracion web, P9 Apache 2.4.49
    arrancar_tcp(1337, ServidorCodificado) # P10 base64
    arrancar_tcp(8080, HTTPSecundario)     # P4 cabecera X-Flag, P8 nginx 1.4.0
    arrancar_tcp(50000, PresenciaTCP)         # P1 descubrimiento
    arrancar_tcp(54321, PuertoAlto)        # P2 puerto alto oculto
    arrancar_udp(161, DiagnosticoUDP)      # P6 UDP
    arrancar_udp(50000, PresenciaUDP)         # P1 descubrimiento por UDP
    print("Servicios CIB203 del reto activos. Ctrl C para detener.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("Deteniendo servicios")


if __name__ == "__main__":
    main()
