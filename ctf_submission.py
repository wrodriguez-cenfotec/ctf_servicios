#!/usr/bin/env python3
# El estudiante abre esta pagina desde Kali, escribe su nombre y su equipo,
# selecciona la pregunta y pega la bandera. El servicio calcula sha256 de lo
# enviado y lo compara con el hash de referencia del docente. Solo un match
# exacto cuenta como acierto, igual que comparar dos hashes.
#
# Uso
#   CTF_HASHES=/opt/ctf/hashes_A.txt python3 ctf_submission.py
# Escucha en el puerto 8000.

import hashlib
import html
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HASHES_PATH = os.environ.get("CTF_HASHES", "/opt/ctf/hashes.txt")
REGISTRO_PATH = os.environ.get("CTF_REGISTRO", "/opt/ctf/submissions.jsonl")
PUERTO = int(os.environ.get("CTF_PUERTO", "8000"))

TOTAL_PREGUNTAS = 10


def cargar_hashes(ruta):
    tabla = {}
    if not os.path.exists(ruta):
        raise SystemExit("No se encontro el archivo de hashes en " + ruta)
    with open(ruta, "r", encoding="utf-8") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = linea.split()
            if len(partes) >= 2:
                tabla[partes[0].upper()] = partes[1].lower()
    return tabla


HASHES = cargar_hashes(HASHES_PATH)


def normalizar(texto):
    # Se respeta el contenido tal cual, solo se quitan espacios de los extremos
    # y el salto de linea final que agregan algunas terminales al pegar.
    return texto.strip().strip("\r\n")


def verificar(pregunta, valor):
    pregunta = pregunta.upper()
    if pregunta not in HASHES:
        return None
    calculado = hashlib.sha256(normalizar(valor).encode()).hexdigest()
    return calculado == HASHES[pregunta]


def guardar(evento):
    with open(REGISTRO_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(evento, ensure_ascii=False) + "\n")


PAGINA = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>CIB-203 entrega del reto semana 5</title>
<style>
body{{font-family:sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem}}
label{{display:block;margin:.6rem 0 .2rem}}
input,select{{width:100%;padding:.5rem;box-sizing:border-box}}
button{{margin-top:1rem;padding:.6rem 1.2rem}}
.ok{{color:#136f2b;font-weight:bold}}
.no{{color:#9c1c1c;font-weight:bold}}
table{{border-collapse:collapse;margin-top:1rem;width:100%}}
td,th{{border:1px solid #ccc;padding:.3rem .5rem;text-align:left}}
</style></head><body>
<h1>CIB-203 entrega del reto de la semana 5</h1>
<p>Analisis de puertos y vulnerabilidades. Pega cada bandera encontrada.
La comparacion es exacta, respeta mayusculas, minusculas y simbolos.</p>
{aviso}
<form method="post" action="/enviar">
<label for="nombre">Nombre del estudiante</label>
<input id="nombre" name="nombre" required value="{nombre}">
<label for="equipo">Equipo</label>
<input id="equipo" name="equipo" required value="{equipo}">
<label for="pregunta">Pregunta</label>
<select id="pregunta" name="pregunta">{opciones}</select>
<label for="valor">Bandera o respuesta</label>
<input id="valor" name="valor" required>
<button type="submit">Enviar</button>
</form>
</body></html>"""


def render(aviso="", nombre="", equipo=""):
    opciones = ""
    for i in range(1, TOTAL_PREGUNTAS + 1):
        etiqueta = "P%02d" % i
        opciones += '<option value="%s">%s</option>' % (etiqueta, etiqueta)
    return PAGINA.format(
        aviso=aviso,
        nombre=html.escape(nombre),
        equipo=html.escape(equipo),
        opciones=opciones,
    )


class Manejador(BaseHTTPRequestHandler):
    def _responder(self, cuerpo, codigo=200):
        self.send_response(codigo)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(cuerpo.encode())

    def do_GET(self):
        if self.path.startswith("/"):
            self._responder(render())

    def do_POST(self):
        if self.path != "/enviar":
            self._responder(render("<p class='no'>Ruta no valida</p>"), 404)
            return
        largo = int(self.headers.get("Content-Length", "0"))
        bruto = self.rfile.read(largo).decode(errors="ignore")
        campos = urllib.parse.parse_qs(bruto)
        nombre = campos.get("nombre", [""])[0]
        equipo = campos.get("equipo", [""])[0]
        pregunta = campos.get("pregunta", [""])[0]
        valor = campos.get("valor", [""])[0]
        resultado = verificar(pregunta, valor)
        guardar({
            "nombre": nombre,
            "equipo": equipo,
            "pregunta": pregunta,
            "correcto": bool(resultado),
            "hora": self.log_date_time_string(),
        })
        if resultado is True:
            aviso = "<p class='ok'>Correcto, " + html.escape(pregunta) + " aceptada</p>"
        elif resultado is False:
            aviso = "<p class='no'>Incorrecto, revisa la bandera de " + html.escape(pregunta) + "</p>"
        else:
            aviso = "<p class='no'>Pregunta no reconocida</p>"
        self._responder(render(aviso, nombre, equipo))

    def log_message(self, formato, *args):
        return


def main():
    servidor = ThreadingHTTPServer(("0.0.0.0", PUERTO), Manejador)
    print("Servicio de entrega CIB203 escuchando en el puerto " + str(PUERTO))
    servidor.serve_forever()


if __name__ == "__main__":
    main()
