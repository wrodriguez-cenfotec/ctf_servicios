#!/usr/bin/env bash
# Generador de banderas por equipo para el reto Capture The Flag
#
# Uso
#   ./generate_challenge.sh EQUIPO
# Ejemplo
#   ./generate_challenge.sh A
#
# Produce tres archivos
#   flags.env           banderas que lee el servidor de servicios dummy
#   answer_key_EQUIPO.txt    clave de respuestas en texto plano para el docente
#   hashes_EQUIPO.txt   sha256 de cada bandera, es la cadena que compara el docente

set -euo pipefail

EQUIPO="${1:-}"
if [ -z "$EQUIPO" ]; then
  echo "Falta el identificador del equipo. Ejemplo de uso, ./generate_challenge.sh A"
  exit 1
fi

token() {
  # 12 caracteres hexadecimales aleatorios, hacen la bandera imposible de adivinar
  head -c 16 /dev/urandom | sha256sum | cut -c1-12
}

marca() {
  echo "CIB203{EQ${EQUIPO}_$1_$(token)}"
}

FLAG01="$(marca DESCUBRIMIENTO)"
FLAG02="$(marca PUERTO_ALTO)"
FLAG03="$(marca BANNER_FTP)"
FLAG04="$(marca CABECERA_HTTP)"
FLAG05="$(marca ENUM_WEB)"
FLAG06="$(marca UDP_DIAG)"
FLAG10="$(marca BASE64)"

# Preguntas de analisis con respuesta fija, no van en el servidor
FLAG07="23:filtered 3389:closed"
FLAG08="CVE-2013-2028"
FLAG09="CVE-2021-41773"

cat > flags.env <<EOF
# Banderas del equipo ${EQUIPO}, generadas para el servidor de servicios dummy
FLAG01=${FLAG01}
FLAG02=${FLAG02}
FLAG03=${FLAG03}
FLAG04=${FLAG04}
FLAG05=${FLAG05}
FLAG06=${FLAG06}
FLAG10=${FLAG10}
EOF

cat > "answer_key_${EQUIPO}.txt" <<EOF
CIB-203 clave de respuestas del reto de la semana 5, equipo ${EQUIPO}

P01 descubrimiento del host           ${FLAG01}
P02 servicio en puerto alto 54321     ${FLAG02}
P03 banner del servicio FTP 21        ${FLAG03}
P04 cabecera X-Flag en 8080           ${FLAG04}
P05 ruta oculta por robots.txt en 80  ${FLAG05}
P06 servicio UDP de diagnostico 161   ${FLAG06}
P07 estados de puerto                 ${FLAG07}
P08 CVE de nginx 1.4.0 en 8080        ${FLAG08}
P09 CVE de Apache 2.4.49 en 80        ${FLAG09}
P10 cadena base64 del puerto 1337     ${FLAG10}

Nota sobre P07, la respuesta se entrega exactamente como aparece arriba,
puerto dos puntos estado, separados por un espacio, el puerto 23 filtrado
y el puerto 3389 cerrado.
EOF

{
  echo "# sha256 de cada bandera del equipo ${EQUIPO}"
  echo "# formato  PREGUNTA  SHA256"
  printf "P01 %s\n" "$(printf '%s' "$FLAG01" | sha256sum | cut -d' ' -f1)"
  printf "P02 %s\n" "$(printf '%s' "$FLAG02" | sha256sum | cut -d' ' -f1)"
  printf "P03 %s\n" "$(printf '%s' "$FLAG03" | sha256sum | cut -d' ' -f1)"
  printf "P04 %s\n" "$(printf '%s' "$FLAG04" | sha256sum | cut -d' ' -f1)"
  printf "P05 %s\n" "$(printf '%s' "$FLAG05" | sha256sum | cut -d' ' -f1)"
  printf "P06 %s\n" "$(printf '%s' "$FLAG06" | sha256sum | cut -d' ' -f1)"
  printf "P07 %s\n" "$(printf '%s' "$FLAG07" | sha256sum | cut -d' ' -f1)"
  printf "P08 %s\n" "$(printf '%s' "$FLAG08" | sha256sum | cut -d' ' -f1)"
  printf "P09 %s\n" "$(printf '%s' "$FLAG09" | sha256sum | cut -d' ' -f1)"
  printf "P10 %s\n" "$(printf '%s' "$FLAG10" | sha256sum | cut -d' ' -f1)"
} > "hashes_${EQUIPO}.txt"

echo "Listo. Archivos generados para el equipo ${EQUIPO}"
echo "  flags.env"
echo "  answer_key_${EQUIPO}.txt"
echo "  hashes_${EQUIPO}.txt"
