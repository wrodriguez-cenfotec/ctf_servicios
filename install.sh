#!/usr/bin/env bash
# CIB-203 Seguridad Defensiva y Ofensiva
# Instalador del reto Capture The Flag de la semana 5 sobre la maquina objetivo
#
# Este instalador descarga todos los archivos del reto desde GitHub,
#   https://github.com/wrodriguez-cenfotec/ctf_servicios
# genera las banderas del equipo indicado e instala los servicios.
#
# Distribucion recomendada, Ubuntu Server 24.04 LTS en instalacion minima sin
# escritorio. Requisitos del invitado, 1 vCPU, 768 MB de memoria y 4 GB de disco.
# python3 viene de serie en Ubuntu Server 24.04.
#
# Uso en la maquina objetivo, como root
#   Opcion de una linea, descarga este instalador y lo ejecuta para el equipo A
#     curl -fsSL https://raw.githubusercontent.com/wrodriguez-cenfotec/ctf_servicios/main/install.sh | sudo bash -s -- A
#   Opcion con el repositorio ya clonado
#     sudo ./install.sh A
#
# El argumento es la letra del equipo. Si ya existen flags.env y hashes.txt en el
# directorio actual, se usan esos y el argumento del equipo es opcional.

set -euo pipefail

REPO="${CTF_REPO:-https://github.com/wrodriguez-cenfotec/ctf_servicios}"
RAMA="${CTF_RAMA:-main}"
EQUIPO="${1:-}"
TRABAJO="/opt/ctf/source"

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecuta este instalador como root"
  exit 1
fi

echo "Instalando dependencias minimas"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y python3 nftables git ca-certificates >/dev/null

echo "Descargando los archivos del reto desde ${REPO}"
rm -rf "$TRABAJO"
mkdir -p /opt/ctf
git clone --depth 1 --branch "$RAMA" "$REPO" "$TRABAJO" >/dev/null

# Resolver banderas del equipo
if [ -f "flags.env" ] && [ -f "hashes.txt" ]; then
  echo "Usando flags.env y hashes.txt del directorio actual"
  cp flags.env  /opt/ctf/flags.env
  cp hashes.txt /opt/ctf/hashes.txt
elif [ -n "$EQUIPO" ]; then
  echo "Generando banderas para el equipo ${EQUIPO}"
  ( cd "$TRABAJO" && bash generate_challenge.sh "$EQUIPO" )
  cp "$TRABAJO/flags.env"            /opt/ctf/flags.env
  cp "$TRABAJO/hashes_${EQUIPO}.txt" /opt/ctf/hashes.txt
  # La clave de respuestas se guarda en /root para que el docente la retire
  cp "$TRABAJO/answer_key_${EQUIPO}.txt"  "/root/answer_key_${EQUIPO}.txt"
  cp "$TRABAJO/hashes_${EQUIPO}.txt" "/root/hashes_${EQUIPO}.txt"
  echo "Clave de respuestas guardada en /root/answer_key_${EQUIPO}.txt"
  echo "Retira ese archivo de la maquina objetivo antes de entregarla al equipo"
else
  echo "Falta la letra del equipo y no hay flags.env ni hashes.txt locales"
  echo "Ejemplo de uso, sudo ./install.sh A"
  exit 1
fi

chmod 0600 /opt/ctf/flags.env /opt/ctf/hashes.txt

echo "Copiando los servicios a /opt/ctf"
install -m 0755 "$TRABAJO/services/ctf_services.py" /opt/ctf/ctf_services.py
install -m 0755 "$TRABAJO/services/ctf_submission.py"  /opt/ctf/ctf_submission.py
touch /opt/ctf/submissions.jsonl
chmod 0600 /opt/ctf/submissions.jsonl

echo "Configurando el puerto filtrado para la pregunta 7"
# El puerto 23 se descarta en silencio, aparece como filtered en el escaneo.
# El puerto 3389 no escucha y no se descarta, el kernel responde RST, aparece closed.
cat > /etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
flush ruleset
table inet reto {
    chain entrada {
        type filter hook input priority 0; policy accept;
        tcp dport 23 drop
        udp dport 23 drop
    }
}
NFT
systemctl enable --now nftables >/dev/null
nft -f /etc/nftables.conf

echo "Instalando los servicios systemd"
install -m 0644 "$TRABAJO/systemd/ctf-services.service" /etc/systemd/system/ctf-services.service
install -m 0644 "$TRABAJO/systemd/ctf-submission.service"   /etc/systemd/system/ctf-submission.service
systemctl daemon-reload
systemctl enable --now ctf-services.service
systemctl enable --now ctf-submission.service

echo
echo "Instalacion terminada"
echo "Servicios de escaneo activos en 21, 80, 161 udp, 1337, 8080, 50000 tcp y udp, 54321"
echo "Puerto 23 filtrado y 3389 cerrado para la pregunta de estados"
echo "Pagina de entrega en http://IP_DEL_OBJETIVO:8000"
echo "La direccion IP del objetivo"
ip -4 addr show scope global | awk '/inet/ {print "  " $2}'
