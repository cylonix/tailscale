#!/bin/sh
CONF=/etc/config/qpkg.conf
QPKG_NAME="Cylonix"
QPKG_ROOT=$(/sbin/getcfg ${QPKG_NAME} Install_Path -f ${CONF} -d"")
export QPKG_ROOT
export CYLONIXD_LOG_PATH="${QPKG_ROOT}/var/cylonixd.stdout.log"
mkdir -p -m 0755 "${QPKG_ROOT}/var"
exec "${QPKG_ROOT}/cylonix" --socket=/tmp/cylonix/cylonixd.sock web --cgi --prefix="/cgi-bin/qpkg/Cylonix/index.cgi/" 2>> "${CYLONIXD_LOG_PATH}"