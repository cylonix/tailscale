#!/bin/sh
CONF=/etc/config/qpkg.conf
QPKG_NAME="Cylonix"
QPKG_ROOT=`/sbin/getcfg ${QPKG_NAME} Install_Path -f ${CONF}`
QPKG_PORT=`/sbin/getcfg ${QPKG_NAME} Service_Port -f ${CONF}`
export QNAP_QPKG=${QPKG_NAME}
export QPKG_ROOT
export CYLONIXD_LOG_PATH="${QPKG_ROOT}/var/cylonixd.stdout.log"
set -e

case "$1" in
  start)
    ENABLED=$(/sbin/getcfg ${QPKG_NAME} Enable -u -d FALSE -f ${CONF})
    if [ "${ENABLED}" != "TRUE" ]; then
        echo "${QPKG_NAME} is disabled."
        exit 1
    fi
    mkdir -p /home/httpd/cgi-bin/qpkg
    ln -sf ${QPKG_ROOT}/ui /home/httpd/cgi-bin/qpkg/${QPKG_NAME}
    mkdir -p -m 0755 /tmp/cylonix
    mkdir -p -m 0755 ${QPKG_ROOT}/var
    if [ -e /tmp/cylonix/cylonixd.pid ]; then
        PID=$(cat /tmp/cylonix/cylonixd.pid)
        if [ -d /proc/${PID}/ ]; then
          echo "${QPKG_NAME} is already running."
          exit 0
        fi
    fi
    ${QPKG_ROOT}/cylonixd --port ${QPKG_PORT} --statedir=${QPKG_ROOT}/state --socket=/tmp/cylonix/cylonixd.sock >> ${CYLONIXD_LOG_PATH} 2>&1 &
    echo $! > /tmp/cylonix/cylonixd.pid
    ;;

  stop)
    if [ -e /tmp/cylonix/cylonixd.pid ]; then
      PID=$(cat /tmp/cylonix/cylonixd.pid)
      kill -9 ${PID} || true
      rm -f /tmp/cylonix/cylonixd.pid
    fi
    ;;

  restart)
    $0 stop
    $0 start
    ;;
  remove)
    ;;

  *)
    echo "Usage: $0 {start|stop|restart|remove}"
    exit 1
esac

exit 0
