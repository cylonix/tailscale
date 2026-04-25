#! /bin/sh

LOG_FILE="/var/packages/Cylonix/var/cylonixd.stdout.log"
exec /var/packages/Cylonix/target/bin/cylonix web -cgi -prefix="/webman/3rdparty/Cylonix/index.cgi/" 2>>"${LOG_FILE}"
