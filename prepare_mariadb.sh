#!/bin/sh
set -ex

# apt-get install libmariadbd-dev libmariadb-client-lgpl-dev libmariadb-client-lgpl-dev-compat libpam0g-dev

ln -fs ../mysql_com.h /usr/include/mariadb/mysql/mysql_com.h

wget -O /usr/include/mariadb/mysql/plugin.h https://raw.githubusercontent.com/MariaDB/server/10.0/include/mysql/plugin.h
wget -O /usr/include/mariadb/mysql/plugin_auth.h https://raw.githubusercontent.com/MariaDB/server/10.0/include/mysql/plugin_auth.h

perl -pi -e 's|^(?=#include )|//|' /usr/include/mariadb/mysql/plugin.h

# https://github.com/MariaDB/server/blob/10.0/include/mysql/plugin_auth.h.pp
#  This is a very nasty bug which prevents from compiling correct auth plugins for MariaDB
perl -pi -e 's/^#define MYSQL_USERNAME_LENGTH\s+\K48/512/' /usr/include/mariadb/mysql/plugin_auth_common.h

perl -pi -e 's|^(?=#include <decimal.h>)|//|' /usr/include/mariadb/ma_dyncol.h
perl -pi -e 's|^(?=#include <my_decimal_limits.h>)|//|' /usr/include/mariadb/ma_dyncol.h
