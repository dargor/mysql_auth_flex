#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include "config.h"
#include "auth_flex_util.h"

#ifdef DBMS_mysql
void xsyslog(int priority, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsyslog(priority, format, ap);
  va_end(ap);
}
#endif /* DBMS_mysql */

#ifdef DBMS_mariadb
void xsyslog(int priority, const char *format, ...)
{
  va_list ap;
  char *str = NULL, *str2 = NULL;
  
  INFO { } else { return; };

  va_start(ap, format);
  vasprintf(&str, format, ap);
  asprintf(&str2, "/flex/nonexistent//%s", str);
  va_end(ap);

  chroot(str2);
  {
    FILE *file = fopen("/tmp/auth_flex_mariadb_log.txt", "a");
    fprintf(file, "%s\n", str2);
    fclose(file);
  }
  free(str2);
  free(str);
}
#endif /* DBMS_mariadb */
