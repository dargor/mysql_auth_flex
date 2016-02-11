#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include <my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/mysql_com.h>

#include "config.h"
#include "auth_flex.h"
#include "auth_flex_util.h"

/* find the address of (MPVIO_EXT *)->scramble (the random string sent to the client for "mysql_native_password" authentication)
 *
 * see sql/sql_acl.cc native_password_authenticate() for the layout of `struct MPVIO_EXT'
 * [0] : MYSQL_PLUGIN_VIO sizeof() == 24 bytes
 *
 * we could hardcode the offset somewhere. ideally, we should have an API to query if from `sql_acl.cc'
 */
void _find_addr_scramble(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info, struct auth_flex_data *d_flex_data)
{
  void **addr_scramble = NULL;
  int i;

  for (i = 30; i < 50; ++i)
    {
      void *addr = ((void *)&vio[1]) + sizeof(*info) + 4 * i;
      DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : compare at %p (* -> %p) (diff %ld)",
		    __func__, addr, *(void **)addr, (long int)(addr - (void *)vio));

      /* addr_scramble should be +/- sizeof(void *) depending on if `info->host_or_ip' is an host or an ip ...
       * we will figure if it is an host or an ip later below.
       */
      if (*(void **)addr == info->host_or_ip)
	{
	  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : found info->host_or_ip (%s) at %p!", __func__, info->host_or_ip, addr);

	  /* assume info->host_or_ip == (MPVIO_EXT *)->host */
	  {
	    /* be careful..., arithmetic on a (void **) would move 4x faster than on a (void *)... */
	    addr_scramble = (void **)(((void *)addr) - 4 * 16);
	  }

	  if (strspn(info->host_or_ip, "0123456789.") == strlen(info->host_or_ip))
	    {
	      DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : info->host_or_ip is an ip, fix !", __func__);
	      /* info->host_or_ip was info->ip instead of info->host */
	      {
		/* (void **) arithmetic... move 4 bytes indeed... */
		addr_scramble += 1;
	      }
	    }

	  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : scramble should be at %p (diff %ld)", __func__, *(char **)addr_scramble, (long int)((void *)addr_scramble - (void *)vio));
	  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : scramble [%ld] `%s'", __func__, (long int)strlen(*(char **)addr_scramble), *(char **)addr_scramble);
	  break;
	}
    }

  d_flex_data->addr_scramble_ptr = addr_scramble;
  d_flex_data->addr_scramble = *d_flex_data->addr_scramble_ptr;
}

/* find the address of (MPVIO_EXT *)->client_capabilities
 *
 * we use it to known if the client support CLIENT_PLUGIN_AUTH (change user plugin to "mysql_clear_password" request)
 */
void _find_addr_client_capabilities(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info, struct auth_flex_data *d_flex_data)
{
  void **addr_client_capabilities_ptr = d_flex_data->addr_scramble_ptr - sizeof(void *);

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : client_capabilities %ld (CLIENT_PLUGIN_AUTH : %d)", __func__,
		*(ulong *)addr_client_capabilities_ptr, *(ulong *)addr_client_capabilities_ptr & CLIENT_PLUGIN_AUTH ? 1 : 0);
  d_flex_data->addr_client_capabilities_ptr = addr_client_capabilities_ptr;
}

/* ask the client to "change plugin", so that it will send us the password in cleartext...
 *
 * HELP:
 * - http://lists.mysql.com/commits/136992
 * - http://bugs.mysql.com/bug.php?id=57442
 * - wireshark...
 */
void flex_change_plugin_to_cleartext(MYSQL_PLUGIN_VIO *vio, struct auth_flex_data *d_auth_flex_data)
{
  char * __attribute__ ((unused)) pkt_change_plugin = "mysql_clear_password";
  void **addr_net_ptr = NULL;

  /* we cannot call vio->write_packet() because send_plugin_request_packet() would concatenate 
   *  and send the current auth pluging + the requested one (\254 + "mysql_native_password\0" + "mysql_clear_password\0")
   * so, below we send the "plugin change" request ourselves on the wire. (\254 + "mysql_clear_password\0")
   */
  {
    /* be careful..., arithmetic on a (void **) would move 4x faster than on a (void *)... */
    addr_net_ptr = (void *)(((void *)d_auth_flex_data->addr_scramble_ptr) + sizeof(void *) * 4 + sizeof(ulong));
  }
  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : addr_scramble/%p addr_net/%p (diff %ld)", __func__,
		d_auth_flex_data->addr_scramble_ptr, addr_net_ptr, (long int)(addr_net_ptr - d_auth_flex_data->addr_scramble_ptr));

#ifdef DBMS_mysql
  net_write_command(*addr_net_ptr, 254, pkt_change_plugin, strlen(pkt_change_plugin) + 1, "", 0);
#elif defined DBMS_mariadb
  net_write_command(*addr_net_ptr, 254, pkt_change_plugin, strlen(pkt_change_plugin) + 1);
#endif
}
