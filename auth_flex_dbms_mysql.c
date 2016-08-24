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
 * for mysql57, see sql/auth/sql_authentication.h
 *
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
  ulong client_capabilities;
  void **addr_client_capabilities_ptr;
  /* be careful..., arithmetic on a (void **) would move 4x faster than on a (void *)... */
#if DBMS_mysql < 57
  addr_client_capabilities_ptr = ((void *)d_flex_data->addr_scramble_ptr) - sizeof(void *);
#else /* DBMS_mysql < 57 */
  /* mysql 5.7 use a c++ class to hold client_capabilities, so we will have to use advanced black magic.
   *
   * http://stackoverflow.com/questions/12378271/what-does-an-object-look-like-in-memory/12378515#12378515
   *
   * As you suspect, the data members (fields) are laid out sequentially.
   * This also includes the fields of base classes.
   *
   * If the class (or one of its base classes) contain any virtual methods, the layout typically starts
   * with a vptr, i.e a pointer to a virtual table (or vtable) which is a table of pointers to function
   * implementations related to that class.
   *
   * Please note that this is not defined by standard, but AFAIK all current compilers use this approach.
   * Also, with multiple inheritance it gets more hairy, so let's ignore it for the moment.
   *
   * +-----------+
   * |  vptr     |  pointer to vtable which is located elsewhere
   * +-----------+
   * |  fieldA   |  first member
   * |  fieldB   |  ...
   * |  fieldC   |
   * |  ...      |
   * +-----------+
   *
   */
  void **addr_protocol_classic_ptr = ((void *)d_flex_data->addr_scramble_ptr) + 5 * sizeof(void *);
  addr_client_capabilities_ptr = *addr_protocol_classic_ptr + sizeof(void *);
#endif /* DBMS_mysql < 57 */
  client_capabilities = *(ulong *)addr_client_capabilities_ptr;
  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : client_capabilities %ld (CLIENT_PLUGIN_AUTH : %d)", __func__,
		client_capabilities, client_capabilities & CLIENT_PLUGIN_AUTH ? 1 : 0);
  d_flex_data->client_capabilities = client_capabilities;
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

#if DBMS_mysql < 57

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

  net_write_command(*addr_net_ptr, 254, pkt_change_plugin, strlen(pkt_change_plugin) + 1, "", 0);

#else /* DBMS_mysql < 57 */

  /* for mysql 5.7, things get a bit hairy.
   *
   * we have to simulate a MYSQL_PLUGIN_VIO struct, fill in some interesting fields
   * and send it back to our mysql client so it can retry auth with desired plugin.
   *
   * don't do this at home, kids.
   *
   */

  struct MYSQL_PLUGIN_VIO_FAKE
  {
    MYSQL_PLUGIN_VIO plugin_vio;
    MYSQL_SERVER_AUTH_INFO auth_info;
    void *acl_user;
    struct st_plugin_int {
      LEX_STRING name;
      struct st_mysql_plugin *plugin;
    } *plugin;
    LEX_STRING db;
    struct {
      char *plugin, *pkt;
      uint pkt_len;
    } cached_client_reply;
    struct {
      char *pkt;
      uint pkt_len;
    } cached_server_packet;
    int packets_read, packets_written;
    enum { SUCCESS, FAILURE, RESTART } status;
  };

  struct MYSQL_PLUGIN_VIO_FAKE *vio_fake = (struct MYSQL_PLUGIN_VIO_FAKE *)vio;
  int old_status = vio_fake->status;
  vio_fake->status = RESTART;

  struct st_mysql_auth tmp_auth = {0};
  tmp_auth.client_auth_plugin = pkt_change_plugin;
  struct st_mysql_plugin tmp_plugin = {0};
  tmp_plugin.info = &tmp_auth;
  struct st_plugin_int tmp_int = {0};
  tmp_int.plugin = &tmp_plugin;

  void *old_plugin = vio_fake->plugin;
  vio_fake->plugin = &tmp_int;

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : packets read/written %d/%d", __func__,
		vio_fake->packets_read, vio_fake->packets_written);
  vio->write_packet(vio, "", 0); /* This will somehow trigger the CHANGE_PLUGIN procedure... */
  vio_fake->plugin = old_plugin;
  vio_fake->status = old_status;

#endif /* DBMS_mysql < 57 */

}
