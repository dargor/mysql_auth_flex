#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include <my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/mysql_com.h>
#ifdef DBMS_mariadb
#include <mariadb/my_sys.h>
#include <mariadb/ma_dyncol.h>
#endif

#include "config.h"
#include "auth_flex.h"
#include "auth_flex_util.h"
#include "auth_flex_dbms_generic.h"

static int write_packet_fake(struct st_plugin_vio *vio, const unsigned char *packet, int packet_len)
{
  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : will do nothing", __func__);
  return 1;
}

static int read_packet_fake(struct st_plugin_vio *vio, unsigned char **buf)
{
  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : will do nothing", __func__);
  return -1;
}

void _find_addr_scramble(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info, struct auth_flex_data *d_flex_data)
{
  static void *handle;
  static struct st_mysql_plugin *native_plugin;

  if (!handle)
    {
      handle = dlopen(NULL, RTLD_LAZY);
      native_plugin = dlsym(handle, "builtin_maria_mysql_password_plugin");
    }
  if (!native_plugin)
    {
      xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : could not dlsym plugin", __func__);
      return;
    }

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : native_plugin->name %s", __func__, native_plugin->name);
  if (native_plugin->type != MYSQL_AUTHENTICATION_PLUGIN ||
      strcmp(native_plugin->name, "mysql_native_password"))
    {
      xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : native_plugin->type/name mismatch", __func__);
      return;
    }

  struct st_mysql_auth *native_auth = native_plugin->info;
  if (native_auth->interface_version != MYSQL_AUTHENTICATION_INTERFACE_VERSION ||
      strcmp(native_auth->client_auth_plugin, "mysql_native_password"))
    {
      xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : native_auth->interface_version/client_auth_plugin mismatch", __func__);
      return;
    }

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : will authenticate_user()/%p via client_auth_plugin/%s", __func__,
		native_auth->authenticate_user, native_auth->client_auth_plugin);

  struct MYSQL_PLUGIN_VIO_FAKE
  {
    MYSQL_PLUGIN_VIO plugin_vio;
    MYSQL_SERVER_AUTH_INFO auth_info;
    unsigned char *thd;
    /* This is a protection against bad headers for `MYSQL_SERVER_AUTH_INFO auth_info' members.
     * - MariaDB 10.0 use a size of '#define MYSQL_USERNAME_LENGTH 512' for the fields:
     * /usr/include/mariadb/mysql/plugin_auth.h:  char authenticated_as[MYSQL_USERNAME_LENGTH+1]; 
     * /usr/include/mariadb/mysql/plugin_auth.h:  char external_user[MYSQL_USERNAME_LENGTH+1];
     *
     * - MariaDB 10.0 provides for externally-compiled client plugin a size of '#define MYSQL_USERNAME_LENGTH 48' ...
     *
     * ./prepare_mariadb.sh should have fixed this.
     */
    unsigned char useless[4096];
  };

  struct MYSQL_PLUGIN_VIO_FAKE *vio_fake_caller = (struct MYSQL_PLUGIN_VIO_FAKE *)vio;
  
  if (&vio_fake_caller->auth_info != info)
    {
      xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s vio_fake_caller->auth_info/%p != info/%p, mismatch", __func__,
	      &vio_fake_caller->auth_info, info);
      xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : sizeof(MYSQL_SERVER_AUTH_INFO) == %d", __func__, sizeof(*vio_fake_caller));
      xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : if you have sizeof() < 512 * 2, then you should run ./prepare_mariadb.sh ...", __func__);
      return;
    }
    
  struct MYSQL_PLUGIN_VIO_FAKE vio_fake = {0};
  unsigned int thd_fake_len = 4096 * 128;
  unsigned char *thd_fake_ptr = malloc(thd_fake_len);
  memset(thd_fake_ptr, '\1', thd_fake_len);
  vio_fake.thd = thd_fake_ptr;
  vio_fake.plugin_vio.write_packet = write_packet_fake;
  vio_fake.plugin_vio.read_packet = read_packet_fake;

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : will authenticate_user()/%p [vio_fake/%p thd_fake_ptr/%p]", __func__, &vio_fake, thd_fake_ptr);
  native_auth->authenticate_user((MYSQL_PLUGIN_VIO *)&vio_fake, &vio_fake.auth_info);

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : done authenticate_user()", __func__);

  unsigned int offset_vio_to_scramble_end = 0;
  unsigned int offset_vio_to_rand_end = 0;

  {
    int i;

    for (i = 0; i < thd_fake_len; ++i)
      {
	if (!thd_fake_ptr[i])
	  {
	    DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : NULL character at i = %d", __func__, i);

	    if (!offset_vio_to_rand_end || i - offset_vio_to_rand_end < sizeof(struct my_rnd_struct))
	      {
		offset_vio_to_rand_end = i;
	      }
	    else
	      {
		offset_vio_to_scramble_end = i;
	      }
	  }
      }
  }

  free(thd_fake_ptr);

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : done offset_ rand/scramble %d/%d", __func__, offset_vio_to_rand_end, offset_vio_to_scramble_end);

  d_flex_data->addr_rand = &((struct MYSQL_PLUGIN_VIO_FAKE *)vio)->thd[offset_vio_to_rand_end] - sizeof(struct my_rnd_struct);
  d_flex_data->addr_rand_ptr = &d_flex_data->addr_rand;
  d_flex_data->addr_scramble = &((struct MYSQL_PLUGIN_VIO_FAKE *)vio)->thd[offset_vio_to_scramble_end] - SCRAMBLE_LENGTH;
  d_flex_data->addr_scramble_ptr = &d_flex_data->addr_scramble;
}

/*
 * Here, we do extremely bizarre works, because MariaDB has lot of static function which we would need:
 * - Access to the "NET *mpvio->thd->net" to fuzze with the network protocol...
 * - Access to a write_packet_raw() which would not try to outsmart us be escaping \254 (cmd CHANGE_PLUGIN)...
 *
 * Yeah we have pratically access to nothing. We would like to have access to:
 * - The *native* `Password' column (info->auth_string only provides the authentication_string)
 * `- It prevents to use native MySQL "SET PASSWORD ..." directives
 * - The scramble (mpvio->thd->scramble)
 * - The salt (yeah ok if you duplicate the password into info->auth_string then you can have it)
 */
void flex_change_plugin_to_cleartext(MYSQL_PLUGIN_VIO *vio, struct auth_flex_data *d_auth_flex_data)
{
  char * __attribute__ ((unused)) pkt_change_plugin = "mysql_clear_password";

  struct MYSQL_PLUGIN_VIO_FAKE
  {
    MYSQL_PLUGIN_VIO plugin_vio;
    MYSQL_SERVER_AUTH_INFO auth_info;
    unsigned char *thd;
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
    bool make_it_fail;
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

  return;
  /* We could *maybe* otherwise do it like it is done auth_flex_dbms_mariadb.c ...
   * The hardest part is to get a 'NET *net' address, in MariaDB it is &mpvio->thd->NET ...
   *  (and mpvio->thd is completly opaque)
   *
   * Maybe a good start would be to do (not tested):
   * - void *net = ((void *)vio_fake->buff) - sizeof(void *);
   *
   * It could indeed works if vio_fake->buff (or a similar pointer) is pointing inside mpvio->thd->net->buff ...
   *
   * The we could, like for MySQL, issue a net_write_command() ...
   */
}
