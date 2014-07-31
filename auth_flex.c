#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include <my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/mysql_com.h>

#include "config.h"
#include "pam_flex.h"

int flex_debug_level = FLEX_DEBUG_LEVEL;

/* Ideally, we should:
 * - have an API to query the scramble from `sql_acl.cc' in auth plugins
 * - have a way to overload (calling them ourselves) and override others auth plugins
 * - have a way to request "plugin change" from clients
 * 
 * Thus in our auth plugin, we could:
 * - call native_password_authenticate()
 * - if it fails, request a "plugin change" to the client to "mysql_clear_password"
 * - do whatever we want with the cleartext password (ie. validation against PAM)
 *
 * Here, we are mickmiking this. We:
 * - do the same thing than native_password_authenticate()
 * `- we have to find the send scramble in an `hacky' way to compare the hash...
 *  - we have to find the hashed password for the user, either in `info->auth_string' or in `mpvio->acl_user->salt'
 * - validate the password using check_scramble() (which is okay)
 * - if it fails, we request a "change plugin" to the client to "mysql_clear_password"
 * - validate the "mysql_clear_password" against PAM
 */

static int auth_flex_cleartext_plugin(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info);

static unsigned char *_dump_bin_to_hex(unsigned char *s, unsigned int len)
{
  unsigned char *hex;
  int i;

  hex = malloc(len * 2 + 1);
  if (!hex)
    return NULL;

  for (i = 0; i < len; ++i)
    sprintf(&hex[i * 2], "%02X", s[i]);

  hex[len * 2] = '\0';

  return hex;
}

static void _show_password(unsigned char *pkt, unsigned int pkt_len)
{
  char *pw_hex = _dump_bin_to_hex(pkt, pkt_len);
  if (!pw_hex)
    return;

  syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : password [%d] `%s'", __func__, pkt_len, pw_hex);

  free(pw_hex);
}

/* find the address of (MPVIO_EXT *)->scramble (the random string sent to the client for "mysql_native_password" authentication)
 *
 * see sql/sql_acl.cc native_password_authenticate() for the layout of `struct MPVIO_EXT'
 * [0] : MYSQL_PLUGIN_VIO sizeof() == 24 bytes
 *
 * we could hardcode the offset somewhere. ideally, we should have an API to query if from `sql_acl.cc'
 */
static void *_find_addr_scramble(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  void *addr_scramble = NULL;
  int i;

  for (i = 30; i < 50; ++i)
    {
      void *addr = ((void *)&vio[1]) + sizeof(*info) + 4 * i;
      DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : compare at %p (* -> %p) (diff %ld)",
		   __func__, addr, *(void **)addr, addr - (void *)vio);

      /* addr_scramble should be +/- sizeof(void *) depending on if `info->host_or_ip' is an host or an ip ...
       * we will figure if it is an host or an ip later below.
       */
      if (*(void **)addr == info->host_or_ip)
	{
	  DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : found info->host_or_ip (%s) at %p!", __func__, info->host_or_ip, addr);

	  /* assume info->host_or_ip == (MPVIO_EXT *)->host */
	  addr_scramble = addr - 4 * 16;

	  if (strspn(info->host_or_ip, "0123456789.") == strlen(info->host_or_ip))
	    {
	      DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : info->host_or_ip is an ip, fix !", __func__);
	      /* info->host_or_ip was info->ip instead of info->host */
	      addr_scramble += sizeof(void *);
	    }

	  DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : scramble should be at %p (diff %ld)", __func__, *(char **)addr_scramble, addr_scramble - (void *)vio);
	  DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : scramble [%ld] `%s'", __func__, strlen(*(char **)addr_scramble), *(char **)addr_scramble);
	  break;
	}
    }

  return addr_scramble;
}

/* find the address of (MPVIO_EXT *)->acl_user->salt (the hashed password for the user stored in the `mysql.user' table)
 *
 * INCOMPLETED: instead, we rely and return `info->auth_string' (the `auth_string' stored in the `mysql.user' table)
 * we lack an API to ask `sql_acl.cc' for the user password. or simply an API to validate the password.
 */
static void *_find_salt(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  void *addr_acl_user = ((void *)&vio[1]) + sizeof(*info);
  /* void *addr_salt = addr_acl_user + 24 + ?? */

  return &info->auth_string;
}

/* validate authentication like "mysql_native_password" would do it.
 *
 * return 1 if successfull, 0 otherwise.
 *
 * - http://dev.mysql.com/doc/internals/en/secure-password-authentication.html
 * - http://www.mysqlfanboy.com/2012/06/mysql-security/
 */
static int flex_validate_authentication_native(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info, unsigned char *pw_to_check,
					       void *addr_scramble)
{
  void *addr_salt = _find_salt(vio, info);

  char *binary_salt = malloc(strlen(*(void **)addr_salt) + 1);
  if (!binary_salt)
    return 0;

  get_salt_from_password(binary_salt, *(void **)addr_salt);

  int ret = check_scramble(pw_to_check, *(void **)addr_scramble, binary_salt); /* return 0 if okay. BEWARE */

  free(binary_salt);

  return !ret; /* reverse. 1 == okay, 0 == fail. BEWARE */
}

/* validate authentication like "mysql_clear_password" would do it.
 *
 * return 1 if successfull, 0 otherwise.
 */
static int flex_validate_authentication_cleartext(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info, unsigned char *pw_to_check)
{
  if (pam_flex_check(info->user_name, pw_to_check))
    return 1;

  return 0;
}

/* ask the client to "change plugin", so that it will send us the password in cleartext...
 *
 * HELP:
 * - http://lists.mysql.com/commits/136992
 * - http://bugs.mysql.com/bug.php?id=57442
 * - wireshark...
 */
static void flex_change_plugin_to_cleartext(void *addr_scramble)
{
    char *pkt_change_plugin = "mysql_clear_password";

    /* we cannot call vio->write_packet() because send_plugin_request_packet() would concatenate 
     *  and send the current auth pluging + the requested one (\254 + "mysql_native_password\0" + "mysql_clear_password\0")
     * so, below we send the "plugin change" request ourselves on the wire. (\254 + "mysql_clear_password\0")
     */
    void *addr_net = addr_scramble + sizeof(void *) * 4 + sizeof(ulong);
    DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : addr_scramble/%p addr_net/%p (diff %ld)", __func__,
		 addr_scramble, addr_net, addr_net - addr_scramble);

    net_write_command(*(void **)addr_net, 254, pkt_change_plugin, strlen(pkt_change_plugin) + 1, "", 0);
}

static int auth_flex_plugin(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  unsigned char *pkt;
  int pkt_len;

  DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s (auth_string: %.*s) vio/%p info/%p", __func__,
	       info->user_name_length, info->user_name, info->host_or_ip, (int)info->auth_string_length, info->auth_string, vio, info);

  if ((pkt_len = vio->read_packet(vio, &pkt)) < 0)
    return CR_ERROR;

  if (!pkt_len || *pkt == '\0')
    {
      info->password_used = PASSWORD_USED_NO;
      return CR_ERROR;
    }

  info->password_used = PASSWORD_USED_YES;

  DEBUG _show_password(pkt, pkt_len);

  void *addr_scramble = _find_addr_scramble(vio, info);

  int authed = flex_validate_authentication_native(vio, info, pkt, addr_scramble);
  INFO syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s native password validation : %d", __func__,
	      info->user_name_length, info->user_name, info->host_or_ip, authed);

  if (authed)
    return CR_OK;

  flex_change_plugin_to_cleartext(addr_scramble);

  return auth_flex_cleartext_plugin(vio, info);
}

static int auth_flex_cleartext_plugin(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  unsigned char *pkt;
  int pkt_len;

  DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s (auth_string: %.*s) vio/%p info/%p", __func__,
	       info->user_name_length, info->user_name, info->host_or_ip, (int)info->auth_string_length, info->auth_string, vio, info);

  if ((pkt_len = vio->read_packet(vio, &pkt)) < 0)
    return CR_ERROR;

  info->password_used = PASSWORD_USED_YES;

  DEBUG _show_password(pkt, pkt_len);

  int authed = flex_validate_authentication_cleartext(vio, info, pkt);
  INFO syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s cleartext password validation : %d", __func__,
	      info->user_name_length, info->user_name, info->host_or_ip, authed);

  if (authed)
    return CR_OK;

  return CR_ERROR;
}

static struct st_mysql_auth auth_flex_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "mysql_native_password",
  auth_flex_plugin
};

static struct st_mysql_auth auth_flex_cleartext_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "mysql_clear_password", /* requires the clear text plugin */
  auth_flex_cleartext_plugin
};

static struct st_mysql_auth auth_flex_mixed_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "mysql_clear_password", /* requires the clear text plugin */
  auth_flex_plugin
};

mysql_declare_plugin(flex_plugin)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &auth_flex_handler,
  "auth_flex",
  "Eric Gouyer",
  "Flexible Authentication",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x0100,
  NULL,
  NULL,
  NULL,
  0,
},
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &auth_flex_cleartext_handler,
  "auth_flex_cleartext",
  "Eric Gouyer",
  "Flexible Authentication Cleartext",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x0100,
  NULL,
  NULL,
  NULL,
  0,
},
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &auth_flex_mixed_handler,
  "auth_flex_mixed",
  "Eric Gouyer",
  "Flexible Authentication Mixed",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x0100,
  NULL,
  NULL,
  NULL,
  0,
}
mysql_declare_plugin_end;
