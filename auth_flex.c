#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include <my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/mysql_com.h>

#include "config.h"
#include "auth_flex.h"
#include "auth_flex_util.h"
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

  xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : password [%d] `%s'", __func__, pkt_len, pw_hex);

  free(pw_hex);
}

/* find the address of (MPVIO_EXT *)->acl_user->salt (the hashed password for the user stored in the `mysql.user' table)
 *
 * INCOMPLETED: instead, we rely and return `info->auth_string' (the `auth_string' stored in the `mysql.user' table)
 * we lack an API to ask `sql_acl.cc' for the user password. or simply an API to validate the password.
 */
static void _find_addr_salt(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info, struct auth_flex_data *d_flex_data)
{
  void __attribute__ ((unused)) *addr_acl_user = ((void *)&vio[1]) + sizeof(*info);
  /* void *addr_salt = addr_acl_user + 24 + ?? */

  d_flex_data->addr_salt_ptr = (void **)&info->auth_string;
  d_flex_data->addr_salt = *d_flex_data->addr_salt_ptr;
}

/* validate authentication like "mysql_native_password" would do it.
 *
 * return 1 if successfull, 0 otherwise.
 *
 * - http://dev.mysql.com/doc/internals/en/secure-password-authentication.html
 * - http://www.mysqlfanboy.com/2012/06/mysql-security/
 */
static int flex_validate_authentication_native(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info, unsigned char *pw_to_check,
					       struct auth_flex_data *d_auth_flex_data)
{
  _find_addr_salt(vio, info, d_auth_flex_data);

  /* xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : offset salt len : %d (sizeof %d)", __func__, strlen(d_auth_flex_data->addr_salt), sizeof(struct my_rnd_struct)); */
  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : addr_salt [%d] %s", __func__, strlen(d_auth_flex_data->addr_salt), d_auth_flex_data->addr_salt);
  void *binary_salt = malloc(strlen(d_auth_flex_data->addr_salt) + 1);
  if (!binary_salt)
    return 0;

  get_salt_from_password(binary_salt, d_auth_flex_data->addr_salt);

  int ret = -1;
#ifdef DBMS_mysql
  ret = check_scramble(pw_to_check, d_auth_flex_data->addr_scramble, binary_salt); /* return 0 if okay. BEWARE */
#endif
#ifdef DBMS_mariadb
  ret = check_scramble(pw_to_check, d_auth_flex_data->addr_scramble, binary_salt, 0); /* return 0 if okay. BEWARE */
#endif

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

static int auth_flex_plugin(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  struct auth_flex_data d_auth_flex_data = {0};
  unsigned char *pkt;
  int pkt_len;

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "/flex/coucou/function/"AT);
  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s (auth_string: %.*s) vio/%p info/%p", __func__,
		info->user_name_length, info->user_name, info->host_or_ip, (int)info->auth_string_length, info->auth_string, vio, info);

  if ((pkt_len = vio->read_packet(vio, &pkt)) < 0)
    return CR_ERROR;

  if (!pkt_len)
    {
      info->password_used = PASSWORD_USED_NO;
      return CR_ERROR;
    }

  info->password_used = PASSWORD_USED_YES;

  DEBUG _show_password(pkt, pkt_len);

  _find_addr_scramble(vio, info, &d_auth_flex_data);
  if (!d_auth_flex_data.addr_scramble)
    return CR_ERROR;
  
  int authed = flex_validate_authentication_native(vio, info, pkt, &d_auth_flex_data);
  INFO xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s native password validation : %d", __func__,
	       info->user_name_length, info->user_name, info->host_or_ip, authed);

  if (authed)
    return CR_OK;

#ifdef DBMS_mysql
  _find_addr_client_capabilities(vio, info, &d_auth_flex_data);
  if (!(d_auth_flex_data.client_capabilities & CLIENT_PLUGIN_AUTH))
    return CR_ERROR;
#endif /* DBMS_mysql */

  flex_change_plugin_to_cleartext(vio, &d_auth_flex_data);

  return auth_flex_cleartext_plugin(vio, info);
}

static int auth_flex_cleartext_plugin(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  unsigned char *pkt;
  int pkt_len;

  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s (auth_string: %.*s) vio/%p info/%p", __func__,
		info->user_name_length, info->user_name, info->host_or_ip, (int)info->auth_string_length, info->auth_string, vio, info);

  if ((pkt_len = vio->read_packet(vio, &pkt)) < 0)
    return CR_ERROR;

  info->password_used = PASSWORD_USED_YES;

  /* XXX to the brave souls who may be wandering in this code hopelessly,
   *     there is one thing you should know : the mysql client truncates
   *     passwords at 80 characters when reading them from stdin, so if
   *     you try to log in with a key longer than that, you may find
   *     yourself scratching your head, wondering where in your life
   *     everything went wrong and what you should have done better.
   *
   *     see get_tty_password_ext() in get_password.c from mysql sources,
   *     and enjoy the sweet bitterness of its code.
   *
   *     but fear not, mysql [...] --password='teh_key' works as expected.
   *
   *     may this friendly piece of advice save some hours of your life.
   *
   */

  DEBUG _show_password(pkt, pkt_len);

  int authed = flex_validate_authentication_cleartext(vio, info, pkt);
  INFO xsyslog(LOG_LOCAL7 | LOG_NOTICE, "%s : user `%.*s' from %s cleartext password validation : %d", __func__,
	       info->user_name_length, info->user_name, info->host_or_ip, authed);

  if (authed)
    return CR_OK;

  return CR_ERROR;
}

#if defined(DBMS_mysql) && DBMS_mysql >= 57

int generate_auth_string_hash(char *outbuf MY_ATTRIBUTE((unused)),
                              unsigned int *buflen,
                              const char *inbuf MY_ATTRIBUTE((unused)),
                              unsigned int inbuflen MY_ATTRIBUTE((unused)))
{
  *buflen= 0;
  return 0;
}

int validate_auth_string_hash(char* const inbuf  MY_ATTRIBUTE((unused)),
                              unsigned int buflen  MY_ATTRIBUTE((unused)))
{
  return 0;
}

int set_salt(const char* password MY_ATTRIBUTE((unused)),
             unsigned int password_len MY_ATTRIBUTE((unused)),
             unsigned char* salt MY_ATTRIBUTE((unused)),
             unsigned char* salt_len)
{
  *salt_len= 0;
  return 0;
}

#endif /* defined(DBMS_mysql) && DBMS_mysql >= 57 */

static struct st_mysql_auth auth_flex_handler=
{
  .interface_version              = MYSQL_AUTHENTICATION_INTERFACE_VERSION,        // 5.5 - 5.6 - 5.7
  .client_auth_plugin             = "mysql_native_password",                       // 5.5 - 5.6 - 5.7
  .authenticate_user              = auth_flex_plugin,                              // 5.5 - 5.6 - 5.7
#if defined(DBMS_mysql) && DBMS_mysql >= 57
  .generate_authentication_string = generate_auth_string_hash,                     //             5.7
  .validate_authentication_string = validate_auth_string_hash,                     //             5.7
  .set_salt                       = set_salt,                                      //             5.7
  .authentication_flags           = AUTH_FLAG_PRIVILEGED_USER_FOR_PASSWORD_CHANGE, //             5.7
#endif /* defined(DBMS_mysql) && DBMS_mysql >= 57 */
};

#if defined(DBMS_mysql)
static struct st_mysql_auth auth_flex_cleartext_handler=
{
  .interface_version              = MYSQL_AUTHENTICATION_INTERFACE_VERSION,        // 5.5 - 5.6 - 5.7
  .client_auth_plugin             = "mysql_clear_password",                        // 5.5 - 5.6 - 5.7
  .authenticate_user              = auth_flex_cleartext_plugin,                    // 5.5 - 5.6 - 5.7
#if DBMS_mysql >= 57
  .generate_authentication_string = generate_auth_string_hash,                     //             5.7
  .validate_authentication_string = validate_auth_string_hash,                     //             5.7
  .set_salt                       = set_salt,                                      //             5.7
  .authentication_flags           = AUTH_FLAG_PRIVILEGED_USER_FOR_PASSWORD_CHANGE, //             5.7
#endif /* DBMS_mysql >= 57 */
};

static struct st_mysql_auth auth_flex_mixed_handler=
{
  .interface_version              = MYSQL_AUTHENTICATION_INTERFACE_VERSION,        // 5.5 - 5.6 - 5.7
  .client_auth_plugin             = "mysql_clear_password",                        // 5.5 - 5.6 - 5.7
  .authenticate_user              = auth_flex_plugin,                              // 5.5 - 5.6 - 5.7
#if DBMS_mysql >= 57
  .generate_authentication_string = generate_auth_string_hash,                     //             5.7
  .validate_authentication_string = validate_auth_string_hash,                     //             5.7
  .set_salt                       = set_salt,                                      //             5.7
  .authentication_flags           = AUTH_FLAG_PRIVILEGED_USER_FOR_PASSWORD_CHANGE, //             5.7
#endif /* DBMS_mysql >= 57 */
};
#endif /* defined(DBMS_mysql) */

static int init(void *p __attribute__((unused)))
{
  DEBUG xsyslog(LOG_LOCAL7 | LOG_NOTICE, "/flex/coucou/init/"AT);
  return 0;
}

mysql_declare_plugin(flex_plugin)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &auth_flex_handler,
  "auth_flex",
  "Eric Gouyer",
  "Flexible Authentication",
  PLUGIN_LICENSE_GPL,
    init, /* init func */
    NULL, /* deinit func */
  0x0100,
    NULL, /* status variables */
    NULL, /* system variables */
    "1.0 experimental", /* string version representation, eg. "0.1 example" */
#ifdef DBMS_mysql
    0,
#endif
#ifdef DBMS_mariadb /* I am not even sure that it really matters to have this flag */
    MariaDB_PLUGIN_MATURITY_EXPERIMENTAL, /*  MariaDB_PLUGIN_MATURITY_EXPERIMENTAL */
#endif
}
#ifdef DBMS_mysql
,
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
}
,
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
#endif
mysql_declare_plugin_end;
