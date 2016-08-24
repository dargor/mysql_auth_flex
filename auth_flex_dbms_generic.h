#ifndef AUTH_FLEX_DBMS_GENERIC_H
#define AUTH_FLEX_DBMS_GENERIC_H

extern void _find_addr_scramble(MYSQL_PLUGIN_VIO *, MYSQL_SERVER_AUTH_INFO *, struct auth_flex_data *);

#ifdef DBMS_mysql
extern void _find_addr_client_capabilities(MYSQL_PLUGIN_VIO *, MYSQL_SERVER_AUTH_INFO *, struct auth_flex_data *);
#endif

extern void flex_change_plugin_to_cleartext(MYSQL_PLUGIN_VIO *, struct auth_flex_data *);

#endif
