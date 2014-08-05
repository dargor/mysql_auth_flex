#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <syslog.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "config.h"
#include "pam_flex.h"

static int _flex_pam_conv(int num_msg, const struct pam_message **msg,
			  struct pam_response **resp, void *appdata_ptr)
{
  int i;

  DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s", __func__);

  if (num_msg <= 0 || num_msg > 1)
    return PAM_CONV_ERR;
  if (!(*resp = calloc(num_msg, sizeof(**resp))))
    return PAM_BUF_ERR;

  for (i = 0; i < num_msg; ++i)
    {
      struct pam_response *p_resp = resp[i];

      p_resp->resp = NULL;

      switch (msg[i]->msg_style)
	{
	case PAM_PROMPT_ECHO_OFF:
	  p_resp->resp = strdup(appdata_ptr);
	  break;
	case PAM_PROMPT_ECHO_ON:
	  p_resp->resp = strdup(appdata_ptr);
	  break;
	case PAM_ERROR_MSG:
	  break;
	case PAM_TEXT_INFO:
	  break;
	default:
	  break;
	}
    }

  return PAM_SUCCESS;
}

int pam_flex_check(const char *username, const char *password)
{
  struct pam_conv pamc;
  pam_handle_t *pamh;
  int ret_pam;
  int authed = 0;

  DEBUG syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : username/%s password/%s", __func__,
	       username, password);

  pamc = (struct pam_conv){.conv = _flex_pam_conv, .appdata_ptr = (char *)password};

  if ((ret_pam = pam_start("mysql", username, &pamc, &pamh)) != PAM_SUCCESS)
    {
      syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : pam_start() error : %s", __func__, pam_strerror(pamh, ret_pam));
      return 0;
    }

  /*  PAM_DISALLOW_NULL_AUTHTOK : The PAM module service should return PAM_AUTH_ERR if the user does not have a registered authentication token. */
  ret_pam = pam_authenticate(pamh, PAM_SILENT);

  INFO syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : pam_authenticate() error : %s", __func__, pam_strerror(pamh, ret_pam));

  if (ret_pam == PAM_SUCCESS)
    authed = 1;

  if ((ret_pam = pam_end(pamh, ret_pam)) != PAM_SUCCESS)
    {
      syslog(LOG_LOCAL7 | LOG_NOTICE, "%s : pam_end() error : %s", __func__, pam_strerror(pamh, ret_pam));
      return 0;
    }

  return authed;
}
