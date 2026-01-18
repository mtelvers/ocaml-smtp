/* PAM C stubs for OCaml
   RFC 5321 SMTP server - Authentication via PAM

   Implements SASL authentication (RFC 4954) using PAM backend.
*/

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

/* Conversation data passed to PAM callback */
struct conv_data {
    const char *password;
};

/* PAM conversation function - provides password when PAM asks */
static int pam_conv_func(int num_msg, const struct pam_message **msg,
                         struct pam_response **resp, void *appdata_ptr)
{
    struct conv_data *data = (struct conv_data *)appdata_ptr;
    struct pam_response *reply;
    int i;

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
        return PAM_CONV_ERR;

    reply = calloc(num_msg, sizeof(struct pam_response));
    if (reply == NULL)
        return PAM_BUF_ERR;

    for (i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON:
            /* Provide the password */
            reply[i].resp = strdup(data->password);
            if (reply[i].resp == NULL) {
                /* Free already allocated responses */
                for (int j = 0; j < i; j++) {
                    free(reply[j].resp);
                }
                free(reply);
                return PAM_BUF_ERR;
            }
            reply[i].resp_retcode = 0;
            break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            /* Ignore informational messages */
            reply[i].resp = NULL;
            reply[i].resp_retcode = 0;
            break;
        default:
            /* Free already allocated responses */
            for (int j = 0; j < i; j++) {
                free(reply[j].resp);
            }
            free(reply);
            return PAM_CONV_ERR;
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
}

/* OCaml binding: authenticate username password service_name -> bool */
CAMLprim value caml_pam_authenticate(value v_service, value v_username, value v_password)
{
    CAMLparam3(v_service, v_username, v_password);

    const char *service = String_val(v_service);
    const char *username = String_val(v_username);
    const char *password = String_val(v_password);

    pam_handle_t *pamh = NULL;
    int retval;

    struct conv_data data = { .password = password };
    struct pam_conv conv = {
        .conv = pam_conv_func,
        .appdata_ptr = &data
    };

    /* Start PAM session */
    retval = pam_start(service, username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        CAMLreturn(Val_false);
    }

    /* Authenticate */
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        CAMLreturn(Val_false);
    }

    /* Check account validity */
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        CAMLreturn(Val_false);
    }

    /* Clean up */
    pam_end(pamh, PAM_SUCCESS);
    CAMLreturn(Val_true);
}

/* OCaml binding: check if PAM is available */
CAMLprim value caml_pam_available(value unit)
{
    CAMLparam1(unit);
    /* If we compiled with PAM support, it's available */
    CAMLreturn(Val_true);
}
