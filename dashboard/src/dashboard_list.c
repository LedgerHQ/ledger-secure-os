/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_ux.h"

#include "dashboard_prototypes.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "os_helpers.h"
#include "os_registry.h"
#include "os_types.h"

static void dashboard_list_apps_internal(uint8_t* apdu_buffer,
                                         size_t* out_length) {
  bolos_list_internal(apdu_buffer, out_length,
                      &G_dashboard.transient_ctx.list_index, true);

  // no app listed, return 0 length instead of the magic solely
  // OR last entry reached last time
  if (*out_length == 1) {
    *out_length = 0;
    G_dashboard.transient_ctx.list_state = LIST_NOT_STARTED;
    G_dashboard.transient_ctx.list_index = 0;
  }
}

/*
 * APDU command "Secure List Apps" of SEC_INS code 0x0E.
 * This command aims at retrieving information on all the installed
 * applications, when a SCP session is open. If the length of the
 * to-be-retrieved information is too big to fit within a single APDU response,
 * the host needs to send back several List Applications Continue (Secure) APDU
 * commands, until no more data can be retrieved.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Format version magic (1)
 *                    Application entry length (1)
 *                    Application size in blocks (2)
 *                    Application flags (2)
 *                    Application code sha256 hash (32)
 *                    Application full sha256 hash (32)
 *                    Application name length (1)
 *                    Application name (app_name_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_secure_list_apps(uint8_t* apdu_buffer,
                                            size_t in_length,
                                            size_t* out_length) {
  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  G_dashboard.transient_ctx.list_index = 0;
  G_dashboard.transient_ctx.list_state = LIST_STARTED_SCP;
  dashboard_list_apps_internal(apdu_buffer, out_length);
  return SWO_OK;
}

/*
 * APDU command "Secure List Apps Continue" of SEC_INS code 0x0F.
 * This command aims at retrieving information on all the installed
 * applications, when the response of the previsouly sent List Applications
 * (Secure) APDU command could not contain all the to-be-retrieved information.
 * The host then needs to send back several List Applications Continue (Secure)
 * APDU commands, until no more data can be retrieved.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Format version magic (1)
 *                    Application entry length (1)
 *                    Application size in blocks (2)
 *                    Application flags (2)
 *                    Application code sha256 hash (32)
 *                    Application full sha256 hash (32)
 *                    Application name length (1)
 *                    Application name (app_name_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_STA_23 if a list apps secure command has not been sent
 * prior to this
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_secure_list_apps_continue(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length) {
  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  if (G_dashboard.transient_ctx.list_state != LIST_STARTED_SCP) {
    return SWO_APD_STA_23;
  }
  dashboard_list_apps_internal(apdu_buffer, out_length);
  return SWO_OK;
}

/*
 * APDU command "List Apps" of SEC_INS code 0xDE.
 * This command aims at retrieving information on all the installed
 * applications. If the length of the to-be-retrieved information is too big to
 * fit within a single APDU response, the host needs to send back several List
 * Applications Continue APDU commands, until no more data can be retrieved.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Format version magic (1)
 *                    Application entry length (1)
 *                    Application size in blocks (2)
 *                    Application flags (2)
 *                    Application code sha256 hash (32)
 *                    Application full sha256 hash (32)
 *                    Application name length (1)
 *                    Application name (app_name_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_SEC_PIN_01/02 if the global has not been validated
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_unsecure_list_apps(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length) {
  bolos_err_t err = SWO_OK;
  uint8_t issuer_or_custom_ca_trusted;

  // The P1, P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  issuer_or_custom_ca_trusted =
      bolos_is_issuer_trusted() || bolos_is_customca_trusted();

  // We do not prompt the consent display if this session already trusts the
  // issuer.
  if (!issuer_or_custom_ca_trusted) {
    G_ux_params.ux_id = BOLOS_UX_CONSENT_LISTAPPS;
    G_ux_params.len = 0;
    if ((err = bolos_check_consent(
             &G_ux_params, &G_dashboard.reinit_display_on_error,
             G_dashboard.bolos_display, 0 /*no pin for that*/))) {
      return err;
    }
  }

  G_dashboard.transient_ctx.list_index = 0;
  G_dashboard.transient_ctx.list_state = LIST_STARTED_NOSCP;

  dashboard_list_apps_internal(apdu_buffer, out_length);
  return err;
}

/*
 * APDU command "List Apps Continue" of INS code 0xDF.
 * This command aims at retrieving information on all the installed
 * applications, when the response of the previsouly sent List Applications APDU
 * command could not contain all the to-be-retrieved information. The host then
 * needs to send back several List Applications Continue APDU commands, until no
 * more data can be retrieved.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Format version magic (1)
 *                    Application entry length (1)
 *                    Application size in blocks (2)
 *                    Application flags (2)
 *                    Application code sha256 hash (32)
 *                    Application full sha256 hash (32)
 *                    Application name length (1)
 *                    Application name (app_name_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_STA_24 if a list apps command has not been sent prior to
 * this
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_unsecure_list_apps_continue(uint8_t* apdu_buffer,
                                                       size_t in_length,
                                                       size_t* out_length) {
  // The P1, P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  if (G_dashboard.transient_ctx.list_state != LIST_STARTED_NOSCP) {
    return SWO_APD_STA_24;
  }
  dashboard_list_apps_internal(apdu_buffer, out_length);
  return SWO_OK;
}