/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"

#include "dashboard.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "os_apdu.h"
#include "os_io.h"
#include "os_io_seproxyhal.h"
#include "os_pin.h"
#include "os_seed.h"

// This function performs the basic P1, P2 and Length checks when these values
// are fixed for any command.
static bolos_err_t dashboard_preprocessing_checks(
    const dashboard_apdu_dispatcher_t* dispatcher_entry,
    uint8_t* apdu_buffer,
    size_t in_length) {
  // We check the parameters.
  if ((dispatcher_entry->dispatcher_p1 != P1_VAR) &&
      (dispatcher_entry->dispatcher_p1 != apdu_buffer[APDU_OFF_P1])) {
    return SWO_APD_HDR_0E;
  }

  if ((dispatcher_entry->dispatcher_p2 != P2_VAR) &&
      (dispatcher_entry->dispatcher_p2 != apdu_buffer[APDU_OFF_P2])) {
    return SWO_APD_HDR_0F;
  }

  // We check that the Lc byte is coherent with the received length.
  if (in_length != (size_t)(apdu_buffer[APDU_OFF_LC] + APDU_OFF_DATA)) {
    return SWO_APD_HDR_10;
  }

  // We check the received length.
  if ((dispatcher_entry->dispatcher_length != LC_VAR) &&
      (dispatcher_entry->dispatcher_length != apdu_buffer[APDU_OFF_LC])) {
    return SWO_APD_HDR_11;
  }

  // We clear the transient context to close any existing SCP connection
  // if the incoming APDU is an unsecure one and if the current state is
  // authenticated
  if ((dispatcher_entry->dispatcher_instruction != INS_SECURE_COMMAND) &&
      (G_dashboard.transient_ctx.state == STATE_MUTUAL_AUTHENTICATED)) {
    memset(&G_dashboard.transient_ctx, 0, sizeof(G_dashboard.transient_ctx));
  }
  return SWO_OK;
}

// This function performs the basic length checks when these values
// are fixed for any secure command, once deciphered.
static bolos_err_t dashboard_secure_preprocessing_checks(
    const dashboard_apdu_secure_dispatcher_t* dispatcher_entry,
    size_t in_length) {
  // We check the received length.
  if ((dispatcher_entry->dispatcher_length != LC_VAR) &&
      (dispatcher_entry->dispatcher_length != in_length)) {
    return SWO_APD_HDR_12;
  }
  return SWO_OK;
}

// This function looks for the received INS byte, performs basic checks and
// calls the associated APDU handler.
bolos_err_t dashboard_handle_apdu(uint8_t* apdu_buffer,
                                  size_t in_length,
                                  size_t* out_length) {
  bolos_err_t err = SWO_OK;
  unsigned int current;

  // We find the correct non-secure dispatcher entry.
  for (current = 0; current < DISPATCHER_NON_SECURE_LENGTH; current++) {
    if (C_dashboard_dispatcher_non_secure[current].dispatcher_instruction ==
        apdu_buffer[APDU_OFF_INS]) {
      break;
    }
  }

  if (DISPATCHER_NON_SECURE_LENGTH == current) {
    return SWO_APD_INS_02;
  }

  G_io_app.transfer_mode = 0;

  // We perform header checks.
  if ((err = dashboard_preprocessing_checks(
           &C_dashboard_dispatcher_non_secure[current], apdu_buffer,
           in_length))) {
    return err;
  }

  // We can call the associated function and return the resulting error (if one)
  if ((err = C_dashboard_dispatcher_non_secure[current].dispatcher_function(
           apdu_buffer, in_length, out_length))) {
    return err;
  }
  return SWO_OK;
}

bolos_err_t dashboard_handle_secure_apdu(uint8_t* apdu_buffer,
                                         size_t in_length,
                                         size_t* out_length) {
  bolos_err_t err = SWO_OK;
  unsigned int current;

  // retrieve data (all raw loader commands are case 2)
  in_length = apdu_buffer[APDU_OFF_LC];

  /////////////////////////////////////////////////////////////
  // SECURITY CHECK
  /////////////////////////////////////////////////////////////

  // kthx you can reset the plug, manually :)
  if (G_dashboard.transient_ctx.state != STATE_MUTUAL_AUTHENTICATED
      // when pin locked, secure channel is disabled => avoid a forgotten token
      // to allow app management if the owner pin is not entered
      || (os_global_pin_is_validated() != BOLOS_TRUE &&
          os_perso_is_pin_set() == BOLOS_TRUE)) {
    return SWO_APD_STA_15;
  }

  // decrypt and unpad data
  // CLA INS P1 P2 LC CIHERDATA
  size_t plaintext_length = 0;
  if (dashboard_scp_unwrap(&G_dashboard.transient_ctx.secret.scp,
                           apdu_buffer + 5, in_length, &plaintext_length)) {
    // Immediately close the channel if wrapped data is incorrect.
    // Make sure to change transient context state, as SCP structure does not
    // have any state field.
    dashboard_scp_close(&G_dashboard.transient_ctx.secret.scp);
    G_dashboard.transient_ctx.state = STATE_TARGET_VALIDATED;
    return SWO_UNIQUE_SCP_ERROR;
  }

  if (plaintext_length < 1) {
    return SWO_APD_LEN_15;
  }

  if (G_dashboard.transient_ctx.state != STATE_MUTUAL_AUTHENTICATED) {
    return SWO_APD_STA_16;
  }

  /////////////////////////////////////////////////////////////
  // DISPATCH
  /////////////////////////////////////////////////////////////
  const dashboard_apdu_secure_dispatcher_t* secure_dispatcher =
      C_dashboard_secure_dispatcher;
  uint32_t secure_dispatcher_length = DISPATCHER_SECURE_LENGTH;
  if (SCP_RECOVER == G_dashboard.transient_ctx.scp_type) {
    secure_dispatcher = C_dashboard_recover_secure_dispatcher;
    secure_dispatcher_length = DISPATCHER_RECOVER_SECURE_LENGTH;
  }

  // We find the correct secure dispatcher entry.
  for (current = 0; current < secure_dispatcher_length; current++) {
    if (secure_dispatcher[current].dispatcher_instruction ==
        apdu_buffer[APDU_OFF_SECINS]) {
      break;
    }
  }

  if (secure_dispatcher_length == current) {
    return SWO_APD_INS_01;
  }

  err = dashboard_is_secure_instruction_allowed(apdu_buffer[APDU_OFF_SECINS]);
  if (err != SWO_OK) {
    return err;
  }

  // We perform the length checks if relevant, the length parameter stores the
  // plaintext length (APDU header excepted) at this point.
  if ((err = dashboard_secure_preprocessing_checks(&secure_dispatcher[current],
                                                   plaintext_length))) {
    return err;
  }

  // We can call the associated function.
  return secure_dispatcher[current].dispatcher_function(
      apdu_buffer, plaintext_length, out_length);
}