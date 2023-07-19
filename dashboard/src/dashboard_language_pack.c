/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"

#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"
#include "os_apdu.h"

#include "bolos.h"
#include "bolos_ux.h"
#include "ux_loc.h"

static bolos_err_t dashboard_del_data(unsigned int data_id) {
  bolos_err_t err = SWO_OK;
  // Search for a language pack having the specified language
  unsigned slot_idx = os_registry_count();
  while (slot_idx--) {
    application_t* app = &N_application_registry.applications[slot_idx];

    if (app->flags & APPLICATION_FLAG_LANGUAGE_PACK) {
      LANGUAGE_PACK* lp = (LANGUAGE_PACK*)(app->nvram_begin);
      // Check if we want to remove that language pack
      if (P1_DEL_ALL_LANGUAGE_PACK == data_id || lp->language == data_id) {
        if ((err = dashboard_delete_slot(slot_idx, false))) {
          return err;
        }
        slot_idx = os_registry_count();
      }
    }
  }
  return err;
}

/*
 * APDU command "Create Language Pack" of INS code 0x30.
 * This command will create a slot in the registry to store a language pack.
 *
 * @param apdu_buffer Contains the input data when the command is received.
 * - Input format: P1 contains the language ID that will be installed.
 *                 LC contains LC_VAL_CREATE_LANGUAGE_PACK (4).
 *                 DATA contains the size needed (4 bytes in BE format).
 *
 * - Output format: None.
 *
 * Please note that a consent screen is displayed: if the user is, for exemple,
 * in the control center, then the consent screen will be displayed when the
 * user will return to the dashboard.
 *
 * This command is intended to be followed by:
 *  - dashboard_apdu_load_language_pack (as many time as necessary)
 *  - dashboard_apdu_commit_language_pack (once, to check the signature)
 *
 * @param in_length The input length.
 * @param out_length  = 0, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors:  SWO_APD_DAT_1B if P1 value is not correct.
 *            SWO_APD_LEN_2C if LC != LC_VAL_CREATE_LANGUAGE_PACK.
 *            SWO_SEC_PIN_01 if consent is denied.
 *            SWO_SEC_PIN_02 if consent is not validated.
 *            any error returned by dashboard_delete_slot (ie SWO_APD_STA_21).
 *
 * - Success: SWO_OK if everything went well.
 */

bolos_err_t dashboard_apdu_create_language_pack(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length) {
  UNUSED(in_length);
  bolos_err_t err = SWO_OK;
  unsigned int data_len = U4BE(apdu_buffer, APDU_OFF_DATA);
  unsigned char language = apdu_buffer[APDU_OFF_P1];

  if (NB_LANG <= language) {
    return SWO_APD_DAT_1B;
  }

  if (apdu_buffer[APDU_OFF_LC] != LC_VAL_CREATE_LANGUAGE_PACK) {
    return SWO_APD_LEN_2C;
  }

  // Ask user consent before installing the language pack
  // (and do it before deleting the current language!)
  G_ux_params.ux_id = BOLOS_UX_CONSENT_LANG_ADD;
  G_ux_params.u.langaddel.language = language;
  G_ux_params.len = 0;
  if ((err = bolos_check_consent(&G_ux_params,
                                 &G_dashboard.reinit_display_on_error,
                                 G_dashboard.bolos_display, 0))) {
    return err;
  }

  // Remove previous language pack, if any
  if ((err = dashboard_del_data(language))) {
    return err;
  }

  // Prepare the installation of this Language Pack
  *out_length = dashboard_create_slot(APPLICATION_FLAG_LANGUAGE_PACK, data_len,
                                      0, 0, 0, NULL);
  // Store language parameter (will be checked on next APDUs)
  G_dashboard.transient_ctx.language = language;
  return err;
}

/*
 * APDU command "Load Language Pack" of INS code 0x31.
 * This command will add data to a slot in the registry, to store the data of a
 * language pack.
 * Create Language Pack APDU must have been called before.
 * As a chunk of data can only store BOLOS_SCP_MTU (224) bytes, there will be
 * as much call to this function as necessary to transfer all data.
 *
 * @param apdu_buffer Contains the input data when the command is received.
 * - Input format: P1 contains the language ID that will be installed.
 *                 DATA contains offset to store data (4 bytes in BE format).
 *                 &apdu_buffer[APDU_OFF_DATA + 4] contain the data to load.
 *
 * - Output format: None.
 *
 * This command is intended to be preceded by:
 *  - dashboard_apdu_create_language_pack (once, to create the slot)
 * This command is intended to be followed by:
 *  - dashboard_apdu_commit_language_pack (once, to check the signature)
 *
 * @param in_length The input length.
 * @param out_length  = 0, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors:  SWO_APD_LEN_2D if there is no data in apdu_buffer.
 *            SWO_APD_DAT_19 if P1 value is not correct.
 *            SWO_SEC_APP_1C if P1 is different than P1 used with `Create`.
 *            any error returned by dashboard_load_chunk (ie SWO_SEC_APP_06,
 *  SWO_SEC_APP_07 or SWO_APD_DAT_0B).
 *
 * - Success: SWO_OK if everything went well.
 */

bolos_err_t dashboard_apdu_load_language_pack(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length) {
  // at least: 5 bytes header | 4 bytes offset
  if (in_length < APDU_OFF_DATA + 4) {
    return SWO_APD_LEN_2D;
  }

  size_t chunk_length = in_length - APDU_OFF_DATA - 4UL;
  uint8_t* chunk_ptr = apdu_buffer + APDU_OFF_DATA + 4;
  unsigned int offset = U4BE(apdu_buffer, APDU_OFF_DATA);
  unsigned char language = apdu_buffer[APDU_OFF_P1];

  // the UX has changed to processing, need to reset the display to dashboard
  // upon error
  dashboard_app_ux_processing();

  if (NB_LANG <= language) {
    return SWO_APD_DAT_19;
  }

  // Check language is the same than when create_language_pack was called
  if (language != G_dashboard.transient_ctx.language) {
    return SWO_SEC_APP_1C;
  }

  // Load the data
  *out_length = dashboard_load_chunk(chunk_ptr, chunk_length, offset, false);
  return SWO_OK;
}

/*
 * APDU command "Commit Language Pack" of INS code 0x32.
 * This command will check the signature of the language pack that was just
 * 'Created' & 'Loaded' into a registry slot.
 * If the signature is correct, then the language pack is 'finalized' and kept
 * into the registry, and the system starts using that language.
 *
 * @param apdu_buffer Contains the input data when the command is received.
 * - Input format: P1 contains the language ID that will be installed.
 *                 LC contains LC_VAL_CREATE_LANGUAGE_PACK (4).
 *                 DATA contains the size needed (4 bytes in BE format).
 *
 * - Output format: None.
 *
 * This command is intended to be preceded by:
 *  - dashboard_apdu_create_language_pack (once, to create the slot)
 *  - dashboard_apdu_load_language_pack (as many time as necessary)
 *
 * @param in_length The input length.
 * @param out_length  = 0, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors:  SWO_APD_DAT_1C if P1 value is not correct.
 *            SWO_SEC_APP_1D if P1 is different than P1 used with `Create`.
 *            SWO_SEC_SIG_10 if there is no signature in apdu_buffer.
 *            SWO_SEC_SIG_0A if the signature is not fine.
 *            any error returned by dashboard_commit_finalize (ie
 * SWO_SEC_CHK_1C).
 *
 * - Success: SWO_OK if everything went well.
 */

bolos_err_t dashboard_apdu_commit_language_pack(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length) {
  bolos_err_t err = SWO_OK;
  unsigned char language = apdu_buffer[APDU_OFF_P1];
  dashboard_ctx* ctx = &G_dashboard.transient_ctx;
  application_t* app = &ctx->current_application;

  // the UX has changed to processing, need to reset the display to dashboard
  // upon error
  dashboard_app_ux_processing();

  if (NB_LANG <= language) {
    return SWO_APD_DAT_1C;
  }

  // Check language is the same than when create_language_pack was called
  if (language != ctx->language) {
    return SWO_SEC_APP_1D;
  }

  // A signature is MANDATORY for language packs!
  if (in_length <= APDU_OFF_DATA) {
    return SWO_SEC_SIG_10;
  }

  // update language pack full hash
  cx_hash_no_throw((cx_hash_t*)&ctx->load_hash_ctx, CX_LAST, NULL, 0,
                   app->sha256_full, CX_SHA256_SIZE);

  // Offset of the byte containing the signature len, in apdu_buffer
  uint8_t sig_offset = 5;

  if (dashboard_commit_check_signature(apdu_buffer + sig_offset + 1,
                                       apdu_buffer[sig_offset],
                                       &U_secure_element_packsign_public_key)) {
    app->flags |= APPLICATION_FLAG_SIGNED;
    // Add flags to enable those data and make them 'invisible' in the dashboard
    app->flags |= APPLICATION_FLAG_ENABLED;
    app->flags |= APPLICATION_FLAG_NO_RUN;
    if ((err = dashboard_commit_finalize())) {
      return err;
    }
  } else {
    return SWO_SEC_SIG_0A;
  }
  *out_length = 0;
  return err;
}

/*
 * APDU command "Delete Language Pack" of INS code 0x33.
 * This command will delete the Language Pack specified in P1,
 * or all installed ones if P1 = P1_DEL_ALL_LANGUAGE_PACK (0xFF).
 *
 * @param apdu_buffer Contains the input data when the command is received.
 * - Input format: P1 contains the language ID to be deleted (or 0xFF for all).
 *
 * - Output format: None.
 *
 * Please note that no consent screen is displayed and no error is returned,
 * whether there is a corresponding Language Pack installed or not.
 *
 * @param in_length The input length.
 * @param out_length  = 0, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors:  SWO_APD_DAT_1A if P1 value is not correct.
 *            any error returned by dashboard_delete_slot (ie SWO_APD_STA_21).
 *
 * - Success: SWO_OK if everything went well.
 */

bolos_err_t dashboard_apdu_del_language_pack(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length) {
  bolos_err_t err = SWO_OK;
  unsigned char language = apdu_buffer[APDU_OFF_P1];
  UNUSED(in_length);

  if (NB_LANG <= language && P1_DEL_ALL_LANGUAGE_PACK != language) {
    return SWO_APD_DAT_1A;
  }

  // Remove that language pack
  if ((err = dashboard_del_data(language))) {
    return err;
  }
  *out_length = 0;
  G_dashboard.reinit_display = true;
  return err;
}

void dashboard_list_language_packs_internal(uint8_t* apdu_buffer,
                                            size_t* out_length) {
  bolos_list_internal(apdu_buffer, out_length,
                      &G_dashboard.transient_ctx.list_index, false);

  // no language pack listed, return 0 length instead of the magic solely
  // OR last entry reached last time
  if (*out_length == 1) {
    *out_length = 0;
    G_dashboard.transient_ctx.list_state = LIST_NOT_STARTED;
    G_dashboard.transient_ctx.list_index = 0;
  }
}

/*
 * APDU command "List Language Packs" of INS code 0x34.
 * This command return information about installed Language Packs.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Input format: P1 must be P1_LIST_LANGUAGE_PACKS_FIRST for first call and
 *                 LIST_LANGUAGE_PACKS_NEXT for next calls until out_length=0
 *
 * - Output format: out_length bytes writen in apdu_buffer.
 *
 * Please note that apdu_buffer may contain up to BOLOS_SCP_MTU (224) bytes and
 * must be dimensionned accordingly!
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors:  SWO_APD_STA_2D if LIST_LANGUAGE_PACKS_NEXT is used on first call.
 *
 * - Success: SWO_OK if everything went well.
 */

bolos_err_t dashboard_apdu_list_language_packs(uint8_t* apdu_buffer,
                                               size_t in_length,
                                               size_t* out_length) {
  unsigned char first_or_next_listing = apdu_buffer[APDU_OFF_P1];
  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  if (P1_LIST_LANGUAGE_PACKS_FIRST != first_or_next_listing) {
    if (G_dashboard.transient_ctx.list_state != LIST_STARTED_SCP) {
      return SWO_APD_STA_2D;
    }
  } else {
    G_dashboard.transient_ctx.list_index = 0;
    G_dashboard.transient_ctx.list_state = LIST_STARTED_SCP;
  }

  dashboard_list_language_packs_internal(apdu_buffer, out_length);
  return SWO_OK;
}