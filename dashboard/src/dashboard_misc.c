/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_ux.h"

#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "cx_ram.h"
#include "lcx_ecdsa.h"
#include "os_apdu.h"
#include "os_helpers.h"
#include "os_io.h"
#include "os_io_seproxyhal.h"
#include "os_nvm.h"
#include "os_pin.h"
#include "os_registry.h"
#include "os_seed.h"
#include "os_utils.h"
#include "os_watchdog.h"

/*
 * APDU command "Reset" of INS code 0x02.
 * This command resets the secure element, closes any open SCP session,and asks
 * for the PIN to be validated again.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_reset(uint8_t* apdu_buffer,
                                 size_t in_length,
                                 size_t* out_length) {
  UNUSED(apdu_buffer);
  UNUSED(in_length);

  // The P1, P2 and length basic tests have been performed in the dispatcher.

  *out_length = 0x00;

  G_dashboard.transient_ctx.state = STATE_SE_RESET;
  G_dashboard.flags = IO_RETURN_AFTER_TX;
  return SWO_OK;
}

/*
 * APDU command "Open App" of INS code 0xD8.
 * This command aims at running an application, which triggers a user consent
 * before the application is effectively launched.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Input format: Application Name (VAR)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_LEN_0A if the length of the command is null
 *           SWO_APD_DAT_07 if the app name did not match any installed apps
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_open_app(uint8_t* apdu_buffer,
                                    size_t in_length,
                                    size_t* out_length) {
  bolos_err_t err = SWO_OK;
  // Will not be used.
  *out_length = 0;

  // The P1, P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  // At least one byte of application name.
  if (!(apdu_buffer[APDU_OFF_LC])) {
    return SWO_APD_LEN_0A;
  }

  unsigned int index = os_registry_count();
  while (index--) {
    G_ux_params.u.run_app.app_idx = index;
    os_registry_get(index, &G_ux_params.u.run_app.app);

    // don't allow running ux or libs
    if ((G_ux_params.u.run_app.app.flags &
         (APPLICATION_FLAG_ENABLED | APPLICATION_FLAG_BOLOS_UX |
          APPLICATION_FLAG_NO_RUN)) == APPLICATION_FLAG_ENABLED) {
      // compare name with the newly installed application
      if (os_registry_get_tag(
              index, NULL, BOLOS_TAG_APPNAME,
              OS_REGISTRY_GET_TAG_OFFSET_COMPARE_WITH_BUFFER | 0,
              (uint8_t*)&apdu_buffer[5], apdu_buffer[APDU_OFF_LC]) == 1) {
        // ask_user_consent if user_settings are not wiped
        G_ux_params.ux_id = BOLOS_UX_CONSENT_RUN_APP;
        G_ux_params.len = sizeof(G_ux_params.u.run_app);
        if ((err = bolos_check_consent(&G_ux_params,
                                       &G_dashboard.reinit_display_on_error,
                                       G_dashboard.bolos_display, 0))) {
          return err;
        }

        // run that app after replied
        // FIXME: flags is not a local variable
        G_dashboard.run_index = index;
        G_dashboard.flags =
            IO_RETURN_AFTER_TX;  // go mcu bl after sw transmitted
        G_dashboard.transient_ctx.state = STATE_RUN_APP;
        return err;
      }
    }
  }
  // name not found
  return SWO_APD_DAT_07;
}

/*
 * APDU command "Set Cxport" of INS code 0xC4.
 * This command aims at setting the cxport rights of the factory settings
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Input format: Cxport Token (2)
 *                 Cxport Signature Length (1)
 *                 Cxport Signature (cxport_sig_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_LEN_02 if the length of the command is not correct
 *           SWO_SEC_CRC_09 if the CRC of the factory slot 1 is not correct
 *           SWO_SEC_SIG_03 if the provided signature is not correct
 *           SWO_SEC_CRC_0A if the CRC of the lifetime settings is not correct
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_set_cxport(uint8_t* apdu_buffer,
                                      size_t in_length,
                                      size_t* out_length) {
  // check command style
  // <CXPORT_TOKEN(2)> <LEN_CXPORT_SIG(1)> <CERT_SIG(LEN_CERT_SIG)>
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc;

  if (in_length != 5u + 2u + 1u + apdu_buffer[5 + 2] ||
      apdu_buffer[5 + 2] == 0) {
    return SWO_APD_LEN_02;
  }

  // ensure device has an initialized context.
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
    return err;
  } else if (crc != BOLOS_TRUE) {
    return SWO_SEC_CRC_09;
  }

  // validate the token signature using the factory public.
  bolos_factory_hash_cxport_with_public_key(apdu_buffer + 5,
                                            apdu_buffer + 5 + 2 + 1 + 128);

  if (os_security_ensure_elapsed(BOLOS_SECURITY_ATTESTATION_DELAY_S)) {
    os_security_report_fault();
  }

  // validate signature of the public key using the provided master key, this
  // avoid invalid state (should be done before writing parameters, but crc is
  // not updated yet)
  if (!bolos_ecdsa_verify_with_signer_public(
          FACTORY_SETTINGS_SLOT_1, apdu_buffer + 5 + 2 + 1 + 128,
          CX_SHA256_SIZE, &apdu_buffer[5 + 2 + 1], apdu_buffer[5 + 2])) {
    return SWO_SEC_SIG_03;
  }

  // The preprocessing checks have been done, we can write them in memory.
  if ((err = bolos_write_cxport_rights(apdu_buffer, 5))) {
    return err;
  }

  *out_length = 0;
  return err;
}

/*
 * APDU command "Get Cxport" of INS code 0xC5.
 * This command aims at setting the cxport rights of the factory settings
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Cxport rights (2)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_SEC_CRC_24 if the CRC of the lifetime settings is not correct
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_get_cxport(uint8_t* apdu_buffer,
                                      size_t in_length,
                                      size_t* out_length) {
  bolos_err_t err = SWO_OK;
  UNUSED(in_length);
  if ((err = bolos_read_cxport_rights(apdu_buffer, out_length))) {
    return err;
  }
  return err;
}

/**
 * This function returns the number of characters of 'words_buffer'
 * corresponding to 12 words.
 */
static size_t dashboard_get_12_words_buffer_length(const uint8_t* words_buffer,
                                                   size_t words_buffer_length) {
  uint8_t spaces_count = 0;
  size_t offset;

  for (offset = 0; offset < words_buffer_length; offset++) {
    if (words_buffer[offset] == ' ') {
      spaces_count++;
    }
    if (spaces_count == 12) {
      break;
    }
  }
  return offset;
}

/**
 * This function sends the words to check to the UX app.
 *
 */
static bolos_err_t dashboard_check_mnemonic(const uint8_t* words_buffer,
                                            size_t words_buffer_length) {
  G_ux_params.ux_id = BOLOS_UX_CHECK_MNEMONIC;
  G_ux_params.len = 0;
  memcpy(G_ux_params.u.bip39.words_buffer, (const char*)words_buffer,
         words_buffer_length);
  G_ux_params.u.bip39.words_buffer_length = words_buffer_length;
  if (os_ux_blocking(&G_ux_params) == BOLOS_UX_CANCEL) {
    return SWO_SEC_CHK_24;
  }
  G_dashboard.reinit_display_on_error = true;

  return SWO_OK;
}

/*
 * APDU command "Onboard" of INS code 0xDO.
 * This command is meant to allow users to perform seed provisioning (setup
 * identity) by the mean of an APDU instead of using secure on-target user
 * input. This command enables to setup the main identity when the product is in
 * recovery mode. Additional PIN protected and temporary identities can also be
 * set using this command.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Input format: PIN length (1)
 *                 PIN (pin_len)
 *                 Prefix length (1)
 *                 Prefix (prefix_len)
 *                 Passphrase length (1)
 *                 Passphrase (pass_len)
 *                 Recovery words length (1)
 *                 Recovery words (recovery_words_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_SEC_CRC_12 if the CRC of the first factory slot is not correct
 *           SWO_APD_STA_09 if setting an alternate identity without the main
 * one set SWO_APD_STA_0A if trying to repersonalize the main identity
 *           SWO_APD_HDR_08 if trying to perso an incorrect alternate identity
 *           SWO_APD_LEN_08 if command length is not correct
 *           SWO_APD_STA_0B if trying to personalize the tmp identity with a PIN
 *           SWO_APD_STA_0C if trying to personalize any identity without a PIN
 *           SWO_APD_STA_0D if no recovery words are provided and target not yet
 * personalized SWO_APD_LEN_09 if passphrase and prefix length exceeds max value
 *           SWO_SEC_CHK_04 if there is a watchdog fault
 *           SWO_APD_STA_0E/0F if target already personalized
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_onboard(uint8_t* apdu_buffer,
                                   size_t in_length,
                                   size_t* out_length) {
  // perform unsafe onboarding
  // CLA INS P1(ID) P2 LC
  // <pin_length(1B)> <pin> // not set for IDTMP (ignored)
  // <prefix_length(1B)> <seedprefix> // can be null, if null, BIP39 MNEMONIC is
  // used, to support all possible derivations <passphrase_length(1B)>
  // <passphrase> // can be null <words_length(1B)> <recovery words> // only for
  // ID0,

  /*
  python -m ledgerblue.unsafeOnboard --apdu --id 0 --pin "0000" --words "abandon
  abandon abandon abandon abandon abandon abandon abandon abandon abandon
  abandon about" python -m ledgerblue.unsafeOnboard --apdu --id 0 --pin "0000"
  --prefix "mnemonic" --passphrase "" --words "abandon abandon abandon abandon
  abandon abandon abandon abandon abandon abandon abandon about" python -m
  ledgerblue.unsafeOnboard --apdu --id 1 --pin "1111" --prefix "mnemonic"
  => id 0 and 1 shall have the same seed:
  5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4

  python -m ledgerblue.unsafeOnboard --apdu --id 1 --pin "1111" --prefix
  "mnemonic" --passphrase "abandon"
  => id 1 seed shall be
  666c9a5050365a191f363f7e71028d159f39e7941dfd23394721bfdb517fb4ff4d8d8d8daa3513991e80848ec9ad0ef3bfba35cd660fbac6c69e8b0aa670ba19

  python -m ledgerblue.unsafeOnboard --apdu --id 1 --pin "1111" --prefix
  "mnemonic" --passphrase "abandon" --words "abandon abandon abandon abandon
  abandon abandon abandon abandon abandon abandon abandon about"
  => id 1 seed shall be
  666c9a5050365a191f363f7e71028d159f39e7941dfd23394721bfdb517fb4ff4d8d8d8daa3513991e80848ec9ad0ef3bfba35cd660fbac6c69e8b0aa670ba19

  python -m ledgerblue.unsafeOnboard --apdu --id 2 --prefix "mnemonic2"
  --passphrase "abandon2" --words "abandon abandon abandon abandon abandon
  abandon abandon abandon abandon"
  => idtmp seed shall be
  6e33098df877083586bf7de8bcdb3d8f3e23029a23a40e79ded0ad0afc54ba6b48a85ea91032ef2b2ce40fd7f29fda0a85da8d5d98eb22bd47b7fd9e82f0f3a1

  // WIPE TOKEN
  python -m ledgerblue.unsafeOnboard --apdu --id 0 --pin "0000" --prefix
  "mnemonic2" --passphrase "abandon2" --words "abandon abandon abandon abandon
  abandon abandon abandon abandon abandon abandon abandon about"
  => id0 seed shall be
  d153d04e088a4264d072defa6f75bd2050e340d819683d602b90103c4d82e1f0209e570acefa92a8a5091e4ef85b139cd8adfa28fc833bfdbb6f85c1b4e5462d
  */
  unsigned int off_pin_len, off_prefix_len, off_passphrase_len, off_words_len;
  unsigned int last_offset;
  uint8_t p1;
  bolos_err_t err = SWO_OK;
  bolos_bool_t is_onboarded, crc;

  // The P2 basic tests has been performed in the dispatcher.

  // ensure device is initialized
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
    return err;
  } else if (crc != BOLOS_TRUE) {
    return SWO_SEC_CRC_12;
  }

  // extract offset of fields
  off_pin_len = APDU_OFF_DATA;
  off_prefix_len = off_pin_len + 1 + apdu_buffer[off_pin_len];
  off_passphrase_len = off_prefix_len + 1 + apdu_buffer[off_prefix_len];
  off_words_len = off_passphrase_len + 1 + apdu_buffer[off_passphrase_len];
  last_offset = off_words_len;
  p1 = apdu_buffer[APDU_OFF_P1];

  is_onboarded = os_perso_isonboarded();

  // can't setup alternate identities before the main one
  if (p1 > 0 && is_onboarded != BOLOS_TRUE) {
    return SWO_APD_STA_09;
  }
  // don't allow reperso when already onboarded, wait for a wipe
  if (p1 == 0 && is_onboarded == BOLOS_TRUE) {
    return SWO_APD_STA_0A;
  }
  // do not allow for unrecognized identities
  if (p1 > INS_ONBOARD_P1_IDTMP) {
    return SWO_APD_HDR_08;
  }
  // check global command formatting
  if (in_length != last_offset + 1 + apdu_buffer[last_offset]) {
    return SWO_APD_LEN_08;
  }
  // no pin for idTMP
  if (p1 == INS_ONBOARD_P1_IDTMP && apdu_buffer[off_pin_len] != 0) {
    return SWO_APD_STA_0B;
  }
  // main or alternate seed without a pin is unsupported
  if (p1 < INS_ONBOARD_P1_IDTMP && apdu_buffer[off_pin_len] == 0) {
    return SWO_APD_STA_0C;
  }

  // if no words provided, use id0 onboarded ones
  if (apdu_buffer[off_words_len] == 0) {
    // invalid data provided, must provide with words at least for the initial
    // onboarding
    if (os_perso_isonboarded() != BOLOS_TRUE) {
      return SWO_APD_STA_0D;
    }
  }

  // DESIGN NOTE: won't check the passphrase size as both passphrase and prefix
  // are fitting the apdu size, and therefore fits the pbkdf2 salt buffer
  // underneath
  if ((unsigned int)(apdu_buffer[off_prefix_len] +
                     apdu_buffer[off_passphrase_len] + 4) >
      PBKDF2_SALT_MAX_LENGTH) {
    return SWO_APD_LEN_09;
  }

  // arm the onboard timer to avoid performing onboarding in less than a given
  // time delay is in useconds
  if ((err = os_watchdog_arm(BOLOS_SECURITY_ONBOARD_DELAY_S * 1000000UL,
                             OS_WATCHDOG_NOACTION))) {
    return err;
  }

  // if no perso set, then remove all app to avoid leaking informations
  if (os_perso_isonboarded() != BOLOS_TRUE) {
    bolos_erase_all(NO_USER_PREF_PRESERVED);
  }

  // arm the onboard timer to avoid performing onboarding in less than a given
  // time delay is in useconds
  if (os_watchdog_value() == 0) {
    // clearly an attack scenario
    os_security_report_fault();
    // We throw as a countermeasure to double faults attacks.
    return SWO_SEC_CHK_04;
  }

  // ask user consent when setting alternate/temporary seed
  if (p1 > 0 || os_perso_isonboarded() == BOLOS_TRUE) {
    // invalidate pin to ensure entered in the UX
    os_global_pin_invalidate();

    G_ux_params.ux_id = BOLOS_UX_CONSENT_NOT_INTERACTIVE_ONBOARD;
    G_ux_params.u.onboard.id = p1;
    G_ux_params.len = sizeof(G_ux_params.u.onboard);
    if ((err = bolos_check_consent(&G_ux_params,
                                   &G_dashboard.reinit_display_on_error,
                                   G_dashboard.bolos_display, 1))) {
      return err;
    }
  } else {
    // Check whether the words are well formed
    // Only store at most 12 words in G_ux_params to save memory on LNS
    size_t words_cut_length = dashboard_get_12_words_buffer_length(
        apdu_buffer + off_words_len + 1, apdu_buffer[off_words_len]);
    // Send the first 12 words
    if (apdu_buffer[off_words_len] >= words_cut_length) {
      G_ux_params.u.bip39.flag = BOLOS_BIP39_CHECK_MNEMONIC_START;
      if ((err = dashboard_check_mnemonic(
               (const uint8_t*)apdu_buffer + off_words_len + 1,
               words_cut_length))) {
        return err;
      }
    } else {
      words_cut_length = 0;
    }
    // Send the remaining words if any, and check the mnemonic
    G_ux_params.u.bip39.flag = BOLOS_BIP39_CHECK_MNEMONIC_END;
    if ((err = dashboard_check_mnemonic(
             (const uint8_t*)apdu_buffer + off_words_len + 1 + words_cut_length,
             apdu_buffer[off_words_len] - words_cut_length))) {
      return err;
    }
  }

  // we're gonna be in the blind for awhile
  G_ux_params.ux_id = BOLOS_UX_PROCESSING;
  G_ux_params.len = 0;
  os_ux_blocking(&G_ux_params);
  G_dashboard.reinit_display_on_error = true;
  // finalize display
  io_seproxyhal_general_status();

  // consume the timer event before being able to reply
  io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                         sizeof(G_io_seproxyhal_spi_buffer), 0);

  bolos_wait_onboarding();

  // perform derivation and seed set
  os_perso_derive_and_set_seed(
      p1, (char*)apdu_buffer + off_prefix_len + 1, apdu_buffer[off_prefix_len],
      (char*)apdu_buffer + off_passphrase_len + 1,
      apdu_buffer[off_passphrase_len], (char*)apdu_buffer + off_words_len + 1,
      apdu_buffer[off_words_len]);

  // seal perso and set pin if requested
  switch (p1) {
    case 0:
      // robustness
      if (os_perso_isonboarded() == BOLOS_TRUE) {
        return SWO_APD_STA_0E;
      }
      os_perso_set_pin(0, apdu_buffer + off_pin_len + 1,
                       apdu_buffer[off_pin_len], false);
      os_perso_finalize();
      // validate pin to activate this identity
      os_global_pin_check(apdu_buffer + off_pin_len + 1,
                          apdu_buffer[off_pin_len]);
      // robustness
      if (os_perso_isonboarded() != BOLOS_TRUE) {
        return SWO_APD_STA_0F;
      }
      break;
    case 1:
      os_perso_set_pin(1, apdu_buffer + off_pin_len + 1,
                       apdu_buffer[off_pin_len], true);
      // validate pin to activate this identity
      os_global_pin_check(apdu_buffer + off_pin_len + 1,
                          apdu_buffer[off_pin_len]);
      break;
  }

  G_dashboard.reinit_display = true;
  *out_length = 0;
  return err;
}