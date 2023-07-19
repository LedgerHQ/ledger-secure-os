/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"

#include "cx_ecdsa_internal.h"
#include "cx_ecfp_internal.h"
#include "cx_rng_internal.h"

#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "lcx_ecdsa.h"
#include "lcx_rng.h"
#include "lcx_sha256.h"
#include "os_apdu.h"
#include "os_endorsement.h"
#include "os_helpers.h"
#include "os_seed.h"
#include "os_watchdog.h"

/*
 * APDU command "Endorse Set Start" of INS code 0xC0.
 * This command is the first step of a two-steps operation aiming at performing
 * the user’s endorsement key pair setup. This first step consists in retrieving
 * the endorsed public key with its associated certificate signed by the device
 * public key.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Endorsed public key (65)
 *                  Endorsed public key certificate (cert_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_STA_07 if the target is not onboarded
 *           SWO_APD_HDR_04 if the slot 1 is already filled with an endorsement
 * key SWO_APD_HDR_05 if the slot 2 is already filled with an endorsement key
 *           SWO_APD_HDR_06 if the slot value from P1 is incorrect
 *             CX_INVALID_PARAMETER if something went wrong during the
 * endorsement keypair init SWO_SEC_PIN_02 if the pin has not been validated
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_endorse_set_start(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length) {
  cx_sha256_t hash_ctx;
  cx_ecfp_public_key_t publicKey;
  unsigned char hash[CX_SHA256_SIZE];
  unsigned char role;
  unsigned char index;
  size_t sig_len;
  bolos_err_t err = SWO_OK;

  // The P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  role = CERT_ROLE_ENDORSEMENT;

  // ensure personalization is initialized
  if (os_perso_isonboarded() != BOLOS_TRUE) {
    return SWO_APD_STA_07;
  }

  switch (apdu_buffer[APDU_OFF_P1]) {
    case ENDORSEMENT_SLOT_1:
      if (bolos_endorsement_is_private_key_set(ENDORSEMENT_SLOT_1) ==
          BOLOS_TRUE) {
        return SWO_APD_HDR_04;
      }
      break;
    case ENDORSEMENT_SLOT_2:
      if (bolos_endorsement_is_private_key_set(ENDORSEMENT_SLOT_2) ==
          BOLOS_TRUE) {
        return SWO_APD_HDR_05;
      }
      break;
    default:
      return SWO_APD_HDR_06;
      break;
  }
  // reset the SCP session
  G_dashboard.transient_ctx.state = STATE_NONE;
  index = apdu_buffer[APDU_OFF_P1];

  if ((err = cx_ecfp_internal_generate_pair(
           CX_CURVE_256K1, &publicKey,
           &G_dashboard.transient_ctx.tmp.endorse.privateKey, 0))) {
    return err;
  }

  cx_sha256_init_no_throw(&hash_ctx);
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, &role, 1, NULL, 0);
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, CX_LAST, publicKey.W, 65, hash,
                   CX_SHA256_SIZE);
  memmove(apdu_buffer, publicKey.W, 65);

  if (os_security_ensure_elapsed(BOLOS_SECURITY_ATTESTATION_DELAY_S)) {
    os_security_report_fault();
  }

  sig_len = ENDORSEMENT_MAX_ASN1_LENGTH;
  if ((err = bolos_ecdsa_sign_with_factory(
           FACTORY_SETTINGS_SLOT_1, CX_LAST | CX_RND_RFC6979, hash,
           CX_SHA256_SIZE, apdu_buffer + 65, &sig_len))) {
    return err;
  };

  *out_length = 65 + 2 + apdu_buffer[66];
  G_dashboard.transient_ctx.tmp.endorse.keyIndex = index;
  return err;
}

/*
 * APDU command "Endorse Set Commit" of INS code 0xC2.
 * This command is the second step of a two-steps operation aiming at performing
 * the user’s endorsement key pair setup.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Input format: User certificate (cert_len) ||
 *                 User certificate length (1)
 *                 User certificate (cert_len)
 *                 Metadata length (1)
 *                 Metadata (meta_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_HDR_0C if P2 is incorrect
 *           SWO_APD_STA_08 if the target is not onboarded
 *           SWO_APD_HDR_07 if no slots have been personalized
 *           SWO_APD_LEN_07 if the certificate length exceeds max size
 *           SWO_APD_LEN_26 if metadata length exceeds max size
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_endorse_set_commit(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length) {
  unsigned char length;

  UNUSED(in_length);

  // We first peform a check on P2, before actually using it.
  if (apdu_buffer[APDU_OFF_P2] > 0x01) {
    return SWO_APD_HDR_0C;
  }

  // The formatting of the data field depends on the P2 parameter.
  if (apdu_buffer[APDU_OFF_P2] == 0x01) {
    length = apdu_buffer[APDU_OFF_DATA];

  } else {
    length = apdu_buffer[APDU_OFF_LC];
  }

  // ensure personalization is initialized
  if (os_perso_isonboarded() != BOLOS_TRUE) {
    return SWO_APD_STA_08;
  }

  // ensure a key has been personalized
  if ((G_dashboard.transient_ctx.tmp.endorse.keyIndex != ENDORSEMENT_SLOT_1) &&
      (G_dashboard.transient_ctx.tmp.endorse.keyIndex != ENDORSEMENT_SLOT_2)) {
    return SWO_APD_HDR_07;
  }

  if (length > ENDORSEMENT_MAX_ASN1_LENGTH) {
    return SWO_APD_LEN_07;
  }

  // ensure scp session is void
  G_dashboard.transient_ctx.state = STATE_NONE;

  bolos_endorsement_write(
      G_dashboard.transient_ctx.tmp.endorse.keyIndex,
      apdu_buffer + APDU_OFF_DATA + apdu_buffer[APDU_OFF_P2], length,
      &G_dashboard.transient_ctx.tmp.endorse.privateKey, NULL, 0);

  G_dashboard.transient_ctx.tmp.endorse.keyIndex = 0;
  *out_length = 0;
  return SWO_OK;
}

/*
 * APDU command "Endorsement Info Retrieval" of INS code 0xC6.
 * This command allows the retrieval of the following endorsement information
 * from the device, given a specific index:
 * - The endorsement role (which will always be ROLE_ENDORSEMENT)
 * - The public key associated with the given index
 * - The public key certificate associated with the given index
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Role (1)
 *                  Public key length (1)
 *                  Public key (pub_key_len)
 *                  Public key certificate length (1)
 *                  Public key certificate (pub_key_cert_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_HDR_09 if the slot index specified in P1 is invalid
 *           SWO_APD_HDR_0A if the slot 1 is not used
 *           SWO_APD_HDR_0B if the slot 2 is not used
 *             SWO_PAR_VAL_09/0A if the slot index is incorrect
 *             SWO_SEC_CRC_18/19 if the CRC of the endorsement settings is
 * incorrect SWO_SEC_PIN_04/05 if the global PIN has not been validated
 *             SWO_PAR_LEN_03/04 if the slot private key or certificate has
 * empty length CX_INVALID_PARAMETER if the private key curve or size is
 * incorrect
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_endorsement_info_retrieval(uint8_t* apdu_buffer,
                                                      size_t in_length,
                                                      size_t* out_length) {
  bolos_err_t err = SWO_OK;
  unsigned char pub_key_len, cert_len;
  unsigned char index = apdu_buffer[APDU_OFF_P1];

  // The P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  switch (index) {
    case 0x01:
      if (bolos_endorsement_is_slot_active(ENDORSEMENT_SLOT_1) != BOLOS_TRUE)
        return SWO_APD_HDR_0A;
      break;
    case 0x02:
      if (bolos_endorsement_is_slot_active(ENDORSEMENT_SLOT_2) != BOLOS_TRUE)
        return SWO_APD_HDR_0B;
      break;
    default:
      return SWO_APD_HDR_09;
  }

  // The role is the same for both endorsements.
  apdu_buffer[0x00] = CERT_ROLE_ENDORSEMENT;

  if ((err = os_endorsement_get_public_key(index, apdu_buffer + 0x02,
                                           &pub_key_len))) {
    return err;
  }
  apdu_buffer[0x01] = pub_key_len;
  if ((err = os_endorsement_get_public_key_certificate(
           index, apdu_buffer + 0x03 + pub_key_len, &cert_len))) {
    return err;
  }
  apdu_buffer[0x02 + pub_key_len] = cert_len;

  // One byte of role, two bytes of length and two pieces of data.
  *out_length = 0x03 + pub_key_len + cert_len;
  return err;
}