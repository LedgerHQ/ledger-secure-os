/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos.h"
#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_ux.h"
#include "cx_ecdsa_internal.h"
#include "cx_rng_internal.h"
#include "cx_sha256.h"
#include "dashboard_common.h"
#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"
#include "errors.h"
#include "exceptions.h"
#include "lcx_aes_siv.h"
#include "os_apdu.h"
#include "os_helpers.h"
#include "os_nvm.h"
#include "os_seed.h"
#include "os_types.h"
#include "os_ux.h"

#define RECOVER_CONFIRM_RESTORE "Confirm restore"

// SHA256('ledger/protect/trust/services')
const unsigned int recover_bip32_path[RECOVER_BIP32_PATH_LEN] = {
    0x80000000, 0xd3167252, 0xc5eecdb7, 0x881add64, 0xd488f5ae,
    0xbddb4ca2, 0x80ee2e36, 0xee8af150, 0xf061d037};

static bool is_recover_scp_set(void) {
  return (G_dashboard.transient_ctx.state == STATE_MUTUAL_AUTHENTICATED) &&
         (G_dashboard.transient_ctx.scp_type == SCP_RECOVER);
}

static void dashboard_recover_display(bolos_ux_t ux_id) {
  G_ux_params.ux_id = ux_id;
  G_ux_params.len = 0;
  os_ux_blocking(&G_ux_params);
  G_dashboard.reinit_display_on_error = true;
}

bolos_err_t dashboard_apdu_secure_recover_set_ca(uint8_t* apdu_buffer,
                                                 size_t in_length,
                                                 size_t* out_length) {
  uint32_t offset;
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc_custom_ca;

  // Check that Recover secure channel is established
  if (!is_recover_scp_set()) {
    return SWO_APD_STA_18;
  }

  if (bolos_is_recovery() != BOLOS_TRUE) {
    return SWO_APD_STA_34;
  }

  // Offset corresponding to the public key length
  offset = APDU_SECURE_DATA_OFF + 1 + apdu_buffer[APDU_SECURE_DATA_OFF];

  if (offset >= in_length + APDU_OFF_DATA) {
    return SWO_APD_LEN_16;
  }

  if (apdu_buffer[APDU_SECURE_DATA_OFF] > CUSTOMCA_MAXLEN - 1) {
    return SWO_APD_DAT_19;
  }

  if (apdu_buffer[offset] > RECOVER_SECP256K1_PK_LEN) {
    return SWO_APD_DAT_1A;
  }

  if ((err = bolos_check_crc_consistency(CRC_CUSTOM_CA, &crc_custom_ca))) {
    return err;
  }

  if (crc_custom_ca == BOLOS_TRUE) {
    return SWO_SEC_CRC_24;
  }

  cx_ecdsa_internal_init_public_key(
      CX_CURVE_256K1, apdu_buffer + offset + 1, apdu_buffer[offset],
      &G_dashboard.transient_ctx.ephemeral_public);

  G_ux_params.ux_id = BOLOS_UX_CONSENT_SETUP_PROTECT_CA_KEY;
  memset(&G_ux_params.u.setup_customca.name, 0,
         sizeof(G_ux_params.u.setup_customca.name));
  memcpy(&G_ux_params.u.setup_customca.name,
         apdu_buffer + APDU_SECURE_DATA_OFF + 1,
         apdu_buffer[APDU_SECURE_DATA_OFF]);
  memcpy(&G_ux_params.u.setup_customca.pub,
         &G_dashboard.transient_ctx.ephemeral_public,
         sizeof(G_ux_params.u.setup_customca.pub));
  G_ux_params.len = sizeof(G_ux_params.u.setup_customca);

  if ((err = bolos_check_consent(&G_ux_params,
                                 &G_dashboard.reinit_display_on_error,
                                 G_dashboard.bolos_display, 1))) {
    return err;
  }

  bolos_custom_ca_write(apdu_buffer, APDU_SECURE_DATA_OFF,
                        &G_dashboard.transient_ctx.ephemeral_public,
                        G_dashboard.transient_ctx.scp_type);
  bolos_set_trust_customca(1);

  if ((err = bolos_check_crc_consistency(CRC_CUSTOM_CA, &crc_custom_ca))) {
    return err;
  } else if (crc_custom_ca != BOLOS_TRUE) {
    return SWO_SEC_CRC_15;
  }

  // Redraw dashboard to draw custom CA icon
  G_dashboard.reinit_display = true;

  *out_length = 0;
  return err;
}

bolos_err_t dashboard_apdu_secure_recover_delete_ca(uint8_t* apdu_buffer,
                                                    size_t in_length,
                                                    size_t* out_length) {
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc_custom_ca;
  unsigned int offset;

  // Check that Recover secure channel is established
  if (!is_recover_scp_set()) {
    return SWO_APD_STA_20;
  }

  if (bolos_is_recovery() != BOLOS_TRUE) {
    return SWO_APD_STA_35;
  }

  offset = APDU_SECURE_DATA_OFF + 1 + apdu_buffer[APDU_SECURE_DATA_OFF];

  if (offset >= in_length + 5) {
    return SWO_APD_DAT_27;
  }

  if ((err = bolos_check_crc_consistency(CRC_CUSTOM_CA, &crc_custom_ca))) {
    return err;
  }

  if (crc_custom_ca != BOLOS_TRUE) {
    return SWO_SEC_CRC_25;
  }

  if ((err = bolos_custom_ca_consent_for_reset(
           &G_dashboard.reinit_display_on_error, G_dashboard.bolos_display))) {
    return err;
  }

  bolos_set_trust_customca(0);
  bolos_custom_ca_wipe();

  *out_length = 0;
  G_dashboard.reinit_display = true;
  return err;
}

static void dashboard_recover_get_info(cx_sha256_t* hash_ctx,
                                       uint8_t* buffer,
                                       char* info,
                                       uint32_t* offset) {
  memcpy(info, buffer + *offset + 1, buffer[*offset]);
  cx_sha256_update(hash_ctx, (const uint8_t*)info, buffer[*offset]);
  G_ux_params.u.recover.data_len += buffer[*offset];
  *offset += 1 + buffer[*offset];
}

bolos_err_t dashboard_apdu_secure_recover_validate_backup_data(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length) {
  uint32_t offset;
  bolos_err_t err = SWO_OK;
  uint8_t state;
  cx_sha256_t hash_ctx;

  // Check that Recover secure channel is established
  if (!is_recover_scp_set()) {
    return SWO_APD_STA_22;
  }

  if (in_length <= 2) {
    return SWO_APD_DAT_1C;
  }

  if (in_length < RECOVER_BACKUP_ID_LEN + 1) {
    return SWO_APD_DAT_1B;
  }

  offset = APDU_SECURE_DATA_OFF;
  // Store the backup id and the backup data needed by the 'validate backup data
  // hash' command
  memcpy(G_dashboard.transient_ctx.recover.info.backup_id, apdu_buffer + offset,
         RECOVER_BACKUP_ID_LEN);
  offset += RECOVER_BACKUP_ID_LEN;

  if (apdu_buffer[offset] > RECOVER_BACKUP_NAME_MAXLEN) {
    return SWO_APD_DAT_2B;
  }

  // Hash the backup data
  cx_sha256_init_no_throw(&hash_ctx);
  cx_sha256_update(&hash_ctx, apdu_buffer + offset + 1, apdu_buffer[offset]);

  offset += 1 + apdu_buffer[offset];

  memset(&G_ux_params, 0, sizeof(G_ux_params));
  G_ux_params.ux_id = BOLOS_UX_CONSENT_RECOVER_CONFIRM_USER;
  if ((RECOVER_FIRSTNAME_TAG == apdu_buffer[offset++]) &&
      (apdu_buffer[offset] <= RECOVER_FIRST_NAME_MAXLEN)) {
    dashboard_recover_get_info(&hash_ctx, apdu_buffer,
                               G_ux_params.u.recover.first_name, &offset);
  } else {
    return SWO_APD_DAT_2E;
  }
  if ((RECOVER_NAME_TAG == apdu_buffer[offset++]) &&
      (apdu_buffer[offset] <= RECOVER_LAST_NAME_MAXLEN)) {
    dashboard_recover_get_info(&hash_ctx, apdu_buffer,
                               G_ux_params.u.recover.last_name, &offset);
  } else {
    return SWO_APD_DAT_2F;
  }
  if ((RECOVER_BIRTH_TAG == apdu_buffer[offset++]) &&
      (apdu_buffer[offset] <= RECOVER_DATE_OF_BIRTH_MAXLEN)) {
    dashboard_recover_get_info(&hash_ctx, apdu_buffer,
                               G_ux_params.u.recover.date_of_birth, &offset);
  } else {
    return SWO_APD_DAT_30;
  }
  if ((RECOVER_PLACE_TAG == apdu_buffer[offset]) &&
      ((0 == apdu_buffer[offset + 1]))) {
    // Do not display anything for "place of birth"
  } else if ((RECOVER_PLACE_TAG == apdu_buffer[offset++]) &&
             ((apdu_buffer[offset] <= RECOVER_PLACE_OF_BIRTH_MAXLEN))) {
    dashboard_recover_get_info(&hash_ctx, apdu_buffer,
                               G_ux_params.u.recover.place_of_birth, &offset);
  } else {
    return SWO_APD_DAT_31;
  }
  G_ux_params.len = sizeof(G_ux_params.u.recover);
  if ((err = bolos_check_consent(&G_ux_params,
                                 &G_dashboard.reinit_display_on_error,
                                 G_dashboard.bolos_display, 0))) {
    return err;
  }

  cx_sha256_final(&hash_ctx,
                  G_dashboard.transient_ctx.recover.info.backup_data_hash);

  G_dashboard.transient_ctx.host_chain_length = 0;
  G_dashboard.transient_ctx.recover.state = STATE_RECOVER_CONFIRM_BACKUP;
  G_dashboard.transient_ctx.recover.share_number = 0;
  *out_length = 0;
  os_perso_recover_state(&state, GET_STATE);
  if (ONBOARDING_STATUS_RECOVER_RESTORE_SEED ==
      RECOVER_ONBOARDING_STATUS(state)) {
    // The 4 most significant bits set STATE_RECOVER_CONFIRM_BACKUP and
    // STATE_RECOVER_CODE_GENERATED and the 4 less significant bits set
    // ONBOARDING_STATUS_RECOVER_RESTORE_SEED
    state |= ((uint8_t)STATE_RECOVER_CONFIRM_BACKUP << 4);
    os_perso_recover_state(&state, SET_STATE);
  }
  memset(G_dashboard.transient_ctx.recover.polynomial_seed, 0,
         sizeof(G_dashboard.transient_ctx.recover.polynomial_seed));
  cx_rng_internal(G_dashboard.transient_ctx.recover.polynomial_seed, 32);

  return err;
}

bolos_err_t dashboard_apdu_secure_recover_validate_certificate(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length) {
  uint32_t offset, sig_offset;
  cx_sha256_t hash_ctx;
  uint8_t hash[CX_SHA256_SIZE];
  bolos_err_t err = SWO_OK;
  uint8_t state;
  bolos_bool_t crc_custom_ca;

  // Check that Recover secure channel is established
  if (!is_recover_scp_set()) {
    return SWO_APD_STA_37;
  }

  if (in_length <= 2) {
    return SWO_APD_DAT_20;
  }

  if (RECOVER_SHARES_NUMBER == G_dashboard.transient_ctx.recover.share_number) {
    explicit_bzero(&G_dashboard.transient_ctx.recover,
                   sizeof(G_dashboard.transient_ctx.recover));
    return SWO_SEC_STA_0D;
  }

  if ((G_dashboard.transient_ctx.recover.state &
       STATE_RECOVER_CONFIRM_BACKUP) == 0) {
    // Device was turned off after 'validate_backup_data'
    os_perso_recover_state(&state, GET_STATE);
    // The 4 most significant bits set STATE_RECOVER_CONFIRM_BACKUP
    // and the 4 less significant bits set
    // ONBOARDING_STATUS_RECOVER_RESTORE_SEED
    if (RECOVER_CONFIRM_BACKUP_STATE(state) != STATE_RECOVER_CONFIRM_BACKUP) {
      return SWO_APD_STA_33;
    }
  }

  // Offset corresponding to the certificate version
  offset = APDU_SECURE_DATA_OFF + 1;
  hash[0] = apdu_buffer[offset];
  hash[1] = apdu_buffer[++offset];
  // Offset corresponding to the name length
  offset++;

  if (INS_VALIDATE_CERTIFICATE_P1_LAST == apdu_buffer[APDU_SECURE_DATA_OFF]) {
    if (hash[1] != CERT_ROLE_RECOVER_PROVIDER_EPHEMERAL) {
      return SWO_APD_DAT_29;
    }
  } else {
    if (hash[1] != CERT_ROLE_RECOVER_PROVIDER) {
      return SWO_APD_DAT_2A;
    }
  }
  cx_sha256_init_no_throw(&hash_ctx);
  // Hash the version and the certificate's role
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, hash, 2, NULL, 0);
  // Hash the certificate's name length and value
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, apdu_buffer + offset,
                   apdu_buffer[offset] + 1, NULL, 0);
  offset += 1 + apdu_buffer[offset];
  // Hash the certificate's public key length and value
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, CX_LAST, apdu_buffer + offset,
                   apdu_buffer[offset] + 1, hash, CX_SHA256_SIZE);

  // Offset corresponding to the signature length
  sig_offset = offset + 1 + apdu_buffer[offset];

  if (G_dashboard.transient_ctx.host_chain_length == 0) {
    if ((err = bolos_check_crc_consistency(CRC_CUSTOM_CA, &crc_custom_ca))) {
      return err;
    }
    if ((crc_custom_ca != BOLOS_TRUE) &&
        bolos_ecdsa_verify_with_root_ca(hash, CX_SHA256_SIZE,
                                        apdu_buffer + sig_offset + 1,
                                        apdu_buffer[sig_offset])) {
      G_dashboard.transient_ctx.auth_source_flags = APPLICATION_FLAG_ISSUER;
      ;
      // Enforce the state to STATE_MUTUAL_AUTHENTICATED for further uses of
      // the secure channel
      dashboard_accept_certificate(apdu_buffer + offset + 1,
                                   apdu_buffer[offset],
                                   STATE_MUTUAL_AUTHENTICATED);
    } else if ((crc_custom_ca == BOLOS_TRUE) &&
               (0 == bolos_check_ca_type(G_dashboard.transient_ctx.scp_type)) &&
               bolos_ecdsa_verify_with_custom_ca(hash, CX_SHA256_SIZE,
                                                 apdu_buffer + sig_offset + 1,
                                                 apdu_buffer[sig_offset])) {
      G_dashboard.transient_ctx.auth_source_flags = APPLICATION_FLAG_CUSTOM_CA;
      dashboard_accept_certificate(apdu_buffer + offset + 1,
                                   apdu_buffer[offset],
                                   STATE_MUTUAL_AUTHENTICATED);
    } else {
      return SWO_SEC_SIG_11;
    }
  } else {
    if (!cx_ecdsa_internal_verify(&G_dashboard.transient_ctx.host_public, hash,
                                  CX_SHA256_SIZE, apdu_buffer + sig_offset + 1,
                                  apdu_buffer[sig_offset])) {
      return SWO_SEC_SIG_12;
    } else {
      // Enforce the state to STATE_MUTUAL_AUTHENTICATED for further uses of
      // the secure channel
      dashboard_accept_certificate(apdu_buffer + offset + 1,
                                   apdu_buffer[offset],
                                   STATE_MUTUAL_AUTHENTICATED);
      G_dashboard.transient_ctx.recover.state =
          STATE_RECOVER_VALID_CERTIFICATES |
          (G_dashboard.transient_ctx.recover.state &
           STATE_RECOVER_CONFIRM_MASK);
    }
  }

  *out_length = 0;
  return err;
}

static void dashboard_secure_recover_display_code(void) {
  G_ux_params.ux_id = BOLOS_UX_RECOVER_DISPLAY_CODE;
  G_ux_params.u.recover.data_len = 4;
  G_ux_params.len = sizeof(G_ux_params.u.recover);
  bolos_check_consent(&G_ux_params, &G_dashboard.reinit_display_on_error,
                      G_dashboard.bolos_display, 0);
  G_dashboard.transient_ctx.recover.provider_number++;
}

bolos_err_t dashboard_apdu_secure_recover_mutual_authenticate(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length) {
  UNUSED(apdu_buffer);

  if (!is_recover_scp_set() || ((G_dashboard.transient_ctx.recover.state &
                                 STATE_RECOVER_VALID_CERTIFICATES) !=
                                STATE_RECOVER_VALID_CERTIFICATES)) {
    return SWO_APD_STA_29;
  }

  if (in_length > 1) {
    return SWO_APD_DAT_21;
  }

  if (dashboard_ecdh(&G_dashboard.transient_ctx.recover.ephemeral_private,
                     CX_ECDH_X, G_dashboard.transient_ctx.host_public.W,
                     RECOVER_SECP256K1_PK_LEN,
                     G_dashboard.transient_ctx.recover.derived_key,
                     RECOVER_AES_SIV_KEY_LEN)) {
    return SWO_SEC_KEY_03;
  }
  G_dashboard.transient_ctx.recover.state =
      STATE_RECOVER_MUTUAL_AUTHENTICATED |
      (G_dashboard.transient_ctx.recover.state & STATE_RECOVER_CONFIRM_MASK);
  G_dashboard.transient_ctx.host_chain_length = 0;
  cx_sha256_init_no_throw(&G_dashboard.transient_ctx.load_hash_ctx);
  explicit_bzero(
      &G_dashboard.transient_ctx.recover.share_info.commitments,
      sizeof(G_dashboard.transient_ctx.recover.share_info.commitments));
  G_dashboard.transient_ctx.recover.share_info.commitments_length = 0;

  *out_length = 0;
  return SWO_OK;
}

bolos_err_t dashboard_apdu_secure_recover_validate_backup_data_hash(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length) {
  cx_sha256_t hash_ctx;
  uint8_t device_hash[CX_SHA256_SIZE];
  uint32_t offset;
  uint8_t state;
  bolos_err_t err = SWO_OK;

  if (!is_recover_scp_set() || ((G_dashboard.transient_ctx.recover.state &
                                 STATE_RECOVER_MUTUAL_AUTHENTICATED) !=
                                STATE_RECOVER_MUTUAL_AUTHENTICATED)) {
    return SWO_APD_STA_32;
  }

  if (in_length <= 2) {
    return SWO_APD_DAT_28;
  }

  offset = APDU_SECURE_DATA_OFF;
  if ((err = dashboard_decrypt_and_verify(
           G_dashboard.transient_ctx.recover.derived_key,
           apdu_buffer + offset + 1 + AES_SIV_TAG_LEN, CX_SHA256_SIZE,
           apdu_buffer + offset + 1 + apdu_buffer[APDU_SECURE_DATA_OFF],
           apdu_buffer + offset + 1))) {
    return err;
  }

  cx_sha256_init_no_throw(&hash_ctx);
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0,
                   (const uint8_t*)G_dashboard.transient_ctx.host_public.W,
                   RECOVER_SECP256K1_PK_LEN, NULL, 0);

  cx_hash_no_throw(
      (cx_hash_t*)&hash_ctx, 0,
      (const uint8_t*)G_dashboard.transient_ctx.recover.info.backup_id,
      RECOVER_BACKUP_ID_LEN, NULL, 0);

  cx_hash_no_throw(
      (cx_hash_t*)&hash_ctx, CX_LAST,
      (const uint8_t*)G_dashboard.transient_ctx.recover.info.backup_data_hash,
      CX_SHA256_SIZE, device_hash, CX_SHA256_SIZE);

  if (memcmp(device_hash,
             apdu_buffer + offset + 1 + apdu_buffer[APDU_SECURE_DATA_OFF],
             CX_SHA256_SIZE) != 0) {
    return SWO_APD_DAT_1E;
  }

  memset(apdu_buffer, 0, IO_APDU_BUFFER_SIZE);
  os_perso_recover_state(&state, GET_STATE);
  if (ONBOARDING_STATUS_RECOVER_RESTORE_SEED ==
      RECOVER_ONBOARDING_STATUS(state)) {
    if ((err = dashboard_encrypt_and_digest(
             G_dashboard.transient_ctx.recover.derived_key,
             (uint8_t*)RECOVER_CONFIRM_RESTORE, strlen(RECOVER_CONFIRM_RESTORE),
             apdu_buffer + AES_SIV_TAG_LEN, apdu_buffer))) {
      return err;
    }
    if (0 == G_dashboard.transient_ctx.recover.provider_number) {
      cx_sha256_init_no_throw(&hash_ctx);
      device_hash[0] = RECOVER_CODE_CONFIRMATION_CONSTANT;
      cx_sha256_update(&hash_ctx, device_hash, 1);
      cx_sha256_update(&hash_ctx, G_dashboard.transient_ctx.recover.derived_key,
                       RECOVER_AES_SIV_KEY_LEN);
      cx_sha256_final(&hash_ctx, device_hash);
      memset(&G_ux_params, 0, sizeof(G_ux_params));
      G_ux_params.u.recover.code[0] =
          (device_hash[0] % 10) << 4 | (device_hash[1] % 10);
      G_ux_params.u.recover.code[1] =
          (device_hash[2] % 10) << 4 | (device_hash[3] % 10);
      dashboard_secure_recover_display_code();
    }
  }

  *out_length = strlen(RECOVER_CONFIRM_RESTORE) + AES_SIV_TAG_LEN;
  return err;
}

bolos_err_t dashboard_apdu_secure_recover_get_share(uint8_t* apdu_buffer,
                                                    size_t in_length,
                                                    size_t* out_length) {
  os_perso_derive_node_with_seed_key_internal_params_t params;
  cx_ecpoint_t P;
  uint8_t p1;
  uint8_t nwords;
  uint8_t tag[AES_SIV_TAG_LEN];
  uint8_t output[IO_APDU_BUFFER_SIZE];
  size_t domain_len;
  bolos_err_t err = SWO_OK;

  if (os_perso_isonboarded() != BOLOS_TRUE) {
    return SWO_SEC_STA_0D;
  }

  if (!is_recover_scp_set() || ((G_dashboard.transient_ctx.recover.state &
                                 STATE_RECOVER_MUTUAL_AUTHENTICATED) !=
                                STATE_RECOVER_MUTUAL_AUTHENTICATED)) {
    return SWO_APD_STA_2D;
  }

  if (in_length > 2) {
    return SWO_APD_DAT_1D;
  }

  dashboard_recover_display(BOLOS_UX_PROCESSING);

  p1 = apdu_buffer[APDU_SECURE_DATA_OFF];

  memset(apdu_buffer, 0, IO_APDU_BUFFER_SIZE);

  if ((INS_RECOVER_GET_SHARE_P1 == p1) &&
      (G_dashboard.transient_ctx.recover.share_number == 0)) {
    G_dashboard.transient_ctx.recover.share_info.shares[0].index =
        cx_rng_u32_internal() & 0x7FFFFFFF;
  }
  if (INS_RECOVER_GET_SHARE_P1_COMMIT_POINT == p1) {
    memcpy(apdu_buffer, G_dashboard.transient_ctx.recover.commit_point,
           sizeof(G_dashboard.transient_ctx.recover.commit_point));
    G_dashboard.transient_ctx.recover.state = STATE_RECOVER_CONFIRM_BACKUP;
    G_dashboard.transient_ctx.recover.share_number++;
    *out_length = sizeof(G_dashboard.transient_ctx.recover.commit_point);
  } else {
    U4LE_ENCODE(apdu_buffer, CX_VSS_SECRET_SIZE,
                G_dashboard.transient_ctx.recover.share_info.shares[0].index +
                    G_dashboard.transient_ctx.recover.share_number);
    if ((err = bolos_get_master_seed_shares(
             apdu_buffer,
             G_dashboard.transient_ctx.recover.share_info.commitments,
             G_dashboard.transient_ctx.recover.commit_point,
             sizeof(G_dashboard.transient_ctx.recover.commit_point),
             G_dashboard.transient_ctx.recover.polynomial_seed,
             sizeof(G_dashboard.transient_ctx.recover.polynomial_seed),
             out_length))) {
      return err;
    }
    if (INS_RECOVER_GET_SHARE_P1_COMMIT == p1) {
      memcpy(apdu_buffer,
             G_dashboard.transient_ctx.recover.share_info.commitments,
             RECOVER_SHARING_THRESHOLD * sizeof(cx_vss_commitment_t));
      *out_length = RECOVER_SHARING_THRESHOLD * sizeof(cx_vss_commitment_t);
    } else if (INS_RECOVER_GET_SHARE_P1 == p1) {
      params.mode = HDW_NORMAL;
      params.from_app = BOLOS_FALSE;
      params.curve = CX_CURVE_SECP256K1;
      params.path = recover_bip32_path;
      params.pathLength = RECOVER_BIP32_PATH_LEN;
      params.privateKey = G_dashboard.transient_ctx.recover.derived_key;
      params.chain = NULL;
      params.seed_key = NULL;
      params.seed_key_length = 0;

      os_perso_derive_node_with_seed_key_internal(&params);
      if ((err = cx_ecdomain_parameters_length(CX_CURVE_SECP256K1,
                                               &domain_len))) {
        return err;
      }
      if ((err = cx_bn_lock(domain_len, 0))) {
        return err;
      }
      if ((err = cx_ecpoint_alloc(&P, CX_CURVE_SECP256K1))) {
        cx_bn_unlock();
        return err;
      }
      if ((err = cx_ecdomain_generator_bn(CX_CURVE_SECP256K1, &P))) {
        cx_bn_unlock();
        return err;
      }
      if ((err = cx_ecpoint_rnd_fixed_scalarmul(
               &P, G_dashboard.transient_ctx.recover.derived_key,
               RECOVER_BIP32_DERIVED_KEY))) {
        cx_bn_unlock();
        return err;
      }
      apdu_buffer[*out_length] = 0x04;
      *out_length += 1;
      err =
          cx_ecpoint_export(&P, apdu_buffer + *out_length, domain_len,
                            apdu_buffer + *out_length + domain_len, domain_len);
      cx_bn_unlock();
      if (err) {
        return err;
      }
      *out_length += domain_len * 2;
      explicit_bzero(&G_dashboard.transient_ctx.recover.derived_key,
                     sizeof(G_dashboard.transient_ctx.recover.derived_key));

      // Hash the commitments
      cx_hash_sha256((const uint8_t*)G_dashboard.transient_ctx.recover
                         .share_info.commitments,
                     RECOVER_SHARING_THRESHOLD * sizeof(cx_vss_commitment_t),
                     apdu_buffer + *out_length, CX_SHA256_SIZE);

      *out_length += CX_SHA256_SIZE;

      // Encrypt with the key shared with the provider
      if (dashboard_ecdh(&G_dashboard.transient_ctx.recover.ephemeral_private,
                         CX_ECDH_X, G_dashboard.transient_ctx.host_public.W,
                         RECOVER_SECP256K1_PK_LEN,
                         G_dashboard.transient_ctx.recover.derived_key,
                         RECOVER_AES_SIV_KEY_LEN)) {
        return SWO_SEC_KEY_04;
      }
      if ((err = dashboard_encrypt_and_digest(
               G_dashboard.transient_ctx.recover.derived_key, apdu_buffer,
               *out_length, output, tag))) {
        return err;
      }
      nwords = bolos_get_mnemonic_words_number();
      explicit_bzero(&G_dashboard.transient_ctx.recover.derived_key,
                     sizeof(G_dashboard.transient_ctx.recover.derived_key));
      memcpy(apdu_buffer, tag, AES_SIV_TAG_LEN);
      memcpy(apdu_buffer + AES_SIV_TAG_LEN, output, *out_length);
      *out_length += AES_SIV_TAG_LEN;
      apdu_buffer[*out_length] = nwords;
      *out_length += 1;
    } else {
      return SWO_APD_DAT_1F;
    }
  }

  return err;
}

static bolos_err_t dashboard_recover_copy_commits(uint8_t* in_commits,
                                                  size_t in_length,
                                                  size_t* out_length) {
  if (*out_length + in_length >
      sizeof(G_dashboard.transient_ctx.recover.share_info.commitments)) {
    return SWO_APD_DAT_2D;
  }
  memcpy(G_dashboard.transient_ctx.recover.share_info.commitments + *out_length,
         in_commits, in_length);
  *out_length += in_length;
  return SWO_OK;
}

bolos_err_t dashboard_apdu_secure_recover_validate_commit(uint8_t* apdu_buffer,
                                                          size_t in_length,
                                                          size_t* out_length) {
  uint32_t offset;
  bolos_err_t err = SWO_OK;

  if (!is_recover_scp_set()) {
    return SWO_APD_STA_2E;
  }

  if (in_length <= 2) {
    return SWO_APD_DAT_23;
  }

  offset = APDU_SECURE_DATA_OFF + 1;
  switch (apdu_buffer[APDU_SECURE_DATA_OFF]) {
    case INS_RECOVER_VALIDATE_P1_COMMIT:
      if ((err = cx_sha256_update(&G_dashboard.transient_ctx.load_hash_ctx,
                                  apdu_buffer + offset + 1,
                                  apdu_buffer[offset]))) {
        return err;
      }
      if ((err = dashboard_recover_copy_commits(
               apdu_buffer + offset + 1, apdu_buffer[offset],
               &G_dashboard.transient_ctx.recover.share_info
                    .commitments_length))) {
        return err;
      }
      break;
    case INS_RECOVER_VALIDATE_P1_COMMIT_LAST:
      if ((err = cx_sha256_update(&G_dashboard.transient_ctx.load_hash_ctx,
                                  apdu_buffer + offset + 1,
                                  apdu_buffer[offset]))) {
        return err;
      }
      if ((err = cx_sha256_final(&G_dashboard.transient_ctx.load_hash_ctx,
                                 G_dashboard.transient_ctx.recover.chain))) {
        return err;
      }
      if ((err = dashboard_recover_copy_commits(
               apdu_buffer + offset + 1, apdu_buffer[offset],
               &G_dashboard.transient_ctx.recover.share_info
                    .commitments_length))) {
        return err;
      }
      break;
    case INS_RECOVER_VALIDATE_P1_COMMIT_HASH:
      if (dashboard_ecdh(&G_dashboard.transient_ctx.recover.ephemeral_private,
                         CX_ECDH_X, G_dashboard.transient_ctx.host_public.W,
                         RECOVER_SECP256K1_PK_LEN,
                         G_dashboard.transient_ctx.recover.derived_key,
                         RECOVER_AES_SIV_KEY_LEN)) {
        return SWO_SEC_KEY_05;
      }
      if ((err = dashboard_decrypt_and_verify(
               G_dashboard.transient_ctx.recover.derived_key,
               apdu_buffer + offset + 1 + AES_SIV_TAG_LEN,
               apdu_buffer[offset] - AES_SIV_TAG_LEN,
               apdu_buffer + offset + 1 + apdu_buffer[offset],
               apdu_buffer + offset + 1))) {
        return err;
      }
      explicit_bzero(&G_dashboard.transient_ctx.recover.derived_key,
                     sizeof(G_dashboard.transient_ctx.recover.derived_key));
      if (memcmp(G_dashboard.transient_ctx.recover.chain,
                 apdu_buffer + offset + 1 + apdu_buffer[offset],
                 CX_SHA256_SIZE) != 0) {
        return SWO_APD_DAT_22;
      }
      G_dashboard.transient_ctx.recover.state =
          STATE_RECOVER_COMMIT_VALIDATED |
          (G_dashboard.transient_ctx.recover.state &
           STATE_RECOVER_CONFIRM_MASK);
      break;
    default:
      return SWO_APD_DAT_24;
  }

  // Return to dashboard
  if (RECOVER_SHARES_NUMBER == G_dashboard.transient_ctx.recover.share_number) {
    G_dashboard.reinit_display = true;
  }

  memset(apdu_buffer, 0, IO_APDU_BUFFER_SIZE);
  *out_length = 0;
  return SWO_OK;
}

bolos_err_t dashboard_apdu_secure_recover_restore_seed(uint8_t* apdu_buffer,
                                                       size_t in_length,
                                                       size_t* out_length) {
  uint32_t offset;
  bolos_err_t err;
  cx_vss_share_t* current_share;
  bool verified;
  uint8_t state = 0;

  if (!is_recover_scp_set() ||
      ((G_dashboard.transient_ctx.recover.state &
        STATE_RECOVER_COMMIT_VALIDATED) != STATE_RECOVER_COMMIT_VALIDATED)) {
    return SWO_APD_STA_30;
  }

  os_perso_recover_state(&state, GET_STATE);

  if ((BOLOS_TRUE == os_perso_isonboarded()) ||
      (ONBOARDING_STATUS_RECOVER_RESTORE_SEED !=
       RECOVER_ONBOARDING_STATUS(state))) {
    return SWO_SEC_STA_0C;
  }

  if (in_length <= 2) {
    return SWO_APD_DAT_25;
  }

  // Get the number of bip39 words to derive from the master seed
  switch (apdu_buffer[APDU_SECURE_DATA_OFF]) {
    // default is 24 words
    case 0:
      G_ux_params.u.onboard.id = 24;
      break;
    case 12:
    case 18:
      G_ux_params.u.onboard.id = apdu_buffer[APDU_SECURE_DATA_OFF];
      break;
    default:
      return SWO_APD_DAT_2D;
  }

  dashboard_recover_display(BOLOS_UX_PROCESSING);

  offset = APDU_SECURE_DATA_OFF + 1;
  if (dashboard_ecdh(&G_dashboard.transient_ctx.recover.ephemeral_private,
                     CX_ECDH_X, G_dashboard.transient_ctx.host_public.W,
                     RECOVER_SECP256K1_PK_LEN,
                     G_dashboard.transient_ctx.recover.derived_key,
                     RECOVER_AES_SIV_KEY_LEN)) {
    return SWO_SEC_KEY_06;
  }
  if ((err = dashboard_decrypt_and_verify(
           G_dashboard.transient_ctx.recover.derived_key,
           apdu_buffer + offset + 1 + AES_SIV_TAG_LEN,
           apdu_buffer[offset] - AES_SIV_TAG_LEN,
           apdu_buffer + offset + 1 + apdu_buffer[offset],
           apdu_buffer + offset + 1))) {
    return err;
  }
  explicit_bzero(&G_dashboard.transient_ctx.recover.derived_key,
                 sizeof(G_dashboard.transient_ctx.recover.derived_key));
  if ((err = bolos_verify_commitments(
           G_dashboard.transient_ctx.recover.share_info.commitments,
           RECOVER_SHARING_THRESHOLD * sizeof(cx_vss_commitment_t),
           U4LE(apdu_buffer + offset + 1 + apdu_buffer[offset],
                CX_VSS_SECRET_SIZE),
           &verified))) {
    return err;
  }
  if (!verified) {
    return SWO_SEC_CHK_25;
  }
  current_share = &G_dashboard.transient_ctx.recover.share_info
                       .shares[G_dashboard.transient_ctx.recover.share_number];
  memcpy(current_share->share, apdu_buffer + offset + 1 + apdu_buffer[offset],
         CX_VSS_SECRET_SIZE);
  current_share->index =
      U4LE(apdu_buffer + offset + 1 + apdu_buffer[offset], CX_VSS_SECRET_SIZE);

  G_dashboard.transient_ctx.recover.state = STATE_RECOVER_CONFIRM_BACKUP;
  G_dashboard.transient_ctx.recover.share_number++;
  if (RECOVER_SHARING_THRESHOLD ==
      G_dashboard.transient_ctx.recover.share_number) {
    if ((err = bolos_restore_seed_from_shares(
             G_dashboard.transient_ctx.recover.share_info.shares))) {
      return err;
    }
    explicit_bzero(&G_dashboard.transient_ctx.recover,
                   sizeof(G_dashboard.transient_ctx.recover));
    G_ux_params.ux_id = BOLOS_UX_RECOVER_RESTORE;
    G_ux_params.len = sizeof(G_ux_params.u.recover.master_seed);
    if ((err = bolos_check_consent(&G_ux_params,
                                   &G_dashboard.reinit_display_on_error,
                                   G_dashboard.bolos_display, 0))) {
      return err;
    }
    G_dashboard.reinit_display = false;
  }

  memset(apdu_buffer, 0, IO_APDU_BUFFER_SIZE);
  *out_length = 0;
  return err;
}

bolos_err_t dashboard_apdu_secure_recover_delete_backup(uint8_t* apdu_buffer,
                                                        size_t in_length,
                                                        size_t* out_length) {
  os_perso_derive_node_with_seed_key_internal_params_t params;
  cx_ecfp_private_key_t private_key;
  uint32_t offset;
  bolos_err_t err;
  uint8_t nonce[RECOVER_NONCE_LEN];
  uint8_t shared_key[RECOVER_AES_SIV_KEY_LEN];

  if (!is_recover_scp_set() || ((G_dashboard.transient_ctx.recover.state &
                                 STATE_RECOVER_MUTUAL_AUTHENTICATED) !=
                                STATE_RECOVER_MUTUAL_AUTHENTICATED)) {
    return SWO_APD_STA_31;
  }

  if (in_length <= 2) {
    return SWO_APD_DAT_26;
  }

  if (dashboard_ecdh(&G_dashboard.transient_ctx.recover.ephemeral_private,
                     CX_ECDH_X, G_dashboard.transient_ctx.host_public.W,
                     RECOVER_SECP256K1_PK_LEN, shared_key,
                     RECOVER_AES_SIV_KEY_LEN)) {
    return SWO_SEC_KEY_07;
  }
  offset = APDU_SECURE_DATA_OFF;
  if ((err = dashboard_decrypt_and_verify(
           shared_key, apdu_buffer + offset + 1 + AES_SIV_TAG_LEN,
           apdu_buffer[offset] - AES_SIV_TAG_LEN, nonce,
           apdu_buffer + offset + 1))) {
    return err;
  }

  params.mode = HDW_NORMAL;
  params.from_app = BOLOS_FALSE;
  params.curve = CX_CURVE_SECP256K1;
  params.path = recover_bip32_path;
  params.pathLength = RECOVER_BIP32_PATH_LEN;
  params.privateKey = G_dashboard.transient_ctx.recover.derived_key;
  params.chain = NULL;
  params.seed_key = NULL;
  params.seed_key_length = 0;

  os_perso_derive_node_with_seed_key_internal(&params);
  memset(G_dashboard.transient_ctx.recover.chain, 0,
         sizeof(G_dashboard.transient_ctx.recover.chain));
  cx_ecdsa_internal_init_private_key(
      CX_CURVE_256K1, G_dashboard.transient_ctx.recover.derived_key,
      RECOVER_BIP32_DERIVED_KEY, &private_key);
  explicit_bzero(&G_dashboard.transient_ctx.recover.derived_key,
                 sizeof(G_dashboard.transient_ctx.recover.derived_key));

  cx_hash_sha256(nonce, sizeof(nonce), G_dashboard.transient_ctx.recover.chain,
                 CX_SHA256_SIZE);
  *out_length = ECDSA_SHA256_SIG_MAX_ASN1_LENGTH;
  if (cx_ecdsa_internal_sign(&private_key, CX_RND_TRNG, CX_SHA256,
                             G_dashboard.transient_ctx.recover.chain,
                             CX_SHA256_SIZE, apdu_buffer, out_length, NULL)) {
    return SWO_SEC_SIG_13;
  }
  if ((err = dashboard_encrypt_and_digest(
           shared_key, apdu_buffer, *out_length,
           apdu_buffer + *out_length + AES_SIV_TAG_LEN,
           apdu_buffer + *out_length))) {
    return err;
  }
  G_dashboard.reinit_display = true;
  memcpy(apdu_buffer, apdu_buffer + *out_length, AES_SIV_TAG_LEN);
  memcpy(apdu_buffer + AES_SIV_TAG_LEN,
         apdu_buffer + *out_length + AES_SIV_TAG_LEN, *out_length);
  *out_length += AES_SIV_TAG_LEN;
  return SWO_OK;
}