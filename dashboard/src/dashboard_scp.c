/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_ux.h"

#include "cx_ecdsa_internal.h"
#include "cx_ecfp_internal.h"
#include "cx_rng_internal.h"

#include "dashboard_common.h"
#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "lcx_aes_siv.h"
#include "lcx_ecdh.h"
#include "lcx_ecdsa.h"
#include "lcx_rng.h"
#include "os_apdu.h"
#include "os_helpers.h"
#include "os_io_seproxyhal.h"
#include "os_seed.h"
#include "os_types.h"
#include "os_utils.h"
#include "os_watchdog.h"

bolos_err_t dashboard_get_certificate_role(uint8_t certificate_id,
                                           uint8_t ephemeral,
                                           uint8_t* role) {
  if (certificate_id > CERTIFICATE_ROLES_LENGTH) {
    return SWO_APD_DAT_2C;
  }
  *role = ephemeral * certificate_roles[certificate_id].ephemeral_role +
          (1 - ephemeral) * certificate_roles[certificate_id].static_role;
  return SWO_OK;
}

bolos_err_t dashboard_apdu_validate_target_id(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length) {
  UNUSED(in_length);

  // The P1, P2 and length basic tests have been performed in the dispatcher.
  if (U4BE(apdu_buffer, APDU_OFF_DATA) != TARGET_ID) {
    return SWO_APD_DAT_14;
  }
  if ((apdu_buffer[APDU_OFF_P1] != SCP_DEFAULT) &&
      (apdu_buffer[APDU_OFF_P1] != SCP_RECOVER)) {
    return SWO_APD_HDR_0E;
  }
  G_dashboard.transient_ctx.scp_type = apdu_buffer[APDU_OFF_P1];

  *out_length = 0x00;
  G_dashboard.transient_ctx.state = STATE_TARGET_VALIDATED;
  return SWO_OK;
}

bolos_err_t dashboard_apdu_initialize_authentication(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length) {
  // BATCH'S ROOT TRUSTED PUBLIC KEY
  // reset current public key to root trusted public key (volatile)
  // return batch's master public key

  // The P1, P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);
  cx_err_t error;
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc;

  // check state
  if (G_dashboard.transient_ctx.state != STATE_TARGET_VALIDATED) {
    return SWO_APD_STA_02;
  }

  // keep the signer's nonce
  memmove(G_dashboard.transient_ctx.tmp.nonces.sn8, apdu_buffer + 5, 8);

  // generate device's nonce
  cx_rng_internal(G_dashboard.transient_ctx.tmp.nonces.dn8, 8);

  // if (os_security_delay(BOLOS_SECURITY_SCP_APDU_DELAY_S) != BOLOS_TRUE) {
  //   os_security_report_fault();
  // }

  // gen device's ephemeral keypair
  error = cx_ecfp_internal_generate_pair(
      CX_CURVE_256K1, &G_dashboard.transient_ctx.ephemeral_public,
      &G_dashboard.transient_ctx.secret.ephemeral_private, 0);
  if (error) {
    return error;
  }

  // default auth level is small
  G_dashboard.transient_ctx.auth_source_flags = 0;

  // ignore current authentication state, reset it
  G_dashboard.transient_ctx.state = STATE_INITIALIZE_AUTHENTICATION;
  G_dashboard.transient_ctx.host_chain_length = 0;
  G_dashboard.transient_ctx.device_chain_length = 0;

  G_dashboard.transient_ctx.list_state = LIST_NOT_STARTED;

  // ensure device is initialized
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
    return err;
  } else if (crc != BOLOS_TRUE) {
    return SWO_SEC_CRC_0B;
  }

  // PRIVACY: this could be optional if the signer's accept to try multiple
  // private key,
  //          but this would bother the user with many keys to accept => not
  //          very efficient
  // output master's serial, for the master to derivate the appropriate
  // intermediate batch master public key
  bolos_factory_get_signer_serial(apdu_buffer);

  // output the device's nonce for the signer to generate the correct sig
  memmove(apdu_buffer + 4, G_dashboard.transient_ctx.tmp.nonces.dn8, 8);
  *out_length = 8 + 4;
  return err;
}

bolos_err_t dashboard_apdu_validate_certificate(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length) {
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc_factory_1, crc_factory_2;
  cx_sha256_t hash_ctx;
  unsigned char hash_value[CX_SHA256_SIZE];
  unsigned int off_ESpub_len;
  unsigned int off_Ecert_sig_len;
  int factory_cmp;
  uint8_t p1;
  bolos_bool_t crc_custom_ca;

  // The P2 basic test has been performed in the dispatcher.

  // ensure device is initialized
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc_factory_1))) {
    return err;
  } else if (crc_factory_1 != BOLOS_TRUE) {
    return SWO_SEC_CRC_0C;
  }

  if (apdu_buffer[APDU_OFF_P2] >= CERTIFICATE_ROLE_LAST_ID) {
    return SWO_APD_HDR_0F;
  }

  // check state, after last verify, no more validate certificate is allowed
  if (G_dashboard.transient_ctx.state != STATE_INITIALIZE_AUTHENTICATION &&
      G_dashboard.transient_ctx.state != STATE_VALIDATE_CERTIFICATE) {
    return SWO_APD_STA_03;
  }

  off_ESpub_len = 5;
  off_Ecert_sig_len = off_ESpub_len + 1 + apdu_buffer[off_ESpub_len];

  // avoid overflow
  if (off_Ecert_sig_len >= in_length ||
      in_length != off_Ecert_sig_len + 1 + apdu_buffer[off_Ecert_sig_len] ||
      apdu_buffer[off_ESpub_len] !=
          sizeof(G_dashboard.transient_ctx.host_public.W)) {
    return SWO_APD_LEN_04;
  }

  p1 = apdu_buffer[APDU_OFF_P1];

  if ((err = dashboard_get_certificate_role(
           apdu_buffer[APDU_OFF_P2], p1 == INS_VALIDATE_CERTIFICATE_P1_LAST,
           &hash_value[0]))) {
    return err;
  }

  // check provided public key signature with current trusted public key
  // hash device public key to validate its signature by the master
  cx_sha256_init_no_throw(&hash_ctx);
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, hash_value, 1, NULL, 0);
  // last level include nonce signature (enable hierarchy of HSM)
  if (p1 == INS_VALIDATE_CERTIFICATE_P1_LAST) {
    cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0,
                     G_dashboard.transient_ctx.tmp.nonces.sn8, 8, NULL, 0);
    cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0,
                     G_dashboard.transient_ctx.tmp.nonces.dn8, 8, NULL, 0);
  }
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, CX_LAST,
                   apdu_buffer + off_ESpub_len + 1, apdu_buffer[off_ESpub_len],
                   hash_value, CX_SHA256_SIZE);

  // if chain == 0
  //   if signed by issuer
  //     if not trust_issuer yet then ask
  //     set issuer authentication level
  //     ok
  //   if signed by customca
  //     if not trust_customca yet then ask
  //     set customca authentication level
  //     ok
  //   if !P1_LAST then ask for user consent to validate the key
  //     retain the key for next time
  //     ok
  //   denied
  // elif chain > 0
  //   if signed by previous host public
  //     ok
  //   denied
  // store public for next certificate check round

  // root certificate presented or the ephemeral (in the case of issuer CA)
  if (G_dashboard.transient_ctx.host_chain_length == 0) {
    if ((err = bolos_check_crc_consistency(CRC_CUSTOM_CA, &crc_custom_ca))) {
      return err;
    }
    if ((err = bolos_check_crc_consistency(CRC_FACTORY_2, &crc_factory_2))) {
      return err;
    }
    // signed by issuer ?
    if (bolos_ecdsa_verify_with_signer_public(
            FACTORY_SETTINGS_SLOT_1, hash_value, CX_SHA256_SIZE,
            apdu_buffer + off_Ecert_sig_len + 1,
            apdu_buffer[off_Ecert_sig_len])) {
      // must be ephemeral if not the self signed certificate
      if (p1 != INS_VALIDATE_CERTIFICATE_P1_LAST) {
        if ((err = bolos_factory_compare_public_key(
                 FACTORY_SETTINGS_SLOT_1, apdu_buffer + off_ESpub_len + 1,
                 apdu_buffer[off_ESpub_len], &factory_cmp))) {
          return err;
        } else if (factory_cmp != 0) {
          return SWO_SEC_SIG_04;
        }
      }
      // only ask for issuer's key
      if (!bolos_is_issuer_trusted()) {
        // ask to consent to remote ledger administration
        G_ux_params.ux_id = BOLOS_UX_CONSENT_ISSUER_KEY;
        G_ux_params.len = 0;

        if ((err = bolos_check_consent(&G_ux_params,
                                       &G_dashboard.reinit_display_on_error,
                                       G_dashboard.bolos_display, 0))) {
          return err;
        }

        // issuer's key is trusted. keep it
        bolos_set_trust_issuer(1);
      }
      // set issuer authentication level
      G_dashboard.transient_ctx.auth_source_flags = APPLICATION_FLAG_ISSUER;

    accept_certificate:
      // set new current trusted public key, the last validated public key is
      // the one used for ECDH
      if ((err = cx_ecdsa_internal_init_public_key(
               CX_CURVE_256K1, apdu_buffer + off_ESpub_len + 1,
               apdu_buffer[off_ESpub_len],
               &G_dashboard.transient_ctx.host_public))) {
        return err;
      }
      // define next state depending on certificate just tested
      if (p1 == INS_VALIDATE_CERTIFICATE_P1_LAST) {
        G_dashboard.transient_ctx.state = STATE_VALIDATE_CERTIFICATE_LAST;
      } else {
        G_dashboard.transient_ctx.state = STATE_VALIDATE_CERTIFICATE;
      }
      G_dashboard.transient_ctx.host_chain_length++;
      *out_length = 0;
    }

    else if ((crc_factory_2 == BOLOS_TRUE)

             && bolos_ecdsa_verify_with_signer_public(
                    FACTORY_SETTINGS_SLOT_2, hash_value, CX_SHA256_SIZE,
                    apdu_buffer + off_Ecert_sig_len + 1,
                    apdu_buffer[off_Ecert_sig_len])) {
      // must be ephemeral if not the self signed certificate
      if (p1 != INS_VALIDATE_CERTIFICATE_P1_LAST) {
        if ((err = bolos_factory_compare_public_key(
                 FACTORY_SETTINGS_SLOT_2, apdu_buffer + off_ESpub_len + 1,
                 apdu_buffer[off_ESpub_len], &factory_cmp))) {
          return err;
        } else if (factory_cmp != 0) {
          return SWO_SEC_SIG_05;
        }
      }

      // only ask for issuer's key
      if (!bolos_is_issuer_trusted()) {
        // ask to consent to remote ledger administration
        G_ux_params.ux_id = BOLOS_UX_CONSENT_ISSUER_KEY;
        G_ux_params.len = 0;

        if ((err = bolos_check_consent(&G_ux_params,
                                       &G_dashboard.reinit_display_on_error,
                                       G_dashboard.bolos_display, 0))) {
          return err;
        }

        // issuer's key is trusted. keep it
        bolos_set_trust_issuer(1);
      }
      // set issuer authentication level
      G_dashboard.transient_ctx.auth_source_flags = APPLICATION_FLAG_ISSUER;
      goto accept_certificate;
    }

    else if ((crc_custom_ca != BOLOS_TRUE) &&
             bolos_ecdsa_verify_with_root_ca(
                 hash_value, CX_SHA256_SIZE,
                 apdu_buffer + off_Ecert_sig_len + 1,
                 apdu_buffer[off_Ecert_sig_len])) {
      // Give root CA the same level of trust as Issuer
      if (!bolos_is_issuer_trusted()) {
        // Ask to consent to remote ledger administration
        G_ux_params.ux_id = BOLOS_UX_CONSENT_ISSUER_KEY;
        G_ux_params.len = 0;

        if ((err = bolos_check_consent(&G_ux_params,
                                       &G_dashboard.reinit_display_on_error,
                                       G_dashboard.bolos_display, 0))) {
          return err;
        }

        bolos_set_trust_issuer(1);
      }
      G_dashboard.transient_ctx.auth_source_flags = APPLICATION_FLAG_ISSUER;
      goto accept_certificate;
    }

    // signed by custom CA ? (custom ca present ?)
    else if ((crc_custom_ca == BOLOS_TRUE) &&
             (0 == bolos_check_ca_type(G_dashboard.transient_ctx.scp_type)) &&
             bolos_ecdsa_verify_with_custom_ca(
                 hash_value, CX_SHA256_SIZE,
                 apdu_buffer + off_Ecert_sig_len + 1,
                 apdu_buffer[off_Ecert_sig_len])) {
      // must be ephemeral if not the self signed certificate
      if ((p1 != INS_VALIDATE_CERTIFICATE_P1_LAST) &&
          (SCP_RECOVER != G_dashboard.transient_ctx.scp_type)) {
        if (bolos_custom_ca_compare_public_key(apdu_buffer + off_ESpub_len + 1,
                                               apdu_buffer[off_ESpub_len]) !=
            0) {
          return SWO_SEC_SIG_06;
        }
      }

      // ask for custom ca's key
      if (!bolos_is_customca_trusted()) {
        // ask to consent to remote custom administration.
        if ((err = bolos_custom_ca_consent_for_use(
                 &G_dashboard.reinit_display_on_error,
                 G_dashboard.bolos_display))) {
          return err;
        }

        // CA's key is trusted. keep it
        bolos_set_trust_customca(1);
      }
      // set custom ca authentication level
      G_dashboard.transient_ctx.auth_source_flags = APPLICATION_FLAG_CUSTOM_CA;
      goto accept_certificate;
    }
    // foreign key ?
    else {
      // the first level cannot be ephemeral
      if (p1 == INS_VALIDATE_CERTIFICATE_P1_LAST) {
        return SWO_APD_DAT_04;
      }

      // in any case this is not an issuer key
      G_dashboard.transient_ctx.auth_source_flags = 0;

      // grab foreign key from apdu buffer
      if ((err = cx_ecdsa_internal_init_public_key(
               CX_CURVE_256K1, apdu_buffer + off_ESpub_len + 1,
               apdu_buffer[off_ESpub_len],
               &G_ux_params.u.foreign_key.host_pubkey))) {
        return err;
      }
      G_ux_params.len = sizeof(G_ux_params.u.foreign_key);

      // ensure certificate is autosigned (well formed), else reject it
      if (cx_ecdsa_internal_verify(&G_ux_params.u.foreign_key.host_pubkey,
                                   hash_value, CX_SHA256_SIZE,
                                   apdu_buffer + off_Ecert_sig_len + 1,
                                   apdu_buffer[off_Ecert_sig_len])) {
        // only ask for key validation if the key has changed from past consent
        // (key lasts until power cycle)
        if (G_dashboard.last_accepted_public.W_len !=
                apdu_buffer[off_ESpub_len] ||
            memcmp(G_dashboard.last_accepted_public.W,
                   apdu_buffer + off_ESpub_len + 1,
                   G_dashboard.last_accepted_public.W_len) != 0) {
          // enable the user to accept loading from a not allowed source, but
          // then, the loader will not accept to load the application.
          G_ux_params.ux_id = BOLOS_UX_CONSENT_FOREIGN_KEY;

          // If a previously accepted foreign public key FPukA has been stored
          // within the global variable and then the current FPukB one is
          // rejected by the user, the FPukA key remains valid within the global
          // variable and the consent won't be required if the FPukA is used
          // again.
          if ((err = bolos_check_consent(&G_ux_params,
                                         &G_dashboard.reinit_display_on_error,
                                         G_dashboard.bolos_display, 0))) {
            return err;
          }
        }

        // The certificate is correctly formatted and accepted by the user: we
        // keep its value in the dedicated global RAM variable.
        G_dashboard.last_accepted_public.W_len = apdu_buffer[off_ESpub_len];
        memcpy(G_dashboard.last_accepted_public.W,
               apdu_buffer + off_ESpub_len + 1,
               G_dashboard.last_accepted_public.W_len);

        // Not a trusted issuer anymore
        bolos_set_trust_issuer(0);
        G_dashboard.transient_ctx.auth_source_flags &=
            ~(APPLICATION_FLAG_ISSUER);
        goto accept_certificate;
      }
      return SWO_SEC_SIG_07;
    }
  }
  // not the root certificate
  else {
    // signed by previous host public
    if (!cx_ecdsa_internal_verify(&G_dashboard.transient_ctx.host_public,
                                  hash_value, CX_SHA256_SIZE,
                                  apdu_buffer + off_Ecert_sig_len + 1,
                                  apdu_buffer[off_Ecert_sig_len])) {
      return SWO_SEC_SIG_08;
    }
    goto accept_certificate;
  }
  return err;
}

bolos_err_t dashboard_apdu_get_certificate(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length) {
  cx_sha256_t hash_ctx;
  uint8_t factory_slot;
  uint8_t hash_value[CX_SHA256_SIZE];
  uint8_t signature[ECDSA_SHA256_SIG_MAX_ASN1_LENGTH];
  size_t eph_pub_key_sign_length;
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc;

  // The P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  // ensure device is initialized
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
    return err;
  } else if (crc != BOLOS_TRUE) {
    return SWO_SEC_CRC_0E;
  }

  // check state
  // ensure at least an ephemeral key level has been validated
  if ((G_dashboard.transient_ctx.state != STATE_VALIDATE_CERTIFICATE_LAST &&
       G_dashboard.transient_ctx.state != STATE_GET_CERTIFICATE) ||
      G_dashboard.transient_ctx.host_chain_length <
          1 /*2 for issuer's key, the top certificate can be skipped*/) {
    return SWO_APD_STA_04;
  }

  if (apdu_buffer[APDU_OFF_P1] != INS_GET_CERTIFICATE_P1_LAST) {
    // get the [INITIAL]/[NEXT] device certificate from its chain to check for
    // device ephemeral public key authenticity on the terminal side
    switch (G_dashboard.transient_ctx.device_chain_length) {
      case 0:
        if (SCP_RECOVER == G_dashboard.transient_ctx.scp_type) {
          // compute the shared secret to encrypt the certificate
          if (dashboard_ecdh(
                  &G_dashboard.transient_ctx.secret.ephemeral_private,
                  CX_ECDH_X, G_dashboard.transient_ctx.host_public.W,
                  RECOVER_SECP256K1_PK_LEN,
                  G_dashboard.transient_ctx.recover.chain,
                  RECOVER_AES_SIV_KEY_LEN)) {
            return SWO_SEC_KEY_02;
          }
          cx_ecfp_init_private_key_no_throw(
              G_dashboard.transient_ctx.secret.ephemeral_private.curve,
              G_dashboard.transient_ctx.secret.ephemeral_private.d,
              G_dashboard.transient_ctx.secret.ephemeral_private.d_len,
              &G_dashboard.transient_ctx.recover.ephemeral_private);
          os_allow_protected_flash();
          if ((err = bolos_factory_get_encrypted_certificate(
                   apdu_buffer, out_length,
                   &G_dashboard.transient_ctx.secret.scp.enc_key,
                   G_dashboard.transient_ctx.recover.chain,
                   RECOVER_AES_SIV_KEY_LEN, FACTORY_SETTINGS_SLOT_1))) {
            return err;
          }

          dashboard_scp_init(&G_dashboard.transient_ctx.secret.scp,
                             G_dashboard.transient_ctx.recover.chain);
        } else {
          os_allow_protected_flash();
          // P2 contains the chain to use
          switch (apdu_buffer[APDU_OFF_P2]) {
            case 0:
              if ((err = bolos_factory_get_certificate(
                       apdu_buffer, out_length, FACTORY_SETTINGS_SLOT_1))) {
                return err;
              }
              break;
            case 1:
              if ((err = bolos_check_crc_consistency(CRC_FACTORY_2, &crc))) {
                return err;
              } else if (crc != BOLOS_TRUE) {
                return SWO_SEC_CRC_0F;
              }
              if ((err = bolos_factory_get_certificate(
                       apdu_buffer, out_length, FACTORY_SETTINGS_SLOT_2))) {
                return err;
              }
              break;
            default:
              return SWO_APD_HDR_02;
          }
        }
        os_deny_protected_flash();

        G_dashboard.transient_ctx.state = STATE_GET_CERTIFICATE;
        G_dashboard.transient_ctx.device_chain_length++;
        break;
      default:
        // no output data, only a single chain level until the ephemeral
        // certificate is implemented now.
        break;
    }
  } else {
    // can only be done once
    if (G_dashboard.transient_ctx.state != STATE_GET_CERTIFICATE_LAST) {
      // host cannot verify if it hasn't retrieved the whole chain !
      if (G_dashboard.transient_ctx.state != STATE_GET_CERTIFICATE) {
        return SWO_APD_STA_05;
      }

      // sign the ephemeral device public key
      {
        cx_sha256_init_no_throw(&hash_ctx);
        hash_value[0] = CERT_ROLE_DEVICE_EPHEMERAL;
        cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, hash_value, 1, NULL, 0);
        cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0,
                         G_dashboard.transient_ctx.tmp.nonces.dn8, 8, NULL, 0);
        cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0,
                         G_dashboard.transient_ctx.tmp.nonces.sn8, 8, NULL, 0);
        cx_hash_no_throw((cx_hash_t*)&hash_ctx, CX_LAST,
                         G_dashboard.transient_ctx.ephemeral_public.W,
                         G_dashboard.transient_ctx.ephemeral_public.W_len,
                         hash_value, CX_SHA256_SIZE);
      }

      // When receiving this command during onboarding state, the
      // watchdog timer value is BOLOS_SECURITY_ONBOARD_DELAY_S.
      // Re arm the watchdog timer to prevent a long delay in this function
      if (os_perso_isonboarded() != BOLOS_TRUE) {
        if ((err = os_watchdog_arm(5, OS_WATCHDOG_NOACTION))) {
          return err;
        }
      }
      // wait a bit
      if (os_security_ensure_elapsed(BOLOS_SECURITY_ATTESTATION_DELAY_S)) {
        os_security_report_fault();
      }

      eph_pub_key_sign_length = ECDSA_SHA256_SIG_MAX_ASN1_LENGTH;
      switch (apdu_buffer[APDU_OFF_P2]) {
        case 0:
          factory_slot = FACTORY_SETTINGS_SLOT_1;
          break;
        case 1:
          if ((err = bolos_check_crc_consistency(CRC_FACTORY_2, &crc))) {
            return err;
          } else if (crc != BOLOS_TRUE) {
            return SWO_SEC_CRC_10;
          }
          factory_slot = FACTORY_SETTINGS_SLOT_2;
          break;
        default:
          return SWO_APD_HDR_03;
      }

      if (SCP_RECOVER == G_dashboard.transient_ctx.scp_type) {
        if ((err = bolos_prepare_signature_with_factory(
                 factory_slot, CX_LAST | CX_RND_TRNG, hash_value,
                 CX_SHA256_SIZE, G_dashboard.transient_ctx.recover.chain,
                 RECOVER_AES_SIV_KEY_LEN, &eph_pub_key_sign_length,
                 apdu_buffer + 2 +
                     G_dashboard.transient_ctx.ephemeral_public.W_len + 1 +
                     AES_SIV_TAG_LEN,
                 apdu_buffer + 2 +
                     G_dashboard.transient_ctx.ephemeral_public.W_len + 1))) {
          return err;
        }
        explicit_bzero(&G_dashboard.transient_ctx.recover.chain,
                       sizeof(G_dashboard.transient_ctx.recover.chain));
        apdu_buffer[2 + G_dashboard.transient_ctx.ephemeral_public.W_len] =
            AES_SIV_TAG_LEN;
        *out_length = AES_SIV_TAG_LEN;
      } else {
        if ((err = bolos_ecdsa_sign_with_factory(
                 factory_slot, CX_LAST | CX_RND_TRNG, hash_value,
                 CX_SHA256_SIZE, signature, &eph_pub_key_sign_length))) {
          return err;
        }
        memcpy(apdu_buffer + 2 +
                   G_dashboard.transient_ctx.ephemeral_public.W_len + 1,
               signature, eph_pub_key_sign_length);
        apdu_buffer[2 + G_dashboard.transient_ctx.ephemeral_public.W_len] = 0;
        *out_length = 0;
      }

      apdu_buffer[0] = 0;  // certificate header
      apdu_buffer[1] = G_dashboard.transient_ctx.ephemeral_public.W_len;
      memmove(apdu_buffer + 2, G_dashboard.transient_ctx.ephemeral_public.W,
              G_dashboard.transient_ctx.ephemeral_public.W_len);
      apdu_buffer[2 + G_dashboard.transient_ctx.ephemeral_public.W_len] +=
          eph_pub_key_sign_length;
      *out_length += 2 + G_dashboard.transient_ctx.ephemeral_public.W_len + 1 +
                     eph_pub_key_sign_length;

      // ok to proceed with mutual authentication
      G_dashboard.transient_ctx.state = STATE_GET_CERTIFICATE_LAST;
      G_dashboard.transient_ctx.device_chain_length++;
    }
  }
  return err;
}

#define ECDH_SECRET_POINT_SIZE 65

bolos_err_t dashboard_apdu_mutual_authenticate(uint8_t* apdu_buffer,
                                               size_t in_length,
                                               size_t* out_length) {
  bolos_err_t err = SWO_OK;
  cx_err_t cx_err;
  bolos_bool_t crc;
  cx_sha256_t hash_ctx;
  unsigned char ecdh_secret_point[ECDH_SECRET_POINT_SIZE];
  unsigned char ecdh_secret[CX_SHA256_SIZE];
  unsigned char prefix;

  // ensure device is initialized
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
    return err;
  } else if (crc != BOLOS_TRUE) {
    return SWO_SEC_CRC_11;
  }

  // The P1, P2 and length basic tests have been performed in the dispatcher.
  UNUSED(apdu_buffer);
  UNUSED(in_length);

  // ecdh with current trusted public key and the device ephemeral public key
  // hash the generated secret, and use it as the aes key for secure transport
  if (G_dashboard.transient_ctx.state != STATE_GET_CERTIFICATE_LAST ||
      G_dashboard.transient_ctx.device_chain_length < 2) {
    return SWO_APD_STA_06;
  }

  if (SCP_RECOVER == G_dashboard.transient_ctx.scp_type) {
    *out_length = 0;
    G_dashboard.transient_ctx.state = STATE_MUTUAL_AUTHENTICATED;
    G_dashboard.transient_ctx.recover.state = STATE_RECOVER_CONFIRM_USER;
    G_dashboard.transient_ctx.host_chain_length = 0;
    return err;
  }

  // ============== ECDH for ENC and MAC
  cx_err = cx_ecdh_no_throw(
      &G_dashboard.transient_ctx.secret.ephemeral_private, CX_ECDH_POINT,
      // last level trusted signer public key
      G_dashboard.transient_ctx.host_public.W, ECDH_SECRET_POINT_SIZE,
      ecdh_secret_point, ECDH_SECRET_POINT_SIZE);
  if (cx_err != CX_OK) {
    return SWO_SEC_SIG_09;
  } else {
    size_t size;

    cx_err = cx_ecdomain_parameters_length(
        G_dashboard.transient_ctx.secret.ephemeral_private.curve, &size);
    if (cx_err != CX_OK) {
      return SWO_SEC_SIG_09;
    }

    if (1 + 2 * size != ECDH_SECRET_POINT_SIZE) {
      return SWO_SEC_SIG_09;
    }
  }

  // Prepare the secret to match libsecp256k1 ECDH derivation
  cx_sha256_init_no_throw(&hash_ctx);
  prefix = ((ecdh_secret_point[ECDH_SECRET_POINT_SIZE - 1] & 1) ? 0x03 : 0x02);
  if (cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, &prefix, 1, NULL, 0) !=
      CX_OK) {
    return SWO_SEC_SCP_01;
  }
  if (cx_hash_no_throw((cx_hash_t*)&hash_ctx, CX_LAST, ecdh_secret_point + 1,
                       CX_SHA256_SIZE, ecdh_secret, CX_SHA256_SIZE) != CX_OK) {
    return SWO_SEC_SCP_02;
  }

  // ecdh_secret_point is not used anymore and can be cleaned
  explicit_bzero(ecdh_secret_point, ECDH_SECRET_POINT_SIZE);

  // ============== SESSION START
  // initialize the SCP session cryptographic material
  if (dashboard_scp_init(&G_dashboard.transient_ctx.secret.scp, ecdh_secret)) {
    // implies a manual unplug/replug, enjoy the delay :)
    io_seproxyhal_se_reset();
    for (;;)
      ;
  }
  explicit_bzero(ecdh_secret, CX_SHA256_SIZE);

  // No output.
  *out_length = 0;

  // mark SCP as open and usable
  G_dashboard.transient_ctx.state = STATE_MUTUAL_AUTHENTICATED;
  return err;
}