/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"

#include "cx_ecfp_internal.h"
#include "os_internal.h"

#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "lcx_ecdsa.h"
#include "os_apdu.h"
#include "os_helpers.h"
#include "os_id.h"
#include "os_io.h"
#include "os_io_seproxyhal.h"
#include "os_nvm.h"
#include "os_types.h"
#include "os_watchdog.h"

#include "bolos_ux_factory.h"

#include "hw_display.h"

bolos_bool_t dashboard_has_serial_number(void) {
  unsigned char byte = 0;
  unsigned int len = os_seph_serial(&byte, 1);

  if ((len == 0) || (byte == '%')) {
    return BOLOS_FALSE;
  } else {
    return BOLOS_TRUE;
  }
}

/*
 * APDU command "Get Device Public Key" of INS code 0x40.
 * This command aims at retrieving the device’s internally generated public key.
 * The lifetime of this public key is the device lifetime, and it is not meant
 * to be changed.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Device public key length (1)
 *                  Device public key (device_pub_key_len)
 *                  Serial number length (1)
 *                  Serial number (serial_number_len)
 *                  Initial public key certificate length (1)
 *                  Initial public key certificate (ini_pub_key_cert_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_SEC_CRC_01/02 if the factory settings CRC is incorrect
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_get_device_public_key(uint8_t* apdu_buffer,
                                                 size_t in_length,
                                                 size_t* out_length) {
  unsigned int tmp;
  cx_sha256_t hash_ctx;
  size_t sig_len;
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc;

  UNUSED(in_length);

  // The P1, P2 and length basic tests have been performed in the dispatcher.

  // ensure device has not already an initialized context
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
    return err;
  } else if (crc == BOLOS_TRUE) {
    return SWO_SEC_CRC_01;
  }
  safe_desynch_internal();
  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
    return err;
  } else if (crc == BOLOS_TRUE) {
    return SWO_SEC_CRC_02;
  }

  // gen device's keypair
  if ((err = cx_ecfp_internal_generate_pair(
           CX_CURVE_256K1, &G_dashboard.transient_ctx.ephemeral_public,
           &G_dashboard.transient_ctx.secret.ephemeral_private, 0))) {
    return err;
  }

  // output public key
  apdu_buffer[0] = G_dashboard.transient_ctx.ephemeral_public.W_len;
  memmove(apdu_buffer + 1, G_dashboard.transient_ctx.ephemeral_public.W,
          G_dashboard.transient_ctx.ephemeral_public.W_len);
  // output device's serial
  apdu_buffer[1 + G_dashboard.transient_ctx.ephemeral_public.W_len] = os_get_sn(
      apdu_buffer + 1 + G_dashboard.transient_ctx.ephemeral_public.W_len + 1);

  tmp = 1 + G_dashboard.transient_ctx.ephemeral_public.W_len + 1 +
        apdu_buffer[1 + G_dashboard.transient_ctx.ephemeral_public.W_len];

  // compute and output the pub key certificate
  cx_sha256_init_no_throw(&hash_ctx);
  apdu_buffer[tmp] = CERT_ROLE_DEVICE;
  apdu_buffer[tmp + 1] = (unsigned char)(TARGET_ID >> 24);
  apdu_buffer[tmp + 2] = (unsigned char)(TARGET_ID >> 16);
  apdu_buffer[tmp + 3] = (unsigned char)(TARGET_ID >> 8);
  apdu_buffer[tmp + 4] = (unsigned char)(TARGET_ID);
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, apdu_buffer + tmp, 5, NULL, 0);
  cx_hash_no_throw((cx_hash_t*)&hash_ctx, CX_LAST,
                   G_dashboard.transient_ctx.ephemeral_public.W,
                   G_dashboard.transient_ctx.ephemeral_public.W_len,
                   apdu_buffer + tmp, CX_SHA256_SIZE);

  // sign the soon to be device public key using the ROM privatekey stored in
  // overlay in nvram over device_private.
  sig_len = ECDSA_SHA256_SIG_MAX_ASN1_LENGTH;
  if ((err = bolos_ecdsa_sign_with_factory(
           FACTORY_SETTINGS_SLOT_1, CX_LAST | CX_RND_TRNG, apdu_buffer + tmp,
           CX_SHA256_SIZE, apdu_buffer + tmp + 1, &sig_len))) {
    return err;
  }
  apdu_buffer[tmp] = sig_len;
  *out_length = tmp + 1 + apdu_buffer[tmp];
  G_dashboard.transient_ctx.state = STATE_SET_CERTIFICATE;
  return err;
}

/*
 * APDU command "Set Certificate" of INS code 0x41.
 * This command pushes the device’s certificate. Afterward the device is
 * considered in production mode and is able to establish secure channels
 * remotely. The Initial Private Key is destroyed when the 'Fab Set Certificate'
 * command is executed successfully.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Input format: Signer serial number (4)
 *                 Signer public key length (1)
 *                 Signer public key (signer_pub_key_len)
 *                 Device certificate header length (1)
 *                 Device certificate header (dev_cert_head_len)
 *                 Device certificate signature length (1)
 *                 Device certificate signature (dev_cert_sig_len)
 *                 Device MCU serial length (1)
 *                 Device MCU serial (dev_mcu_serial_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_LEN_01 if the payload length is incorrect
 *           SWO_APD_STA_01 if the context state is incorrect
 *           SWO_APD_HDR_01 if P2 value is unknown
 *           SWO_SEC_CRC_23 if the CRC type is incorrect
 *           SWO_SEC_CRC_06 if the CRC of the factory settings is incorrect
 *           SWO_SEC_CRC_07 if the CRC of the second factory settings is
 * incorrect SWO_SEC_CRC_08 if the CRC of the factory settings is correct when
 * setting up the certificate on the second
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_set_certificate(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length) {
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc;
  unsigned int off_cert_header_len = 5 + 4 + 1 + apdu_buffer[5 + 4];
  unsigned int off_cert_sig_len =
      off_cert_header_len + 1 + apdu_buffer[off_cert_header_len];

  unsigned int off_mcu_serial_len =
      off_cert_sig_len + 1 + apdu_buffer[off_cert_sig_len];

  // check command style
  // <HEADER(5)> <BATCH_SERIAL(4)> <LEN_BATCH_PUBLIC(1)>
  // <BATCH_PUBLIC(LEN_BATCH_PUBLIC)> <LEN_CERT_HEADER(1)>
  // <CERT_HEADER(LEN_CERT_HEADER)> <LEN_CERT_SIG(1)> <CERT_SIG(LEN_CERT_SIG)>

  if (off_cert_header_len >= in_length || off_cert_sig_len >= in_length ||
      off_mcu_serial_len >= in_length ||
      in_length != off_mcu_serial_len + 1 + apdu_buffer[off_mcu_serial_len]) {
    return SWO_APD_LEN_01;
  }

  if (G_dashboard.transient_ctx.state != STATE_SET_CERTIFICATE) {
    return SWO_APD_STA_01;
  }

  // depending on P2, select the target factory setting zone to set
  switch (apdu_buffer[APDU_OFF_P2]) {
    default:
      return SWO_APD_HDR_01;

    case 0:
      if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
        return err;
      } else if (crc == BOLOS_TRUE) {
        return SWO_SEC_CRC_06;
      }
      // if the second cert is not set yet, then deny setting the first cert
      if ((err = bolos_check_crc_consistency(CRC_FACTORY_2, &crc))) {
        return err;
      } else if (crc != BOLOS_TRUE) {
        return SWO_SEC_CRC_07;
      }
      if ((err = bolos_factory_set_certificate(
               apdu_buffer, FACTORY_SETTINGS_SLOT_1,
               &G_dashboard.transient_ctx.ephemeral_public,
               &G_dashboard.transient_ctx.secret.ephemeral_private))) {
        return err;
      }
      // ask for return after tx
      G_dashboard.transient_ctx.state = STATE_SE_RESET;
      G_dashboard.flags |= IO_RETURN_AFTER_TX;
      // ask the MCU to set its protection, after prod is completed.
      G_dashboard.transient_ctx.state = STATE_MCU_RDP2_THEN_RESET;
      break;
    case 1:
      // can't set second cert (when wiped) if the perso is already set.
      // the second authentication cert must be set BEFORE the legacy one
      if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &crc))) {
        return err;
      } else if (crc == BOLOS_TRUE) {
        return SWO_SEC_CRC_08;
      }
      if ((err = bolos_factory_set_certificate(
               apdu_buffer, FACTORY_SETTINGS_SLOT_2,
               &G_dashboard.transient_ctx.ephemeral_public,
               &G_dashboard.transient_ctx.secret.ephemeral_private))) {
        return err;
      }
      break;
  }

  *out_length = 0;

  // robustness only
  bolos_erase_all(NO_USER_PREF_PRESERVED);
  return err;
}

/*
 * APDU command "Factory Test" of INS code 0x44.
 * This command aims at testing various features of a device in factory mode.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_STA_2C if the target has a serial number and is not in
 * recovery mode SWO_APD_HDR_02 if the target has a serial number and is in
 * recovery mode SWO_APD_HDR_13 if P2/LC is invalid when testing Fatstacks
 * screen SWO_APD_HDR_01 if P1 in invalid
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_factory_test(uint8_t* apdu_buffer,
                                        size_t in_length,
                                        size_t* out_length) {
  unsigned int offset = 0;
  bolos_err_t err = SWO_OK;

  UNUSED(err);
  UNUSED(in_length);

  if (dashboard_has_serial_number() == BOLOS_TRUE) {
    if (bolos_is_recovery() != BOLOS_TRUE) {
      return SWO_APD_STA_2C;
    } else {
      { return SWO_APD_HDR_02; }
    }
  }

  G_ux_params.ux_id = BOLOS_UX_BOOT_FACTORY_MODE;
  G_ux_params.len = sizeof(G_ux_params.u.factory_mode);

  switch (apdu_buffer[APDU_OFF_P1]) {
    case P1_FACTORY_TEST_START_STOP:
      G_ux_params.u.factory_mode.type = FACTORY_TEST_START_STOP;
      G_ux_params.u.factory_mode.param = apdu_buffer[APDU_OFF_P2];
      os_ux_blocking(&G_ux_params);
      break;

    case P1_FACTORY_TEST_SCREEN:
      if ((apdu_buffer[APDU_OFF_P2] == 0x00) ||
          (apdu_buffer[APDU_OFF_P2] == 0x01)) {
        G_ux_params.u.factory_mode.type = FACTORY_TEST_SET_SCREEN;
        G_ux_params.u.factory_mode.param = apdu_buffer[APDU_OFF_P2];
        os_ux_blocking(&G_ux_params);
      } else if ((apdu_buffer[APDU_OFF_P2] == 0x10) &&
                 (apdu_buffer[APDU_OFF_LC] == 0x01)) {
        G_ux_params.u.factory_mode.type = FACTORY_TEST_SET_BRIGHTNESS;
        G_ux_params.u.factory_mode.param = apdu_buffer[APDU_OFF_DATA];
        os_ux_blocking(&G_ux_params);
      } else if (apdu_buffer[APDU_OFF_P2] == 0x20) {
        uint16_t x = U2BE(&apdu_buffer[APDU_OFF_DATA], 0);
        uint16_t y = U2BE(&apdu_buffer[APDU_OFF_DATA], 2);
        uint16_t width = U2BE(&apdu_buffer[APDU_OFF_DATA], 4);
        uint16_t height = U2BE(&apdu_buffer[APDU_OFF_DATA], 6);
        HW_DISPLAY_bitmap(x, y, width, height, width * height,
                          &apdu_buffer[APDU_OFF_DATA + 8], 0);
        HW_DISPLAY_update();
      }
      break;

    case P1_FACTORY_TEST_BUTTON:
      G_ux_params.u.factory_mode.type = FACTORY_TEST_GET_BUTTON_STATE;
      G_ux_params.u.factory_mode.param = 0;
      os_ux_blocking(&G_ux_params);
      os_ux_result(&G_ux_params);
      if (G_ux_params.u.factory_mode.datas[0] == 0xDA) {
        memcpy(apdu_buffer, &G_ux_params.u.factory_mode.datas[2],
               MIN(G_ux_params.u.factory_mode.datas[1],
                   sizeof(G_ux_params.u.factory_mode.datas)));
        offset = MIN(G_ux_params.u.factory_mode.datas[1],
                     sizeof(G_ux_params.u.factory_mode.datas));
      }
      break;

    case P1_FACTORY_TEST_BATTERY:
      G_ux_params.u.factory_mode.type = FACTORY_TEST_GET_BATTERY_INFO;
      G_ux_params.u.factory_mode.param = apdu_buffer[APDU_OFF_P2];
      os_ux_blocking(&G_ux_params);
      os_ux_result(&G_ux_params);
      if (G_ux_params.u.factory_mode.datas[0] == 0xDA) {
        memcpy(apdu_buffer, &G_ux_params.u.factory_mode.datas[2],
               MIN(G_ux_params.u.factory_mode.datas[1],
                   sizeof(G_ux_params.u.factory_mode.datas)));
        offset = MIN(G_ux_params.u.factory_mode.datas[1],
                     sizeof(G_ux_params.u.factory_mode.datas));
      }
      break;

    case P1_FACTORY_TEST_GET_SE_SN:
      offset = os_serial(apdu_buffer, 7);
      break;

    case P1_FACTORY_TEST_RESET:
      G_dashboard.transient_ctx.state = STATE_SE_RESET;
      G_dashboard.flags |= IO_RETURN_AFTER_TX;
      break;

    case P1_FACTORY_TEST_SERIAL_NUMBER:
      if (apdu_buffer[APDU_OFF_P2] == 0x00) {
        if ((err = bolos_factory_set_serial_number(&apdu_buffer[APDU_OFF_DATA],
                                                   apdu_buffer[APDU_OFF_LC]))) {
          return err;
        }
        if (dashboard_has_serial_number() == BOLOS_TRUE) {
          G_dashboard.transient_ctx.state = STATE_MCU_RDP2_THEN_RESET;
        } else
        // ask for return after tx
        {
          G_dashboard.transient_ctx.state = STATE_SE_RESET;
        }
        G_dashboard.flags |= IO_RETURN_AFTER_TX;
      }
      offset = os_seph_serial(apdu_buffer, 32);
      break;

    case P1_FACTORY_TEST_BACKUP_SERIAL_NUMBER:
      if (apdu_buffer[APDU_OFF_P2] == 0x00) {
        offset = apdu_buffer[APDU_OFF_LC] + 1;
        apdu_buffer[APDU_OFF_DATA - 1] = '%';
        if ((err = bolos_factory_set_serial_number(
                 &apdu_buffer[APDU_OFF_DATA - 1], offset))) {
          return err;
        }
      }
      offset = os_seph_serial(apdu_buffer, 32);
      offset--;
      memmove(apdu_buffer, &apdu_buffer[1], offset);
      break;

    case P1_FACTORY_TEST_MCU_SERIAL_NUMBER: {
      uint32_t uid_offset = (0x1FFF7590 - 0x08000000);
      uint8_t uid_size = 12;
      G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_UNSEC_CHUNK_READ_EXT;
      G_io_seproxyhal_spi_buffer[1] = 0;
      G_io_seproxyhal_spi_buffer[2] = 7;
      G_io_seproxyhal_spi_buffer[3] = 0;
      G_io_seproxyhal_spi_buffer[4] = uid_size;
      G_io_seproxyhal_spi_buffer[5] = 0x2;  // FROM_OFFSET
      G_io_seproxyhal_spi_buffer[6] = (uint8_t)(uid_offset >> 24);
      G_io_seproxyhal_spi_buffer[7] = (uint8_t)(uid_offset >> 16);
      G_io_seproxyhal_spi_buffer[8] = (uint8_t)(uid_offset >> 8);
      G_io_seproxyhal_spi_buffer[9] = (uint8_t)(uid_offset >> 0);
      io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 10);
      io_seproxyhal_general_status();
      io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                             sizeof(G_io_seproxyhal_spi_buffer), 0);
      memcpy(apdu_buffer, &G_io_seproxyhal_spi_buffer[3], uid_size);
      offset = uid_size;
      break;
    }

    default:
      return SWO_APD_HDR_01;
      break;
  }

  // Reset ux_id / len that has been set at the beginning of the function, and
  // not used by an os_ux_blocking() function call.
  G_ux_params.ux_id = BOLOS_UX_LAST_ID;
  G_ux_params.len = 0;

  *out_length = offset;
  return err;
}