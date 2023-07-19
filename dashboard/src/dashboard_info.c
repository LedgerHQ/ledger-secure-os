/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_ux.h"

#include "cx_aes_internal.h"

#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "bolos_ux_factory.h"
#include "os_apdu.h"
#include "os_helpers.h"
#include "os_id.h"
#include "os_io_seproxyhal.h"
#include "os_math.h"
#include "os_memory.h"
#include "os_pin.h"
#include "os_registry.h"
#include "os_seed.h"
#include "os_settings.h"
#include "os_utils.h"

#include "ledger_ble.h"

#include "os_io_seproxyhal.h"

#include "bolos_ux_common.h"

#define VERSION "dummy"

/*
 * APDU command "Secure Get Memory Information" of INS code 0x11.
 * This command aims at retrieving memory-related information from the device.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Firmware OS size in bytes (4)
 *                  Application memory already used in bytes (4)
 *                  Application memory available in bytes (4)
 *                  Number of applications installed (4)
 *                  Max number of applications installable (4)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_secure_get_memory_information(uint8_t* apdu_buffer,
                                                         size_t in_length,
                                                         size_t* out_length) {
  meminfo_t meminfo;

  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  // This call retrieves the NVM-related information.
  os_get_memory_info(&meminfo);

  U4BE_ENCODE(apdu_buffer, 0, meminfo.systemSize);
  U4BE_ENCODE(apdu_buffer, 4, meminfo.appMemory);
  U4BE_ENCODE(apdu_buffer, 8, meminfo.free_nvram_size);
  U4BE_ENCODE(apdu_buffer, 12, meminfo.slots);
  U4BE_ENCODE(apdu_buffer, 16, APPLICATION_MAXCOUNT);
  *out_length = 20;
  return SWO_OK;
}

/*
 * APDU command "Set Device Name" of INS code 0xD4.
 * This command aims at setting the device name.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Input format: Device name (VAR)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_STA_10 if target is not onboarded
 *           SWO_SEC_PIN_01/02 if global PIN has not been validated
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_set_device_name(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length) {
  bolos_err_t err = SWO_OK;
  // The P2 basic test has been performed in the dispatcher.
  UNUSED(in_length);

  // ensure personalization is initialized
  if (os_perso_isonboarded() != BOLOS_TRUE) {
    return SWO_APD_STA_10;
  }
  G_ux_params.ux_id = BOLOS_UX_CONSENT_SET_DEVICE_NAME;
  G_ux_params.len = 0;

  unsigned length = MIN((DEVICE_NAME_MAX_LEN - 1), apdu_buffer[APDU_OFF_LC]);

  // transmit name to UX to update screen if consent OK
  memcpy(G_ux_params.u.device_name, apdu_buffer + APDU_OFF_DATA, length);
  G_ux_params.u.device_name[length] = '\0';
  if ((err = bolos_check_consent(&G_ux_params,
                                 &G_dashboard.reinit_display_on_error,
                                 G_dashboard.bolos_display, 0))) {
    return err;
  }

  // If length > DEVICE_MAX_LEN: error will be throw by os_setting_set
  os_setting_set(OS_SETTING_DEVICENAME, apdu_buffer + APDU_OFF_DATA,
                 apdu_buffer[APDU_OFF_LC]);
  G_io_app.name_changed = 1;
  // Restart advertising
  io_seph_ble_enable(0);

  *out_length = 0;
  return err;
}

/*
 * APDU command "Get Device Name" of INS code 0xD2.
 * This command aims at retrieving the device name.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Device name (VAR)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Errors: SWO_APD_STA_11 if target is not onboarded
 *           SWO_SEC_PIN_01/02 if global PIN has not been validated
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_get_device_name(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length) {
  bolos_err_t err = SWO_OK;
  uint8_t issuer_or_custom_ca_trusted;

  // The P1, P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  // Ensure personalization is initialized.
  if (os_perso_isonboarded() != BOLOS_TRUE) {
    return SWO_APD_STA_11;
  }

  issuer_or_custom_ca_trusted =
      bolos_is_issuer_trusted() || bolos_is_customca_trusted();

  // Do not prompt if this session already trusts the issuer.
  if (!issuer_or_custom_ca_trusted) {
    G_ux_params.ux_id = BOLOS_UX_CONSENT_GET_DEVICE_NAME;
    G_ux_params.len = 0;
    if ((err = bolos_check_consent(&G_ux_params,
                                   &G_dashboard.reinit_display_on_error,
                                   G_dashboard.bolos_display, 0))) {
      return err;
    }
  }
  *out_length = os_setting_get(OS_SETTING_DEVICENAME, apdu_buffer, 255);
  return err;
}

static inline void reverse_array(uint8_t* array, size_t size) {
  for (size_t i = 0; i < size / 2; i++) {
    uint8_t tmp = array[i];
    array[i] = array[size - i - 1];
    array[size - i - 1] = tmp;
  }
}
bolos_err_t dashboard_apdu_get_device_mac(uint8_t* apdu_buffer,
                                          size_t in_length,
                                          size_t* out_length) {
  // The P1, P2 and length basic tests have been performed in the dispatcher.
  UNUSED(in_length);

  LEDGER_BLE_get_mac_address(apdu_buffer);
  reverse_array(apdu_buffer, 6);
  *out_length = 6;
  return SWO_OK;
}

static bolos_err_t dashboard_get_version_internal(uint8_t* apdu_buffer,
                                                  size_t* out_length) {
  bolos_err_t err = SWO_OK;
  bolos_bool_t hsm_initialized;
  unsigned int onboarded, pin_validated, factory_filled, offset;
  unsigned int endorsed_first, endorsed_second;

  uint8_t hardware_version = 0x00;
  uint32_t seproxyhal_features;

  // inform about the target ID to allow for special state
  offset = sizeof(U_bolos_target_id);
  memmove(apdu_buffer, U_bolos_target_id, sizeof(U_bolos_target_id));

  // copy the os version
  apdu_buffer[offset++] = strlen(VERSION);
  memmove(apdu_buffer + offset, VERSION, strlen(VERSION));
  offset += strlen(VERSION);

  if ((err = bolos_check_crc_consistency(CRC_FACTORY_1, &hsm_initialized))) {
    return err;
  }

  onboarded = os_perso_isonboarded();
  pin_validated = os_global_pin_is_validated();
  factory_filled = dashboard_has_serial_number();

  endorsed_first =
      (bolos_endorsement_is_slot_active(ENDORSEMENT_SLOT_1) == BOLOS_TRUE);
  endorsed_second =
      (bolos_endorsement_is_slot_active(ENDORSEMENT_SLOT_2) == BOLOS_TRUE);

  // inform the user app the state BOLOS is in
  apdu_buffer[offset++] = 4;
  apdu_buffer[offset++] =
      ((bolos_is_recovery() == BOLOS_TRUE) ? OS_FLAG_RECOVERY : 0) |
      ((bolos_is_signed_mcu_code() == BOLOS_TRUE) ? OS_FLAG_SIGNED_MCU_CODE
                                                  : 0) |
      ((onboarded == BOLOS_TRUE) ? OS_FLAG_ONBOARDED : 0) |
      (bolos_is_issuer_trusted() ? OS_FLAG_ISSUER_TRUSTED : 0) |
      (bolos_is_customca_trusted() ? OS_FLAG_CUSTOMCA_TRUSTED : 0) |
      (hsm_initialized == BOLOS_TRUE ? OS_FLAG_HSM_INITIALIZED : 0) |
      (factory_filled == BOLOS_TRUE ? OS_FLAG_FACTORY_FILLED : 0) |
      (pin_validated == BOLOS_TRUE ? OS_FLAG_PIN_VALIDATED : 0);
  apdu_buffer[offset++] =
      (endorsed_first ? 0x01 : 0x00) | (endorsed_second ? 0x02 : 0x00);

  apdu_buffer[offset++] = ((bolos_get_onboarding_total() & 0x3) << 5 |
                           (bolos_get_onboarding_count() & 0x1F));

  apdu_buffer[offset++] = bolos_get_onboarding_state();

  // states the MCU version
  offset += bolos_get_seproxyhal_version(&apdu_buffer[offset]);

  // states the MCU-BL version
  offset += bolos_get_bootloader_version(&apdu_buffer[offset]);

  // states the hardware revision - Mainly taking into account the distinction
  // between the two MCUs on the LNX, unused for now on the LNS (but we still
  // keep the field in order to avoid a split in the answers from one product to
  // another).
  seproxyhal_features = bolos_get_seproxyhal_features();

  if ((seproxyhal_features &
       SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_MASK) ==
      SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_SSD1312) {
    hardware_version = 0x01;
  }

  apdu_buffer[offset++] = 0x01;
  apdu_buffer[offset++] = hardware_version;
  // Get the current language ID (0=English, 1=French, 2=Spanish etc) on 1 byte
  apdu_buffer[offset++] = 0x01;
  apdu_buffer[offset++] = get_os_language();
  apdu_buffer[offset++] = 0x01;
  os_perso_recover_state(&apdu_buffer[offset++], GET_STATE);

  *out_length = offset;
  return SWO_OK;
}

/*
 * APDU command "Get Version" of INS code 0x01.
 * This command aims at retrieving the version of the device firmware.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Target identifier (4)
 *                  SE version length (1)
 *                  SE version (se_ver_len)
 *                  SE flags length (1)
 *                  SE flags (se_flags_len)
 *                  MCU version length (1)
 *                  MCU version (mcu_ver_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_get_version(uint8_t* apdu_buffer,
                                       size_t in_length,
                                       size_t* out_length) {
  bolos_err_t err = SWO_OK;
  UNUSED(in_length);

  if (G_io_app.apdu_media != IO_APDU_MEDIA_NONE) {
    G_ux_params.ux_id = BOLOS_UX_EXTERNAL_CONNECTION;
    G_ux_params.len = 1;
    // put the used APDU channel in the message
    G_ux_params.u.external_connection.channel = G_io_app.apdu_media;
    os_ux(&G_ux_params);
  }
  // The P1, P2 and length basic tests have been performed in the dispatcher.
  err = dashboard_get_version_internal(apdu_buffer, out_length);

  G_dashboard.transient_ctx.state = STATE_NONE;
  return err;
}

/*
 * APDU command "Get Battery State" of INS code 0x10.
 * This command aims at retrieving the current state of the battery.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Battery state (VAR)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_get_battery_state(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length) {
  UNUSED(in_length);
  *out_length = 0;

  G_ux_params.ux_id = BOLOS_UX_BOOT_FACTORY_MODE;
  G_ux_params.len = sizeof(G_ux_params.u.factory_mode);
  G_ux_params.u.factory_mode.type = FACTORY_TEST_GET_BATTERY_INFO;
  G_ux_params.u.factory_mode.param = apdu_buffer[APDU_OFF_P2];
  os_ux_blocking(&G_ux_params);
  os_ux_result(&G_ux_params);
  if (G_ux_params.u.factory_mode.datas[0] == 0xDA) {
    memcpy(apdu_buffer, &G_ux_params.u.factory_mode.datas[2],
           MIN(G_ux_params.u.factory_mode.datas[1],
               sizeof(G_ux_params.u.factory_mode.datas)));
    *out_length = MIN(G_ux_params.u.factory_mode.datas[1],
                      sizeof(G_ux_params.u.factory_mode.datas));
  }
  return SWO_OK;
}

/*
 * APDU command "Secure Get Version" of INS code 0x10.
 * This command aims at retrieving the version of the device firmware.
 *
 * @param apdu_buffer Contains the input data when the command is received,
 * and the output data when the response is sent.
 * - Output format: Target identifier (4)
 *                  SE version length (1)
 *                  SE version (se_ver_len)
 *                  SE flags length (1)
 *                  SE flags (se_flags_len)
 *                  MCU version length (1)
 *                  MCU version (mcu_ver_len)
 *
 * @param in_length The input length.
 * @param out_length Points on the output length, if the function went well.
 *
 * @returns The following status can be returned:
 * - Success: SWO_OK if everything went well.
 */
bolos_err_t dashboard_apdu_secure_get_version(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length) {
  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);
  return dashboard_get_version_internal(apdu_buffer, out_length);
}

/**
 * <APDUHDR:5> <hash firm:1> <ADDRESS START:4> <LENGTH:4> <AES IV:16>
 */
bolos_err_t dashboard_apdu_secure_hash_firmware(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length) {
  cx_aes_key_t hmac_key;
  unsigned int length;
  uintptr_t address;
  size_t out_len;
  cx_err_t error;

  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  address = U4BE(apdu_buffer, 5 + 1);
  length = U4BE(apdu_buffer, 5 + 1 + 4);

  if (!(G_dashboard.transient_ctx.auth_source_flags &
        APPLICATION_FLAG_ISSUER)) {
    return SWO_APD_STA_25;
  }

  // ensure again
  if (G_dashboard.transient_ctx.state != STATE_MUTUAL_AUTHENTICATED) {
    return SWO_APD_STA_14;
  }

  if (!(G_dashboard.transient_ctx.auth_source_flags &
        APPLICATION_FLAG_ISSUER)) {
    return SWO_APD_STA_26;
  }

  // We check the address and length coherency against the associated
  // constraints.
  bolos_hash_firmware_check_boundaries(address, length);

  // init the string key
  cx_aes_init_key_no_throw((const unsigned char*)"This is stng key", 16,
                           &hmac_key);

  // hmac of the requested part
  os_allow_protected_flash();
  out_len = CX_AES_BLOCK_SIZE;
  if ((error = cx_aes_iv_internal(&hmac_key,
                                  CX_ENCRYPT | CX_CHAIN_CBC | CX_SIGN | CX_LAST,
                                  apdu_buffer + 5 + 1 + 4 + 4, /*IV*/
                                  CX_AES_BLOCK_SIZE, (uint8_t*)address, length,
                                  apdu_buffer, &out_len))) {
    return error;
  }
  os_deny_protected_flash();
  *out_length = CX_AES_BLOCK_SIZE;
  return SWO_OK;
}