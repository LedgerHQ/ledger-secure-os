/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#define DASHBOARD_H

#include <stddef.h>
#include <stdint.h>
#include "bolos_target.h"
#include "dashboard_constants.h"
#include "dashboard_prototypes.h"

#include "os_apdu.h"

// clang-format off

//////////////////////////////////////////////////
// Structures definition.
//////////////////////////////////////////////////

// Pointer on function used within the dispatchers.
typedef bolos_err_t (*dashboard_dispatcher_func_t) (uint8_t* apdu_buffer, size_t in_length, size_t* out_length);

// Structure used as non-secure dispatchers' entries.
// Used to retrieve the instruction and perform basic P1, P2 and Lc tests
// before calling the associated function.
struct dashboard_apdu_dispatcher_s {
  uint8_t                               dispatcher_instruction;
  uint8_t                               dispatcher_p1;
  uint8_t                               dispatcher_p2;
  uint8_t                               dispatcher_length;
  dashboard_dispatcher_func_t           dispatcher_function;
};

typedef struct dashboard_apdu_dispatcher_s dashboard_apdu_dispatcher_t;

// Structure used as secure dispatchers' entries.
// Used to retrieve the secure instruction (first byte of deciphered data)
// and perform basic Lc checks (P1 and P2 are ignored) before calling the associated function.
struct dashboard_apdu_secure_dispatcher_s {
  // We have 2 additional uint8_t here in the structure for free if needed.
  uint8_t                               dispatcher_instruction;
  uint8_t                               dispatcher_length;
  dashboard_dispatcher_func_t           dispatcher_function;
};

typedef struct dashboard_apdu_secure_dispatcher_s dashboard_apdu_secure_dispatcher_t;

//////////////////////////////////////////////////
// Non-secure dispatcher.
//////////////////////////////////////////////////
static const dashboard_apdu_dispatcher_t C_dashboard_dispatcher_non_secure[] = {
  {INS_RESET,                           0x00,   0x00,   LC_RESET,               dashboard_apdu_reset},
  {INS_GET_VERSION,                     0x00,   0x00,   LC_GET_VERSION,         dashboard_apdu_get_version},
  {INS_CREATE_LANGUAGE_PACK,            P1_VAR, 0x00,   LC_VAL_CREATE_LANGUAGE_PACK, dashboard_apdu_create_language_pack},
  {INS_LOAD_LANGUAGE_PACK,              P1_VAR, 0x00,   LC_VAR,                 dashboard_apdu_load_language_pack},
  {INS_COMMIT_LANGUAGE_PACK,            P1_VAR, 0x00,   LC_VAR,                 dashboard_apdu_commit_language_pack},
  {INS_DEL_LANGUAGE_PACK,               P1_VAR, 0x00,   0,                      dashboard_apdu_del_language_pack},
  {INS_LIST_LANGUAGE_PACKS,             P1_VAR, 0x00,   0,                      dashboard_apdu_list_language_packs},

  {INS_VALIDATE_TARGET_ID,              P1_VAR, 0x00,   LC_VAL_TARGET_ID,       dashboard_apdu_validate_target_id},
  {INS_GET_BATTERY_STATE,               0x00,   P2_VAR, LC_GET_BATTERY_STATE,   dashboard_apdu_get_battery_state},
  {INS_SET_MAX_BATT_PERC,               0x00,   0x00,   LC_SET_MAX_BATT_PERC,   dashboard_apdu_set_max_percentage},
  {INS_GET_DEVICE_PUBLIC_KEY,           0x00,   0x00,   LC_GET_PUB_KEY,         dashboard_apdu_get_device_public_key},
  {INS_SET_CERTIFICATE,                 0x00,   P2_VAR, LC_VAR,                 dashboard_apdu_set_certificate},
  {INS_FACTORY_TEST,                    P1_VAR, P2_VAR, LC_VAR,                 dashboard_apdu_factory_test},
  {INS_INITIALIZE_AUTHENTICATION,       0x00,   0x00,   LC_INIT_AUTH,           dashboard_apdu_initialize_authentication},
  {INS_VALIDATE_CERTIFICATE,            P1_VAR, P2_VAR, LC_VAR,                 dashboard_apdu_validate_certificate},
  {INS_GET_CERTIFICATE,                 P1_VAR, 0x00,   LC_GET_CERTIFICATE,     dashboard_apdu_get_certificate},
  {INS_MUTUAL_AUTHENTICATE,             0x00,   0x00,   LC_MUTUAL_AUTH,         dashboard_apdu_mutual_authenticate},
  {INS_SECURE_COMMAND,                  P1_VAR, P2_VAR, LC_VAR,                 dashboard_handle_secure_apdu},
  {INS_SET_CXPORT,                      0x00,   0x00,   LC_VAR,                 dashboard_apdu_set_cxport},
  {INS_GET_CXPORT,                      0x00,   0x00,   LC_GET_CXPORT,          dashboard_apdu_get_cxport},
  {INS_ENDORSE_SET_START,               P1_VAR, 0x00,   LC_ENDORSE_START,       dashboard_apdu_endorse_set_start},
  {INS_ENDORSE_SET_COMMIT,              P1_VAR, P2_VAR, LC_VAR,                 dashboard_apdu_endorse_set_commit},
  {INS_ONBOARD,                         P1_VAR, 0x00, LC_VAR,                   dashboard_apdu_onboard},
  {INS_OPEN_APP,                        0x00,   0x00,   LC_VAR,                 dashboard_apdu_open_app},
  {INS_SET_SCREEN_SAVER,                P1_VAR, P2_VAR, LC_VAR,                 dashboard_apdu_set_screen_saver},
  {INS_LIST_APPS,                       0x00,   0x00,   LC_LIST_APPS_START,     dashboard_apdu_unsecure_list_apps},
  {INS_LIST_APPS_CONTINUE,              0x00,   0x00,   LC_LIST_APPS_CONTINUE,  dashboard_apdu_unsecure_list_apps_continue},

  {INS_ENDORSEMENT_INFO_RETRIEVAL,      P1_VAR, 0x00,   LC_ENDORSEMENT_INFO,    dashboard_apdu_endorsement_info_retrieval},

  {INS_GET_DEVICE_NAME,                 0x00,   0x00,   LC_GET_DEVICE_NAME,     dashboard_apdu_get_device_name},
  {INS_SET_DEVICE_NAME,                 P1_VAR, 0x00,   LC_VAR,                 dashboard_apdu_set_device_name},

  {INS_GET_DEVICE_MAC,                 0x00,   0x00,   LC_GET_DEVICE_MAC,       dashboard_apdu_get_device_mac},



  // Testing APDUs below.

};

#define DISPATCHER_NON_SECURE_LENGTH    (sizeof(C_dashboard_dispatcher_non_secure) / sizeof(C_dashboard_dispatcher_non_secure[0]))

//////////////////////////////////////////////////
// Secure dispatcher.
//////////////////////////////////////////////////
static const dashboard_apdu_secure_dispatcher_t C_dashboard_secure_dispatcher[] = {
  {SECUREINS_CREATE_APP,                LC_SECURE_CREATE_APP,         dashboard_apdu_secure_create_app},
  {SECUREINS_SET_LOAD_OFFSET,           LC_SECURE_SET_LOAD_OFF,       dashboard_apdu_secure_set_load_offset},
  {SECUREINS_LOAD,                      LC_VAR,                       dashboard_apdu_secure_load},
  {SECUREINS_FLUSH,                     LC_SECURE_FLUSH,              dashboard_apdu_secure_flush},
  {SECUREINS_CRC,                       LC_SECURE_CRC,                dashboard_apdu_secure_crc},
  {SECUREINS_COMMIT,                    LC_VAR,                       dashboard_apdu_secure_commit},
  {SECUREINS_GET_VERSION,               LC_SECURE_GET_VERSION,        dashboard_apdu_secure_get_version},



  {SECUREINS_DELETE_APP,                LC_VAR,                       dashboard_apdu_secure_delete_app_by_name},
  {SECUREINS_DELETE_APP_BY_HASH,        LC_SECURE_DELETE_BY_HASH,     dashboard_apdu_secure_delete_app_by_hash},
  {SECUREINS_LIST_APPS,                 LC_SECURE_LIST_APPS_START,    dashboard_apdu_secure_list_apps},
  {SECUREINS_LIST_APPS_CONTINUE,        LC_SECURE_LIST_APPS_CONT,     dashboard_apdu_secure_list_apps_continue},
  {SECUREINS_GET_MEMORY_INFORMATION,    LC_SECURE_GET_MEM_INFO,       dashboard_apdu_secure_get_memory_information},
  {SECUREINS_HASH_FIRMWARE,             LC_SECURE_HASH_FIRMWARE,      dashboard_apdu_secure_hash_firmware},

  {SECUREINS_DELETE_ALL_APPS,           LC_SECURE_DELETE_ALL,                       dashboard_apdu_secure_delete_all_apps},




};

#define DISPATCHER_SECURE_LENGTH    (sizeof(C_dashboard_secure_dispatcher) / sizeof(C_dashboard_secure_dispatcher[0]))

static const dashboard_apdu_secure_dispatcher_t C_dashboard_recover_secure_dispatcher[] = {
  {SECUREINS_RECOVER_SET_CA,                    LC_VAR,               dashboard_apdu_secure_recover_set_ca},
  {SECUREINS_RECOVER_DELETE_CA,                 LC_VAR,               dashboard_apdu_secure_recover_delete_ca},
  {SECUREINS_RECOVER_VALIDATE_BACKUP_DATA,      LC_VAR,               dashboard_apdu_secure_recover_validate_backup_data},
  {SECUREINS_RECOVER_VALIDATE_CERTIFICATE,      LC_VAR,               dashboard_apdu_secure_recover_validate_certificate},
  {SECUREINS_RECOVER_MUTUAL_AUTHENTICATE,       LC_VAR,               dashboard_apdu_secure_recover_mutual_authenticate},
  {SECUREINS_RECOVER_VALIDATE_BACKUP_DATA_HASH, LC_VAR,               dashboard_apdu_secure_recover_validate_backup_data_hash},
  {SECUREINS_RECOVER_GET_SHARE,                 LC_VAR,               dashboard_apdu_secure_recover_get_share},
  {SECUREINS_RECOVER_VALIDATE_COMMIT,           LC_VAR,               dashboard_apdu_secure_recover_validate_commit},
  {SECUREINS_RECOVER_RESTORE_SEED,              LC_VAR,               dashboard_apdu_secure_recover_restore_seed},
  {SECUREINS_RECOVER_DELETE_BACKUP,             LC_VAR,               dashboard_apdu_secure_recover_delete_backup},
};

#define DISPATCHER_RECOVER_SECURE_LENGTH    (sizeof(C_dashboard_recover_secure_dispatcher) / sizeof(C_dashboard_recover_secure_dispatcher[0]))

// clang-format on