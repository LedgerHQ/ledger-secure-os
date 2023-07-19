/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#define DASHBOARD_PROTOTYPES_H

#include <stddef.h>
#include <stdint.h>

#include "lcx_ecfp.h"
#include "os_app.h"
#include "os_types.h"

//////////////////////////////////////////////////
// Dispatcher functions prototypes.
//////////////////////////////////////////////////
bolos_err_t dashboard_apdu_reset(uint8_t* apdu_buffer,
                                 size_t in_length,
                                 size_t* out_length);

bolos_err_t dashboard_apdu_create_language_pack(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length);
bolos_err_t dashboard_apdu_load_language_pack(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length);
bolos_err_t dashboard_apdu_commit_language_pack(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length);
bolos_err_t dashboard_apdu_del_language_pack(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length);
bolos_err_t dashboard_apdu_list_language_packs(uint8_t* apdu_buffer,
                                               size_t in_length,
                                               size_t* out_length);
bolos_err_t dashboard_apdu_list_language_packs_continue(uint8_t* apdu_buffer,
                                                        size_t in_length,
                                                        size_t* out_length);

bolos_err_t dashboard_apdu_get_version(uint8_t* apdu_buffer,
                                       size_t in_length,
                                       size_t* out_length);

bolos_err_t dashboard_apdu_validate_target_id(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length);
bolos_err_t dashboard_apdu_get_battery_state(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length);
bolos_err_t dashboard_apdu_set_max_percentage(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length);
bolos_err_t dashboard_apdu_get_device_public_key(uint8_t* apdu_buffer,
                                                 size_t in_length,
                                                 size_t* out_length);
bolos_err_t dashboard_apdu_set_certificate(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length);
bolos_err_t dashboard_apdu_factory_test(uint8_t* apdu_buffer,
                                        size_t in_length,
                                        size_t* out_length);
bolos_err_t dashboard_apdu_initialize_authentication(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length);
bolos_err_t dashboard_apdu_validate_certificate(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length);
bolos_err_t dashboard_apdu_get_certificate(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length);
bolos_err_t dashboard_apdu_mutual_authenticate(uint8_t* apdu_buffer,
                                               size_t in_length,
                                               size_t* out_length);
bolos_err_t dashboard_handle_secure_apdu(uint8_t* apdu_buffer,
                                         size_t in_length,
                                         size_t* out_length);

bolos_err_t dashboard_apdu_set_cxport(uint8_t* apdu_buffer,
                                      size_t in_length,
                                      size_t* out_length);
bolos_err_t dashboard_apdu_get_cxport(uint8_t* apdu_buffer,
                                      size_t in_length,
                                      size_t* out_length);
bolos_err_t dashboard_apdu_endorse_set_start(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length);
bolos_err_t dashboard_apdu_endorse_set_commit(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length);
bolos_err_t dashboard_apdu_onboard(uint8_t* apdu_buffer,
                                   size_t in_length,
                                   size_t* out_length);
bolos_err_t dashboard_apdu_open_app(uint8_t* apdu_buffer,
                                    size_t in_length,
                                    size_t* out_length);
bolos_err_t dashboard_apdu_set_screen_saver(uint8_t* apdu_buffer,
                                            size_t in_length,
                                            size_t* out_length);
bolos_err_t dashboard_apdu_unsecure_list_apps(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length);
bolos_err_t dashboard_apdu_unsecure_list_apps_continue(uint8_t* apdu_buffer,
                                                       size_t in_length,
                                                       size_t* out_length);

bolos_err_t dashboard_apdu_endorsement_info_retrieval(uint8_t* apdu_buffer,
                                                      size_t in_length,
                                                      size_t* out_length);

bolos_err_t dashboard_apdu_get_device_name(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length);
bolos_err_t dashboard_apdu_set_device_name(uint8_t* apdu_buffer,
                                           size_t in_length,
                                           size_t* out_length);

bolos_err_t dashboard_apdu_get_device_mac(uint8_t* apdu_buffer,
                                          size_t in_length,
                                          size_t* out_length);

// Common functions
void dashboard_app_ux_processing(void);
void dashboard_update_progress_bar(unsigned int chunk_len);
size_t dashboard_create_slot(unsigned int flags,
                             unsigned int code_len,
                             unsigned int data_len,
                             unsigned int params_len,
                             appmain_t boot_offset,
                             const uint8_t* apdu_buffer);
bolos_err_t dashboard_delete_slot(unsigned int slot_idx,
                                  bool force_skip_consent);
bolos_err_t dashboard_delete_background_img(void);
size_t dashboard_load_chunk(uint8_t* chunk_ptr,
                            size_t chunk_length,
                            unsigned int offset,
                            bool secure);
bool dashboard_commit_check_signature(const uint8_t* sig,
                                      unsigned int sig_len,
                                      const cx_ecfp_public_key_t* public_key);
bolos_err_t dashboard_commit_finalize(void);

//////////////////////////////////////////////////
// Secure dispatcher functions prototypes.
//////////////////////////////////////////////////
bolos_err_t dashboard_apdu_secure_create_app(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length);
bolos_err_t dashboard_apdu_secure_set_load_offset(uint8_t* apdu_buffer,
                                                  size_t in_length,
                                                  size_t* out_length);
bolos_err_t dashboard_apdu_secure_load(uint8_t* apdu_buffer,
                                       size_t in_length,
                                       size_t* out_length);
bolos_err_t dashboard_apdu_secure_flush(uint8_t* apdu_buffer,
                                        size_t in_length,
                                        size_t* out_length);
bolos_err_t dashboard_apdu_secure_crc(uint8_t* apdu_buffer,
                                      size_t in_length,
                                      size_t* out_length);
bolos_err_t dashboard_apdu_secure_commit(uint8_t* apdu_buffer,
                                         size_t in_length,
                                         size_t* out_length);
bolos_err_t dashboard_apdu_secure_get_version(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length);

bolos_err_t dashboard_apdu_secure_delete_app_by_name(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length);
bolos_err_t dashboard_apdu_secure_delete_app_by_hash(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length);
bolos_err_t dashboard_apdu_secure_list_apps(uint8_t* apdu_buffer,
                                            size_t in_length,
                                            size_t* out_length);
bolos_err_t dashboard_apdu_secure_list_apps_continue(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length);
bolos_err_t dashboard_apdu_secure_get_memory_information(uint8_t* apdu_buffer,
                                                         size_t in_length,
                                                         size_t* out_length);
bolos_err_t dashboard_apdu_secure_hash_firmware(uint8_t* apdu_buffer,
                                                size_t in_length,
                                                size_t* out_length);
bolos_err_t dashboard_apdu_secure_delete_all_apps(uint8_t* apdu_buffer,
                                                  size_t in_length,
                                                  size_t* out_length);

bolos_err_t dashboard_apdu_secure_recover_set_ca(uint8_t* apdu_buffer,
                                                 size_t in_length,
                                                 size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_delete_ca(uint8_t* apdu_buffer,
                                                    size_t in_length,
                                                    size_t* out_length);

bolos_err_t dashboard_apdu_secure_recover_validate_backup_data(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_validate_certificate(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_mutual_authenticate(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_validate_backup_data_hash(
    uint8_t* apdu_buffer,
    size_t in_length,
    size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_get_share(uint8_t* apdu_buffer,
                                                    size_t in_length,
                                                    size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_validate_commit(uint8_t* apdu_buffer,
                                                          size_t in_length,
                                                          size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_restore_seed(uint8_t* apdu_buffer,
                                                       size_t in_length,
                                                       size_t* out_length);
bolos_err_t dashboard_apdu_secure_recover_delete_backup(uint8_t* apdu_buffer,
                                                        size_t in_length,
                                                        size_t* out_length);

//////////////////////////////////////////////////
// Dashboard internal prototypes.
//////////////////////////////////////////////////

// First APDU handler.
bolos_err_t dashboard_handle_apdu(uint8_t* apdu_buffer,
                                  size_t in_length,
                                  size_t* out_length);
bolos_err_t dashboard_is_secure_instruction_allowed(uint8_t sec_ins);
bolos_err_t dashboard_is_instruction_allowed(uint8_t ins);

// MCU signature checks.
void dashboard_check_mcu_code_signature(unsigned int por_state);

// Serial number check
bolos_bool_t dashboard_has_serial_number(void);