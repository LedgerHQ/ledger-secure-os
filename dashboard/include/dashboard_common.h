/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#define DASHBOARD_COMMON_H

#include <string.h>
#include "cx_errors.h"

#define DASHBOARD_COMMON_SECP256K1_LEN (32)
#define DASHBOARD_COMMON_KEY_DERIVATION_IN_LEN \
  (DASHBOARD_COMMON_SECP256K1_LEN + 4)  // 4 bytes for the counter value

void dashboard_accept_certificate(uint8_t* public_key,
                                  size_t public_key_len,
                                  uint32_t state);

cx_err_t dashboard_decrypt_and_verify(uint8_t* key,
                                      uint8_t* input,
                                      size_t in_len,
                                      uint8_t* output,
                                      uint8_t* tag);

cx_err_t dashboard_encrypt_and_digest(uint8_t* key,
                                      uint8_t* input,
                                      size_t in_len,
                                      uint8_t* output,
                                      uint8_t* tag);

cx_err_t dashboard_ecdh(const cx_ecfp_private_key_t* private_key,
                        uint32_t mode,
                        const uint8_t* point,
                        size_t point_len,
                        uint8_t* secret,
                        size_t secret_len);