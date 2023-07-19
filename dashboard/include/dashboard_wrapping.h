/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#pragma once

#include <stdint.h>

#include "lcx_aes.h"

#define SWO_UNIQUE_SCP_ERROR 0x6985

typedef struct scp_context_s {
  // the ecdh based exchanged symmetric key for encrypting the secure channel
  cx_aes_key_t enc_key;

  // the scp encryption initialisation vector (updated between each command, CBC
  // of all commands)
  uint8_t enc_iv[CX_AES_BLOCK_SIZE];

  // the ecdh based exchanged symetric key for mac'ing encrypted data of the
  // secure channel
  cx_aes_key_t mac_key;
  uint8_t mac_iv[CX_AES_BLOCK_SIZE];

  // the nested encryption chaining info
  uint8_t nek_iv[CX_AES_BLOCK_SIZE];
} scp_context_t;

int dashboard_scp_init(scp_context_t* scp, const uint8_t* session_ecdh_data);
void dashboard_scp_close(scp_context_t* scp);
int dashboard_scp_wrap(scp_context_t* scp,
                       uint8_t* data,
                       size_t data_len,
                       size_t* out_len);
int dashboard_scp_unwrap(scp_context_t* scp,
                         uint8_t* data,
                         size_t data_len,
                         size_t* out_len);