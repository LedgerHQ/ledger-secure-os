/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>
#include "cx_ecdsa_internal.h"
#include "dashboard_ram.h"
#include "lcx_aes_siv.h"
#include "ox_ec.h"

void dashboard_accept_certificate(uint8_t* public_key,
                                  size_t public_key_len,
                                  uint32_t state) {
  cx_ecdsa_internal_init_public_key(CX_CURVE_256K1, public_key, public_key_len,
                                    &G_dashboard.transient_ctx.host_public);
  G_dashboard.transient_ctx.state = state;
  G_dashboard.transient_ctx.host_chain_length++;
}

cx_err_t dashboard_decrypt_and_verify(uint8_t* key,
                                      uint8_t* input,
                                      size_t in_len,
                                      uint8_t* output,
                                      uint8_t* tag) {
  cx_aes_siv_context_t aes_siv;
  cx_cipher_context_t cipher;
  cx_err_t error;
  aes_siv.cipher_ctx = &cipher;
  cx_aes_siv_init(&aes_siv);
  aes_siv.cipher_type = CX_CIPHER_AES_128;
  aes_siv.cipher_ctx->cipher_key =
      (cipher_key_t*)&G_dashboard.transient_ctx.tmp.aes_key;
  if ((error = cx_aes_siv_set_key(&aes_siv, key, 32 * 8)) != CX_OK) {
    return error;
  }

  return cx_aes_siv_decrypt(&aes_siv, input, in_len, NULL, 0, output, tag);
}

cx_err_t dashboard_encrypt_and_digest(uint8_t* key,
                                      uint8_t* input,
                                      size_t in_len,
                                      uint8_t* output,
                                      uint8_t* tag) {
  cx_aes_siv_context_t aes_siv;
  cx_cipher_context_t cipher;
  cx_err_t error;
  aes_siv.cipher_ctx = &cipher;
  cx_aes_siv_init(&aes_siv);
  aes_siv.cipher_type = CX_CIPHER_AES_128;
  aes_siv.cipher_ctx->cipher_key =
      (cipher_key_t*)&G_dashboard.transient_ctx.tmp.aes_key;
  if ((error = cx_aes_siv_set_key(&aes_siv, key, 32 * 8)) != CX_OK) {
    return error;
  }

  return cx_aes_siv_encrypt(&aes_siv, input, in_len, NULL, 0, output, tag);
}