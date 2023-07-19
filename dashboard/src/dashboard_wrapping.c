/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "cx_aes_internal.h"
#include "cx_ecdsa_internal.h"
#include "cx_ecfp_internal.h"

#include "dashboard_ram.h"

#include "dashboard_common.h"
#include "dashboard_constants.h"
#include "lcx_aes.h"
#include "lcx_aes_siv.h"
#include "lcx_ecdh.h"
#include "os_io.h"
#include "os_utils.h"

#define SCP_MAC_LENGTH 14
#define SCP_DERIVE_KEY_MAGIC 0x659A3700

_Static_assert(SCP_MAC_LENGTH <= CX_AES_BLOCK_SIZE,
               "SCP_MAC_LENGTH is bigger than an AES block");

static int dashboard_scp_derive_key(const uint8_t* ecdh_output,
                                    unsigned int keyindex,
                                    uint8_t* out) {
  cx_ecfp_private_key_t ecfp_pkp_privateKey;
  cx_ecfp_public_key_t ecfp_pkp_publicKey;
  cx_sha256_t hash_ctx;
  size_t secp256k1_param_length;
  int diff1, diff2;

  unsigned int retry = 0;
  cx_bn_t bn_out, bn_n;
  cx_err_t error;

  CX_CHECK(cx_ecdomain_parameters_length(CX_CURVE_SECP256K1,
                                         &secp256k1_param_length));
  CX_CHECK(cx_bn_lock(secp256k1_param_length, 0));
  CX_CHECK(cx_bn_alloc(&bn_n, secp256k1_param_length));
  CX_CHECK(
      cx_ecdomain_parameter_bn(CX_CURVE_SECP256K1, CX_CURVE_PARAM_Order, bn_n));
  CX_CHECK(cx_bn_alloc(&bn_out, secp256k1_param_length));

  for (;;) {
    // di = sha256(i || retrycounter || ecdhmastersecret)
    out[0] = keyindex >> 24;
    out[1] = keyindex >> 16;
    out[2] = keyindex >> 8;
    out[3] = keyindex;
    out[4] = retry;

    cx_sha256_init_no_throw(&hash_ctx);
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hash_ctx, 0, out, 5, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t*)&hash_ctx, CX_LAST, ecdh_output,
                              CX_SHA256_SIZE, out, CX_SHA256_SIZE));

    CX_CHECK(cx_bn_init(bn_out, out, CX_SHA256_SIZE));
    // ensure di is in the range [1; n-1]
    CX_CHECK(cx_bn_cmp(bn_out, bn_n, &diff1));
    CX_CHECK(cx_bn_cmp_u32(bn_out, 0, &diff2));
    if (diff1 < 0 && diff2 > 0) {
      // the di value is ok
      break;
    }

    if (retry >= 10) {
      error = CX_INTERNAL_ERROR;
      break;
    }
    retry++;
  }
end:
  cx_bn_unlock();
  if (error) {
    return -1;
  }

  // Pi = di*G
  cx_ecdsa_internal_init_private_key(CX_CURVE_SECP256K1, out, CX_SHA256_SIZE,
                                     &ecfp_pkp_privateKey);
  if (cx_ecfp_internal_generate_pair(CX_CURVE_SECP256K1, &ecfp_pkp_publicKey,
                                     &ecfp_pkp_privateKey, 1) != CX_OK) {
    return -1;
  }

  // We wipe the private key.
  explicit_bzero(&ecfp_pkp_privateKey, sizeof(cx_ecfp_private_key_t));

  // out = sha256(Pi)
  cx_hash_sha256(ecfp_pkp_publicKey.W, ecfp_pkp_publicKey.W_len, out,
                 CX_SHA256_SIZE);

  // We wipe the public key.
  explicit_bzero(&ecfp_pkp_publicKey, sizeof(cx_ecfp_public_key_t));

  // ensure everything has been computed and no action has been skipped (leading
  // to very faulty session keys)
  return SCP_DERIVE_KEY_MAGIC + keyindex;
}

cx_err_t dashboard_recover_scp_derive_key(const uint8_t* ecdh_output,
                                          size_t ecdh_output_len,
                                          uint8_t* derived_key) {
  uint8_t block_to_encrypt[CX_AES_BLOCK_SIZE];
  cx_err_t error = CX_INTERNAL_ERROR;
  cx_aes_key_t aes_key;

  if ((error =
           cx_aes_init_key_no_throw(ecdh_output, ecdh_output_len, &aes_key))) {
    return error;
  }

  // Compute the MAC key
  memset(block_to_encrypt, 0x1, sizeof(block_to_encrypt));
  if ((error = cx_aes_enc_block_internal(&aes_key, block_to_encrypt,
                                         derived_key))) {
    memset(&aes_key, 0, sizeof(cx_aes_key_t));
    return error;
  }
  // Compute the encryption key
  memset(block_to_encrypt, 0x2, sizeof(block_to_encrypt));
  if ((error = cx_aes_enc_block_internal(&aes_key, block_to_encrypt,
                                         derived_key + CX_AES_BLOCK_SIZE))) {
    memset(&aes_key, 0, sizeof(cx_aes_key_t));
    return error;
  }
  memset(&aes_key, 0, sizeof(cx_aes_key_t));
  return CX_OK;
}

cx_err_t dashboard_ecdh(const cx_ecfp_private_key_t* private_key,
                        uint32_t mode,
                        const uint8_t* point,
                        size_t point_len,
                        uint8_t* secret,
                        size_t secret_len) {
  uint8_t tmp[DASHBOARD_COMMON_KEY_DERIVATION_IN_LEN];
  uint8_t counter = 1;
  cx_err_t error;

  if ((error = cx_ecdh_no_throw(private_key, mode, point, point_len, tmp,
                                DASHBOARD_COMMON_SECP256K1_LEN))) {
    return error;
  }
  memset(secret, 0, secret_len);
  U4BE_ENCODE(tmp, DASHBOARD_COMMON_SECP256K1_LEN, counter);
  cx_hash_sha256(tmp, sizeof(tmp), secret, secret_len);
  memcpy(tmp, secret, secret_len);
  if ((error = dashboard_recover_scp_derive_key(tmp, secret_len, secret))) {
    return error;
  }

  return CX_OK;
}

void dashboard_scp_close(scp_context_t* scp) {
  explicit_bzero(scp, sizeof(scp_context_t));
}

int dashboard_scp_init(scp_context_t* scp, const uint8_t* session_ecdh_data) {
  uint8_t tmp[CX_SHA256_SIZE];

  if (SCP_RECOVER == G_dashboard.transient_ctx.scp_type) {
    memcpy(scp->enc_key.keys, session_ecdh_data, sizeof(scp->enc_key.keys));
    scp->enc_key.size = CX_AES_128_KEY_LEN;
    return 0;
  }

  // derive enc session key
  if (dashboard_scp_derive_key(session_ecdh_data, 0, tmp) !=
      SCP_DERIVE_KEY_MAGIC + 0) {
    return -1;
  }
  // initialize the aes_key from the generated secret
  cx_aes_init_key_no_throw(tmp, CX_AES_BLOCK_SIZE, &scp->enc_key);

  // wipe enc IV
  memset(&scp->enc_iv, 0, sizeof(scp->enc_iv));

  // derive hmac session key
  if (dashboard_scp_derive_key(session_ecdh_data, 1, tmp) !=
      SCP_DERIVE_KEY_MAGIC + 1) {
    return -1;
  }
  // initialize the aes_key from the generated secret
  cx_aes_init_key_no_throw(tmp, CX_AES_BLOCK_SIZE, &scp->mac_key);

  // wipe enc IV and NEK IV
  memset(scp->mac_iv, 0, sizeof(scp->mac_iv));
  memset(scp->nek_iv, 0, sizeof(scp->nek_iv));
  return 0;
}

static int compute_cbc_mac(cx_aes_key_t* key,
                           const uint8_t* iv,
                           uint8_t* data,
                           size_t data_len,
                           uint8_t* mac) {
  uint8_t* ptr = data;

  memcpy(mac, iv, CX_AES_BLOCK_SIZE);
  while (data_len) {
    size_t block_size = CX_AES_BLOCK_SIZE;
    // unwrap in place and get the length minus the padding
    if (cx_aes_iv_internal(key, CX_CHAIN_CBC | CX_ENCRYPT | CX_LAST, mac,
                           CX_AES_BLOCK_SIZE, ptr, CX_AES_BLOCK_SIZE, mac,
                           &block_size)) {
      return -1;
    }
    ptr += CX_AES_BLOCK_SIZE;
    data_len -= CX_AES_BLOCK_SIZE;
  }
  return 0;
}

/**
 * Return the unwrapped data length
 */
int dashboard_scp_unwrap(scp_context_t* scp,
                         uint8_t* data,
                         size_t data_len,
                         size_t* out_len) {
  uint8_t tmp[CX_AES_BLOCK_SIZE];
  size_t encrypted_len;

  *out_len = 0;
  if (SCP_RECOVER == G_dashboard.transient_ctx.scp_type) {
    uint8_t output[IO_APDU_BUFFER_SIZE];

    if (data_len < AES_SIV_TAG_LEN) {
      return -1;
    }

    // input and output must not overlap
    if (dashboard_decrypt_and_verify(scp->enc_key.keys, data + AES_SIV_TAG_LEN,
                                     data_len - AES_SIV_TAG_LEN, output,
                                     data)) {
      return -1;
    }
    memset(data, 0, data_len);
    memcpy(data, output, data_len - AES_SIV_TAG_LEN);
    *out_len = data_len - AES_SIV_TAG_LEN;
    return 0;
  }

  // ensure data has correct length
  if (data_len < SCP_MAC_LENGTH) {
    return -1;
  }

  encrypted_len = data_len - SCP_MAC_LENGTH;
  // ENC data must be aligned on a AES block
  if (encrypted_len % CX_AES_BLOCK_SIZE) {
    return -1;
  }

  if (compute_cbc_mac(&scp->mac_key, scp->mac_iv, data, encrypted_len, tmp)) {
    return -1;
  }

  // invalid Command MAC
  if (os_secure_memcmp(tmp + CX_AES_BLOCK_SIZE - SCP_MAC_LENGTH,
                       data + data_len - SCP_MAC_LENGTH, SCP_MAC_LENGTH)) {
    return -1;
  }
  // update MAC iv After checked ok
  memcpy(scp->mac_iv, tmp, CX_AES_BLOCK_SIZE);

  // double check
  if (os_secure_memcmp(data + data_len - SCP_MAC_LENGTH,
                       tmp + CX_AES_BLOCK_SIZE - SCP_MAC_LENGTH,
                       SCP_MAC_LENGTH)) {
    return -1;
  }

  if (data_len < SCP_MAC_LENGTH) {
    return -1;
  }
  // consume mac trace from the unwrapped data
  data_len -= SCP_MAC_LENGTH;

  // ensure data has correct length
  if (data_len % CX_AES_BLOCK_SIZE) {
    return -1;
  }

  // hold next iv
  memcpy(tmp, data + data_len - CX_AES_BLOCK_SIZE, CX_AES_BLOCK_SIZE);
  // unwrap in place and get the length minus the padding
  if (cx_aes_iv_internal(
          &scp->enc_key, CX_PAD_ISO9797M2 | CX_CHAIN_CBC | CX_DECRYPT | CX_LAST,
          scp->enc_iv, CX_AES_BLOCK_SIZE, data, data_len, data, &data_len)) {
    return -1;
  }
  // output next iv
  memcpy(scp->enc_iv, tmp, CX_AES_BLOCK_SIZE);
  *out_len = data_len;
  return 0;
}

int dashboard_scp_wrap(scp_context_t* scp,
                       uint8_t* data,
                       size_t data_len,
                       size_t* out_len) {
  *out_len = 0;

  // perform SCP encryption
  if (SCP_RECOVER == G_dashboard.transient_ctx.scp_type) {
    uint8_t tag[AES_SIV_TAG_LEN];
    uint8_t output[IO_APDU_BUFFER_SIZE];

    // input and output must not overlap
    if (dashboard_encrypt_and_digest(scp->enc_key.keys, data, data_len, output,
                                     tag)) {
      return -1;
    }

    memcpy(data, tag, AES_SIV_TAG_LEN);
    memcpy(data + AES_SIV_TAG_LEN, output, data_len);
    *out_len = data_len + AES_SIV_TAG_LEN;
    return 0;
  }

  data_len += 2 * CX_AES_BLOCK_SIZE;
  if (cx_aes_iv_internal(&scp->enc_key,
                         CX_PAD_ISO9797M2 | CX_CHAIN_CBC | CX_ENCRYPT | CX_LAST,
                         scp->enc_iv, CX_AES_BLOCK_SIZE, data,
                         data_len - 2 * CX_AES_BLOCK_SIZE, data, &data_len)) {
    return -1;
  }
  // retain updated IV
  memcpy(scp->enc_iv, data + data_len - CX_AES_BLOCK_SIZE, CX_AES_BLOCK_SIZE);

  // robustness check
  if (data_len % CX_AES_BLOCK_SIZE) {
    return -1;
  }

  if (compute_cbc_mac(&scp->mac_key, scp->mac_iv, data, data_len,
                      scp->mac_iv)) {
    return -1;
  }
  memcpy(data + data_len, scp->mac_iv + CX_AES_BLOCK_SIZE - SCP_MAC_LENGTH,
         SCP_MAC_LENGTH);

  *out_len = data_len + SCP_MAC_LENGTH;
  return 0;
}