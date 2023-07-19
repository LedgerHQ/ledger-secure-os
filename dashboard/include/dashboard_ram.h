/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#define DASHBOARD_RAM_H

#include "lcx_ecfp.h"
#include "lcx_sha256.h"

#include "bolos_privileged.h"
#include "bolos_privileged_recover.h"
#include "dashboard_constants.h"
#include "dashboard_wrapping.h"
#include "os_app.h"
#include "ox_vss.h"

#include <stdint.h>

_Static_assert(APPLICATION_MAXCOUNT <= 255, "Unsupported APPLICATION_MAXCOUNT");

typedef struct {
  union {
    // the device's ephemeral key to perform ecdh and used during fab phase to
    // temporarily store the device private key
    cx_ecfp_private_key_t ephemeral_private;
    scp_context_t scp;
  } secret;

  union {
    struct {
      unsigned char sn8[8];  // signer's nonce
      unsigned char dn8[8];  // device's nonce
    } nonces;

    struct {
      cx_ecfp_private_key_t privateKey;
      unsigned char keyIndex;
    } endorse;
    cx_aes_key_t aes_key;
  } tmp;

  cx_ecfp_public_key_t ephemeral_public;
  unsigned int device_chain_length;
  cx_ecfp_public_key_t host_public;
  unsigned int host_chain_length;

  unsigned int auth_source_flags;
  unsigned int load_offset32;
  size_t load_address;
  application_t current_application;
  unsigned int current_application_index;

  // hash context for the whole application
  cx_sha256_t load_hash_ctx;
  // hash context for the application's code+data sections only
  cx_sha256_t load_hash_code_data_ctx;

  unsigned int state;
  unsigned int language;

  unsigned char list_index;
  enum {
    LIST_NOT_STARTED,
    LIST_STARTED_SCP = 0x7C,
    LIST_STARTED_NOSCP = 0xB4,
  } list_state;

  bolos_scp_type_t scp_type;
  struct {
    cx_ecfp_private_key_t ephemeral_private;
    uint8_t derived_key[64];
    uint8_t chain[32];
    dashboard_constants_recover_state_t state;
    recover_data_t info;
    uint8_t share_number;
    uint8_t provider_number;
    uint8_t commit_point[96];
    uint8_t polynomial_seed[48];
    struct {
      size_t commitments_length;
      cx_vss_commitment_t commitments[3];
      cx_vss_share_t shares[2];
    } share_info;
  } recover;
} dashboard_ctx;

// RAM-related information.
typedef struct bolos_task_ram_s {
  // The following structure's contents is erased as soon as an APDU processing
  // went wrong.
  dashboard_ctx transient_ctx;

  // last user accepted master public key (not wiped after a successful load or
  // whatever)
  cx_ecfp_public_key_t last_accepted_public;

  unsigned int bolos_display;
  unsigned int
      run_index;  // index of the application to be run by the scheduler
  bool reinit_display;
  bool reinit_display_on_error;
  unsigned char flags;
  int selected_app;

  enum {
    DASHBOARD_STATE_NOT_PERSONALIZED,
    DASHBOARD_STATE_FACTORY_FINAL_TEST,
    DASHBOARD_STATE_ONBOARDING,
    DASHBOARD_STATE_DASHBOARD
  } dashboard_state;

} dashboard_ram_t;

// wiped when switching to a user app
// held in app ram (to allow large buffer for unsecure code signature check)
extern dashboard_ram_t G_dashboard;