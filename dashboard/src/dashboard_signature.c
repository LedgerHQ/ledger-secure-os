/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_ux.h"

#include "cx_aes_internal.h"
#include "cx_rng_internal.h"

#include "dashboard.h"
#include "dashboard_ram.h"

#include "exceptions.h"

#include "lcx_aes.h"
#include "lcx_ecdsa.h"
#include "lcx_rng.h"
#include "os_io_seproxyhal.h"
#include "os_nvm.h"
#include "os_registry.h"
#include "os_seed.h"
#include "os_types.h"
#include "os_utils.h"
#include "os_watchdog.h"

void dashboard_check_mcu_code_signature(unsigned int por_state) {
  bolos_err_t err = SWO_OK;

  UNUSED(err);
  UNUSED(por_state);

  // condition is evaluated before (factory settings set, and POR)
  if (G_ux_params.ux_id) {
// when doing os upgrade, then MCU is just a passthrough, no attack scheme
// available, no app run, no seed.
#error RELEASE without MCU CODE SIGNATURE check !!
    bolos_set_signed_mcu_code(BOLOS_TRUE);
    bolos_boot_ux(&G_ux_params);
  }
}