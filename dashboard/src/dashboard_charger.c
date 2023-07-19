/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>
#include "bolos_privileged_ux.h"
#include "bolos_ux_factory.h"
#include "errors.h"
#include "os_apdu.h"
#include "os_io_seproxyhal.h"
#include "os_types.h"

bolos_err_t dashboard_apdu_set_max_percentage(uint8_t* apdu_buffer,
                                              size_t in_length,
                                              size_t* out_length) {
  UNUSED(in_length);
  // Percentage > 100% return error
  if (apdu_buffer[5] > 100) {
    return SWO_PAR_VAL_2A;
  }

  G_ux_params.ux_id = BOLOS_UX_BOOT_FACTORY_MODE;
  G_ux_params.len = sizeof(G_ux_params.u.factory_mode);
  G_ux_params.u.factory_mode.type = FACTORY_TEST_SET_BATT_MAX_PERC;
  G_ux_params.u.factory_mode.param = apdu_buffer[APDU_OFF_DATA];
  os_ux_blocking(&G_ux_params);
  os_ux_result(&G_ux_params);

  *out_length = 0;
  return SWO_OK;
}