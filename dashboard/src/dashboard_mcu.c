/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

/* Includes ------------------------------------------------------------------*/
#include "bolos_privileged_seph.h"

#include <string.h>
#include "bolos.h"
#include "os.h"
#include "os_common.h"
#include "os_io_seproxyhal.h"
#include "os_watchdog.h"
#include "ux.h"

#include "hw_display.h"

#include "ble_defs.h"
#include "ledger_ble.h"
#include "os_settings.h"

/* Private enumerations ------------------------------------------------------*/

/* Private types, structures, unions -----------------------------------------*/

/* Private defines------------------------------------------------------------*/
#define SEPROXYHAL_TAG_UX_EVENT_BL_PERCENTAGE 0xFF

// Remove endless loops when running CMocka tests
#define ENDLESS_LOOP for (;;)

/* Private macros-------------------------------------------------------------*/

/* Private functions prototypes ----------------------------------------------*/
static unsigned char seph_wait_packet(unsigned char awaited_event_tag,
                                      unsigned int timeout_ms);
static unsigned int extract_version(const uint8_t* buffer, size_t length);

static void show_bootloader_screen(void);

/* Exported variables --------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/

/* Private functions ---------------------------------------------------------*/
static unsigned char seph_wait_packet(unsigned char awaited_event_tag,
                                      unsigned int timeout_ms) {
  bolos_err_t err = SWO_OK;
  if ((err = os_watchdog_arm(((timeout_ms /*ms*/)) * 1000UL,
                             OS_WATCHDOG_NOACTION))) {
    THROW(err);
  }
  io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                         sizeof(G_io_seproxyhal_spi_buffer), 0);
  while ((G_io_seproxyhal_spi_buffer[0] != awaited_event_tag) &&
         (os_watchdog_value())) {
    if (!io_seproxyhal_spi_is_status_sent()) {
      io_seproxyhal_general_status();
    }
    io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                           sizeof(G_io_seproxyhal_spi_buffer), 0);
  }
  if (G_io_seproxyhal_spi_buffer[0] != awaited_event_tag) {
    return 0;
  } else {
    // Disabling the watchdog timer
    if ((err = os_watchdog_arm(((1 /*ms*/)) * 1000UL, OS_WATCHDOG_NOACTION))) {
      THROW(err);
    }
    while (os_watchdog_value())
      ;
    return 1;
  }
}

static unsigned int extract_version(const uint8_t* buffer, size_t length) {
  unsigned short version_major = 0x0000;
  unsigned short version_minor = 0xFFFF;

  // We assume here that the version format is "XX.XXX" style (X is [0-9])
  for (size_t index = 0; index < MIN(length, 6); index++) {
    if ((buffer[index] >= '0') && (buffer[index] <= '9')) {
      // Digit detected
      if ((version_minor == 0xFFFF) && (index < 2)) {
        // Two digit max for the major version
        version_major = version_major * 10 + (buffer[index] - '0');
      } else {
        version_minor = version_minor * 10 + (buffer[index] - '0');
      }
    } else if ((buffer[index] == '.') && (version_minor == 0xFFFF) &&
               (index > 0)) {
      // Dot detected
      version_minor = 0;
    } else {
      break;
    }
  }
  if (version_minor == 0xFFFF)
    version_minor = 0;

  return (((unsigned int)version_major) << 16) + (unsigned int)version_minor;
}

static void show_bootloader_screen(void) {
  G_ux_params.len = 0;
  G_ux_params.ux_id = BOLOS_UX_BOOTLOADER_SCREEN;
  os_ux_blocking(&G_ux_params);
}

/* Exported functions --------------------------------------------------------*/
void dashboard_mcu_handle_version(void) {
  bolos_err_t err = SWO_OK;
  UNUSED(err);
  static volatile unsigned char index = 0;
  unsigned int length = 0;
  unsigned int version = 0;
  unsigned int bl_version_index = 0;
  unsigned int is_seph = 0;
  unsigned char seph_key[4];

  index = 0;
  // Parse packet
  // - Tag
  index++;  // skip

  // - Length
  length = U2BE(G_io_seproxyhal_spi_buffer, index) + 3;
  index += 2;

  // - Button state
  index++;  // skip

  // - Features
  os_allow_protected_ram();
  G_os.seproxyhal_features = U4BE(G_io_seproxyhal_spi_buffer, index);
  if (!(G_os.seproxyhal_features &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_ISET_MCUBL)) {
    is_seph = 1;
  }
  index += 4;

  // - MCU Bootloader/SEPH version
  G_os.seproxyhal_version[0] = MIN(sizeof(G_os.seproxyhal_version) - 1,
                                   G_io_seproxyhal_spi_buffer[index]);
  bl_version_index = index;
  memcpy(&G_os.seproxyhal_version[1], &G_io_seproxyhal_spi_buffer[index + 1],
         G_os.seproxyhal_version[0]);
  index += 1 + G_io_seproxyhal_spi_buffer[index];
  version =
      extract_version(&G_os.seproxyhal_version[1], G_os.seproxyhal_version[0]);
  os_deny_protected_ram();

  // - Bootloader key
  index += 1 + G_io_seproxyhal_spi_buffer[index];  // skip

  if (index < length) {
    // - MCU bootloader version
    os_allow_protected_ram();
    G_os.bootloader_version[0] = MIN(sizeof(G_os.bootloader_version) - 1,
                                     G_io_seproxyhal_spi_buffer[index]);
    bl_version_index = index;
    memcpy(&G_os.bootloader_version[1], &G_io_seproxyhal_spi_buffer[index + 1],
           G_os.bootloader_version[0]);
    index += 1 + G_io_seproxyhal_spi_buffer[index];
    os_deny_protected_ram();

    // - SEPH key
    if (G_io_seproxyhal_spi_buffer[index] == 4) {
      index++;
      memcpy(seph_key, &G_io_seproxyhal_spi_buffer[index], sizeof(seph_key));
      index += 4;
    } else {
      return;
    }
  }

  if (index > length) {
    return;
  }

  if (is_seph != 0) {
    // SEPH is running

    UNUSED(version);

    (void)bl_version_index;

  } else {
    // Bootloader is running

    index = 0;
    LEDGER_BLE_get_mac_address(G_io_apdu_buffer);
    memmove(&G_io_apdu_buffer[5], G_io_apdu_buffer,
            CONFIG_DATA_RANDOM_ADDRESS_LEN);
    G_io_apdu_buffer[index++] = SEPROXYHAL_TAG_MCU;
    G_io_apdu_buffer[index++] = 0;
    G_io_apdu_buffer[index++] = 0;
    G_io_apdu_buffer[index++] = SEPROXYHAL_TAG_MCU_TYPE_BD_ADDR;
    G_io_apdu_buffer[index++] = CONFIG_DATA_RANDOM_ADDRESS_LEN;
    index += CONFIG_DATA_RANDOM_ADDRESS_LEN;
    G_io_apdu_buffer[index] = os_setting_get(
        OS_SETTING_DEVICENAME, (uint8_t*)&G_io_apdu_buffer[index + 1], 20);
    index += G_io_apdu_buffer[index] + 1;
    G_io_apdu_buffer[2] = index - 3;
    io_seproxyhal_spi_send(G_io_apdu_buffer, index);

    G_ux_params.u.mcu_bl.button_percent = 0;
    G_ux_params.u.mcu_bl.update_percent = 0;
    show_bootloader_screen();
    io_seproxyhal_general_status();
    unsigned int push_start_ts_ms = 0;
    unsigned int current_time_ms = 0;
    unsigned char button_pushed = 0;
    while (!current_time_ms) {
      io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                             sizeof(G_io_seproxyhal_spi_buffer), 0);
      if (G_io_seproxyhal_spi_buffer[0] == SEPROXYHAL_TAG_TICKER_EVENT) {
        current_time_ms = U4BE(G_io_seproxyhal_spi_buffer, 3);
      }
      io_seproxyhal_general_status();
    }

    for (;;) {
      button_pushed = io_button_read() & BUTTON_LEFT;
      if (button_pushed) {
        if (!push_start_ts_ms) {
          push_start_ts_ms = current_time_ms;
        }
        if (G_ux_params.u.mcu_bl.button_percent != 0xFFFFFFFF) {
          G_ux_params.u.mcu_bl.button_percent =
              (current_time_ms - push_start_ts_ms) / (3000 / 100);
          show_bootloader_screen();
        }
      } else if (push_start_ts_ms) {
        push_start_ts_ms = 0;
        G_ux_params.u.mcu_bl.button_percent = 0;
        show_bootloader_screen();
      }

      G_io_seproxyhal_spi_buffer[0] = 0;
      io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                             sizeof(G_io_seproxyhal_spi_buffer), 0);
      if ((G_io_seproxyhal_spi_buffer[0] == SEPROXYHAL_TAG_UX_EVENT) &&
          (G_io_seproxyhal_spi_buffer[3] ==
           SEPROXYHAL_TAG_UX_EVENT_BL_PERCENTAGE) &&
          (!push_start_ts_ms)) {
        G_ux_params.len = 0;
        G_ux_params.ux_id = BOLOS_UX_MCU_UPGRADING_PROGRESSION;
        G_ux_params.u.mcu_bl.update_percent = G_io_seproxyhal_spi_buffer[4];
        os_ux_blocking(&G_ux_params);
      }

      if (G_io_seproxyhal_spi_buffer[0] == SEPROXYHAL_TAG_TICKER_EVENT) {
        current_time_ms = U4BE(G_io_seproxyhal_spi_buffer, 3);
      }

      if (G_ux_params.u.mcu_bl.button_percent >= 100) {
        if (G_ux_params.u.mcu_bl.button_percent != 0xFFFFFFFF) {
          G_ux_params.u.mcu_bl.button_percent = 0xFFFFFFFF;
          show_bootloader_screen();
        }
        while (io_button_read()) {
          ;
        }
        {
          // Reset the device if power button is keep pushed at least 3s then
          // released. Wait the button release in order to not trigger a power
          // on.
          G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_DEVICE_OFF;
          G_io_seproxyhal_spi_buffer[1] = 0;
          G_io_seproxyhal_spi_buffer[2] = 0;
          io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 3);
          ENDLESS_LOOP;
        }
      }

      io_seproxyhal_general_status();
    }
    show_bootloader_screen();
    ENDLESS_LOOP;
  }
}

void dashboard_mcu_init(unsigned char display_ledger_logo) {
  {
    // wait for the start session event here
    if (!seph_wait_packet(SEPROXYHAL_TAG_SESSION_START_EVENT, 3000)) {
      memset(G_io_seproxyhal_spi_buffer, 0, sizeof(G_io_seproxyhal_spi_buffer));
    }

    os_allow_protected_ram();
    G_os.recovery = (G_io_seproxyhal_spi_buffer[3] &
                     SEPROXYHAL_TAG_SESSION_START_EVENT_RECOVERY)
                        ? BOLOS_TRUE
                        : BOLOS_FALSE;
    os_deny_protected_ram();

    os_allow_protected_ram();
    G_os.seproxyhal_features = U4BE(&G_io_seproxyhal_spi_buffer[4], 0);

    uint8_t display =
        ((display_ledger_logo == BOLOS_TRUE) &&
         !(G_os.seproxyhal_features &
           SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_ISET_MCUBL));
  }
}

void dashboard_mcu_go_to_bootloader(void) {
  G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_MCU;
  G_io_seproxyhal_spi_buffer[1] = 0;
  G_io_seproxyhal_spi_buffer[2] = 1;
  G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_MCU_TYPE_BOOTLOADER;
  io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
}

void dashboard_mcu_start_ble_factory_test(void) {
  G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
  G_io_seproxyhal_spi_buffer[1] = 0;
  G_io_seproxyhal_spi_buffer[2] = 1;
  G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_BLE_RADIO_POWER_FACTORY_TEST;
  io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
}