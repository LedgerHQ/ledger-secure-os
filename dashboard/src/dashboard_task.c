/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_seph.h"
#include "bolos_privileged_ux.h"

#include "dashboard.h"
#include "dashboard_ram.h"

#include "exceptions.h"

#include "lcx_ecdsa.h"
#include "os_apdu.h"
#include "os_halt.h"
#include "os_id.h"
#include "os_io.h"
#include "os_io_seproxyhal.h"
#include "os_nvm.h"
#include "os_pin.h"
#include "os_seed.h"

#include "os_settings.h"

#include "os_task.h"
#include "os_utils.h"
#include "os_watchdog.h"

#include "bolos_ux_factory.h"

#include "ux.h"

static void dashboard_init_iotask(void) {
  // retrieve and cache the plane mode setting value.
  G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
  // start the io task
  // NOTE: could store the task id, to switch to it later on instead of just
  // yielding
  if (os_sched_create(
          io_task,
          // NVRAM
          &_text_io_task, &_etext_io_task - &_text_io_task,
          // RAM segment
          &_bss_io_task, &_ebss_io_task - &_bss_io_task,
          // STACK segment (overlay the second second, but don't care)
          &_stack_io_task,
          &_estack_io_task - &_stack_io_task) != TASK_SUBTASKS_START) {
    // task id expected in os_ux_blocking is not matched
    halt();
  }
}

static void dashboard_display_boot_menu(void) {
  G_ux_params.len = 0;
  G_ux_params.ux_id = BOLOS_UX_BOOT_MENU;
  switch (os_ux_blocking(&G_ux_params)) {
      // bootloader
    case BOLOS_FALSE:
      G_io_apdu_buffer[0] = SEPROXYHAL_TAG_MCU;
      G_io_apdu_buffer[1] = 0;
      G_io_apdu_buffer[2] = 1;
      G_io_apdu_buffer[3] = SEPROXYHAL_TAG_MCU_TYPE_BOOTLOADER;
      io_seproxyhal_spi_send(G_io_apdu_buffer, 4);
      for (;;)
        ;  // wait until MCU resets the SE
      break;

    // recovery
    case BOLOS_TRUE:
    case BOLOS_UX_REDRAW:
      bolos_set_recovery(BOLOS_TRUE);
      break;

    default:
      break;
  }
}

static void dashboard_init_state_machine(void) {
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc;
  bolos_bool_t is_onboarded;
  bolos_bool_t is_pin_set;
  bolos_bool_t is_pin_validated;
  bolos_bool_t is_factory_filled;

  for (;;) {
    // pre read onboard state to avoid killing the mpu configuration for other
    // if conditions
    is_onboarded = os_perso_isonboarded();
    is_pin_set = os_perso_is_pin_set();
    is_pin_validated = os_global_pin_is_validated();
    is_factory_filled = dashboard_has_serial_number();
    // if MCU is not validated, then sorry for your seed (fault?)
    G_ux_params.len = 0;

    bolos_check_and_wipe_nvram();

    // check if device is hsm personalized
    if ((bolos_check_crc_consistency(CRC_FACTORY_1, &crc) != SWO_OK) ||
        (crc != BOLOS_TRUE)) {
      // wipe all data if crc is wrong (could be a tearing issue, therefore
      // avoid potential leaks)
      bolos_erase_all(NO_USER_PREF_PRESERVED);

      G_dashboard.dashboard_state = DASHBOARD_STATE_NOT_PERSONALIZED;
      G_dashboard.bolos_display =
          BOLOS_UX_BOOT_NOT_PERSONALIZED;  // never meant to be processed by
                                           // other than the internal ux
    }
    // check if device is factory filled with the S/N
    else if (is_factory_filled == BOLOS_FALSE) {
      G_dashboard.dashboard_state = DASHBOARD_STATE_FACTORY_FINAL_TEST;
      G_dashboard.bolos_display = BOLOS_UX_BOOT_FACTORY_MODE;
      G_ux_params.len = sizeof(G_ux_params.u.factory_mode);
      G_ux_params.u.factory_mode.type = FACTORY_TEST_START_STOP;
      G_ux_params.u.factory_mode.param = 1;
    }
    // check if device is user initialized
    // no onboarding in recovery
    else if (bolos_is_signed_mcu_code() == BOLOS_TRUE &&
             bolos_is_recovery() != BOLOS_TRUE && is_onboarded != BOLOS_TRUE) {
      if (is_pin_set != BOLOS_TRUE) {
        bolos_erase_all(PRESERVE_LANGUAGE | PRESERVE_SAVER_STRING);
      } else {
        while (os_global_pin_is_validated() != BOLOS_TRUE) {
          G_ux_params.ux_id = BOLOS_UX_VALIDATE_PIN;
          os_ux_blocking(&G_ux_params);
        }
      }

      if ((err = os_watchdog_arm(BOLOS_SECURITY_ONBOARD_DELAY_S * 1000000UL,
                                 OS_WATCHDOG_NOACTION))) {
        THROW(err);
      }

      G_ux_params.ux_id = BOLOS_UX_BOOT_ONBOARDING;
      if (os_ux_blocking(&G_ux_params) == BOLOS_FALSE) {
        continue;
      }

      G_dashboard.bolos_display = BOLOS_UX_BOOT_ONBOARDING;
      G_dashboard.dashboard_state = DASHBOARD_STATE_ONBOARDING;
    }
    // standard boot, ask pin before dashboard
    else if (bolos_is_signed_mcu_code() != BOLOS_TRUE ||
             is_pin_validated != BOLOS_TRUE) {
      if (bolos_is_signed_mcu_code() == BOLOS_TRUE &&
          os_perso_is_pin_set() == BOLOS_TRUE) {
        // re ask pin before entering in the bolos
        while (os_global_pin_is_validated() != BOLOS_TRUE) {
          G_ux_params.ux_id = BOLOS_UX_VALIDATE_PIN;
          if (os_ux_blocking(&G_ux_params) == BOLOS_FALSE) {
            // could occur if power off onto pin & cancel on power off after
            // lock & unlock => REDRAW
          }

          // wiped ??
          if (os_perso_isonboarded() != BOLOS_TRUE) {
            continue;
          }
        }
      }

      G_dashboard.bolos_display = BOLOS_UX_DASHBOARD;
      G_dashboard.dashboard_state = DASHBOARD_STATE_DASHBOARD;
      // pin ok, display the dashboard
    }
    // likely an application exit
    else {
      G_dashboard.dashboard_state = DASHBOARD_STATE_DASHBOARD;
      G_dashboard.bolos_display = BOLOS_UX_DASHBOARD;
    }

    // special case, already displayed to allow for autoonboarding
    if (G_dashboard.dashboard_state != DASHBOARD_STATE_ONBOARDING) {
      G_ux_params.ux_id = G_dashboard.bolos_display;
      os_ux_blocking(&G_ux_params);  // OK is sent when the screen is ready
    }
    break;
  }
}

// returns BOLOS_TRUE if the boot menu should be displayed
static bolos_bool_t dashboard_delay_logo(void) {
  bolos_err_t err = SWO_OK;
  bolos_bool_t boot_button_pressed = BOLOS_TRUE;
  // when the UX boot, for the balenos, the boot logo is displayed
  // 1 second logo
  if (dashboard_has_serial_number() == BOLOS_TRUE) {
    for (unsigned int i = 0; i < 10; i++) {
      if ((err = os_watchdog_arm(((100 /*ms*/)) * 1000UL,
                                 OS_WATCHDOG_NOACTION))) {
        THROW(err);
      }

      while (os_watchdog_value())
        ;

      if (!(io_button_read() & BUTTON_LEFT)) {
        boot_button_pressed = BOLOS_FALSE;
      }
    }
  }

  // if the left button was pressed the last second, wait 1,5 more second to
  // show boot menu
  if (boot_button_pressed == BOLOS_TRUE) {
    os_watchdog_arm(((1500 /*ms*/)) * 1000UL, OS_WATCHDOG_NOACTION);
    while (os_watchdog_value() && (io_button_read() & BUTTON_LEFT))
      ;
    if (os_watchdog_value()) {
      boot_button_pressed = BOLOS_FALSE;
    }
  }
  return boot_button_pressed;
}

static void dashboard_restart_iotask(void) {
  if (io_seproxyhal_spi_is_status_sent()) {
    io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                           sizeof(G_io_seproxyhal_spi_buffer), 0);
  }
  // restart the IO task, to avoid requiring the PIN after a BLE disconnection
  // for example.
  os_sched_kill(TASK_SUBTASKS_START);
  dashboard_init_iotask();
}

static void dashboard_task_init(void) {
  // reset the try context stuff
  os_boot();

  // wipe ux buffer before using it
  memset(&G_ux_params, 0, sizeof(G_ux_params));

  BEGIN_TRY {
    TRY {
      // save the POR status to display or not the boot menu
      unsigned int por_state = bolos_is_por();

      bolos_bool_t display_boot_menu = BOLOS_FALSE;

      io_seproxyhal_init();
      if (por_state != BOLOS_TRUE) {
        // cache the received event (probably a display sent from the dashboard)
        // if no event received, then well, we're stuck, wait until MCU reset
        // the token
        if (io_seproxyhal_spi_is_status_sent()) {
          io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                 sizeof(G_io_seproxyhal_spi_buffer), 0);
        }
      }

      bolos_set_recovery(BOLOS_FALSE);  // default is to boot normally

      // only wait for the session start for the first run, afterwards (when
      // exiting an application) we won't wait
      if (por_state == BOLOS_TRUE) {
        // await for the session start and proceed to mcu update protocol if
        // required
        dashboard_mcu_init(BOLOS_TRUE);

        G_ux_params.ux_id = BOLOS_UX_INITIALIZE;
        os_ux(&G_ux_params);

        display_boot_menu = dashboard_delay_logo();

        // handle mcu version only on reset
        dashboard_mcu_handle_version();
      }

      bolos_check_and_wipe_nvram();

      // disables IO's (when exiting an app and going back to onboarding)
      io_seproxyhal_disable_io();

      // reset variables to avoid attacks after returning from the loaded app
      memset(&G_dashboard.transient_ctx, 0, sizeof(G_dashboard.transient_ctx));
      G_dashboard.flags = 0;
      G_dashboard.reinit_display = false;
      G_dashboard.reinit_display_on_error = false;
      G_dashboard.selected_app = -1;
      G_dashboard.transient_ctx.state = STATE_BOOT;

      // consider first boot ok, ux app is now active
      bolos_set_por(BOLOS_FALSE);

      // ensure boot is OK when UX app is loaded
      // code signature to be done, draw the boot screen (could be different
      // from the bootlogo)
      G_ux_params.len = 0;
      G_ux_params.ux_id = BOLOS_UX_BOOT;
      os_ux_blocking(&G_ux_params);

      unsigned int extra_check_value;
      bolos_check_security_fault_counter(&extra_check_value);

      // reboot the UX (to allow for animation after an application exits
      // (except settings) code signature to be done, draw the boot screen
      // (could be different from the bootlogo)
      G_ux_params.len = 0;
      G_ux_params.ux_id = BOLOS_UX_BOLOS_START;
      os_ux_blocking(&G_ux_params);

      // if power on, then depending on the io button state, display the boot
      // menu
      if (por_state == BOLOS_TRUE && display_boot_menu == BOLOS_TRUE) {
        dashboard_display_boot_menu();
      }

      // only perform MCU bl upgrade/gobacklock when the MCU interface is
      // enabled

      dashboard_init_state_machine();

      // start IO's
      if (G_dashboard.transient_ctx.state == STATE_BOOT) {
        dashboard_restart_iotask();
      }

      // DESIGN NOTE: shall be done only at boot, afterwards the session key is
      // on
      G_dashboard.transient_ctx.state = STATE_NONE;
    }
    CATCH_ALL {
      // hum, well, what can we do, initialization has not finished correctly
      for (;;)
        ;
    }
    FINALLY {}
  }
  END_TRY;
}

bolos_err_t dashboard_is_secure_instruction_allowed(uint8_t sec_ins) {
  switch (G_dashboard.dashboard_state) {
    case DASHBOARD_STATE_ONBOARDING:
      if ((sec_ins != SECUREINS_GET_VERSION) &&
          (sec_ins != SECUREINS_GET_MEMORY_INFORMATION) &&
          (sec_ins != SECUREINS_LIST_APPS) &&
          (sec_ins != SECUREINS_LIST_APPS_CONTINUE) &&
          (sec_ins != SECUREINS_RECOVER_SET_CA) &&
          (sec_ins != SECUREINS_RECOVER_DELETE_CA) &&
          (sec_ins != SECUREINS_RECOVER_VALIDATE_BACKUP_DATA) &&
          (sec_ins != SECUREINS_RECOVER_VALIDATE_CERTIFICATE) &&
          (sec_ins != SECUREINS_RECOVER_MUTUAL_AUTHENTICATE) &&
          (sec_ins != SECUREINS_RECOVER_VALIDATE_BACKUP_DATA_HASH) &&
          (sec_ins != SECUREINS_RECOVER_GET_SHARE) &&
          (sec_ins != SECUREINS_RECOVER_VALIDATE_COMMIT) &&
          (sec_ins != SECUREINS_RECOVER_RESTORE_SEED) &&
          (sec_ins != SECUREINS_RECOVER_DELETE_BACKUP)) {
        return SWO_APD_INS_06;
      }
      break;

    case DASHBOARD_STATE_FACTORY_FINAL_TEST:
      return SWO_APD_INS_06;

    case DASHBOARD_STATE_NOT_PERSONALIZED:
      return SWO_APD_INS_06;

    case DASHBOARD_STATE_DASHBOARD:
      return SWO_OK;

    default:
      return SWO_APD_INS_06;
  }
  return SWO_OK;
}

bolos_err_t dashboard_is_instruction_allowed(uint8_t ins) {
  // global INS restriction when not personalized state
  if ((G_dashboard.dashboard_state == DASHBOARD_STATE_NOT_PERSONALIZED) &&
      (ins != INS_GET_VERSION) && (ins != INS_CREATE_LANGUAGE_PACK) &&
      (ins != INS_LOAD_LANGUAGE_PACK) && (ins != INS_COMMIT_LANGUAGE_PACK) &&
      (ins != INS_DEL_LANGUAGE_PACK) && (ins != INS_LIST_LANGUAGE_PACKS) &&
      (ins != INS_RESET) && (ins != INS_VALIDATE_TARGET_ID) &&
      (ins != INS_GET_DEVICE_PUBLIC_KEY) && (ins != INS_SET_CERTIFICATE)) {
    return SWO_SEC_CRC_16;
  }
  // global INS restriction when in factory final test state
  else if ((G_dashboard.dashboard_state ==
            DASHBOARD_STATE_FACTORY_FINAL_TEST) &&
           (ins != INS_GET_VERSION) && (ins != INS_CREATE_LANGUAGE_PACK) &&
           (ins != INS_LOAD_LANGUAGE_PACK) &&
           (ins != INS_COMMIT_LANGUAGE_PACK) &&
           (ins != INS_DEL_LANGUAGE_PACK) && (ins != INS_LIST_LANGUAGE_PACKS) &&
           (ins != INS_RESET) && (ins != INS_FACTORY_TEST) &&
           (ins != INS_GET_DEVICE_MAC)) {
    return SWO_APD_INS_06;
  }
  // global INS restriction when in onboarding state
  else if (((G_dashboard.dashboard_state == DASHBOARD_STATE_ONBOARDING)) &&
           (ins != INS_GET_VERSION) && (ins != INS_VALIDATE_TARGET_ID) &&
           (ins != INS_INITIALIZE_AUTHENTICATION) &&
           (ins != INS_VALIDATE_CERTIFICATE) && (ins != INS_GET_CERTIFICATE) &&
           (ins != INS_MUTUAL_AUTHENTICATE) && (ins != INS_SECURE_COMMAND) &&
           (ins != INS_GET_BATTERY_STATE) && (ins != INS_SET_MAX_BATT_PERC) &&
           (ins != INS_SET_SCREEN_SAVER) && (ins != INS_CREATE_LANGUAGE_PACK) &&
           (ins != INS_LOAD_LANGUAGE_PACK) &&
           (ins != INS_COMMIT_LANGUAGE_PACK) &&
           (ins != INS_DEL_LANGUAGE_PACK) && (ins != INS_LIST_LANGUAGE_PACKS)) {
    return SWO_APD_INS_07;
  } else if ((G_dashboard.dashboard_state !=
              DASHBOARD_STATE_NOT_PERSONALIZED) &&
             (G_dashboard.dashboard_state !=
              DASHBOARD_STATE_FACTORY_FINAL_TEST) &&
             (G_dashboard.dashboard_state != DASHBOARD_STATE_ONBOARDING) &&
             (G_dashboard.dashboard_state != DASHBOARD_STATE_DASHBOARD)) {
    return SWO_APD_INS_08;
  }

  return SWO_OK;
}

static void dashboard_task_core(void) {
  unsigned short volatile status_word = SWO_SUCCESS;
  unsigned int volatile exchange_length;
  unsigned int volatile output_length = 0;
  unsigned int volatile is_signed_and_not_recovery;
  unsigned int volatile is_onboarded;
  unsigned int volatile is_recovery = 0;

  for (;;) {
    dashboard_task_init();

    is_onboarded = os_perso_isonboarded();

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU. When APDU are to be fetched from multiple IOs,
    // like NFC+USB+BLE, make sure the io_event is called with a switch event,
    // before the apdu is replied to the bootloader. This avoid APDU injection
    // faults.
    for (;;) {
      BEGIN_TRY {
        TRY {
          // ensure reinit are processed
          // display is ready too soon in case of timeout on the host
          // application for usb. but that way, the display is not invalid
          if (G_dashboard.reinit_display) {
            G_dashboard.reinit_display = false;
            G_dashboard.reinit_display_on_error = false;

            is_signed_and_not_recovery =
                bolos_is_recovery() != BOLOS_TRUE &&
                bolos_is_signed_mcu_code() == BOLOS_TRUE;
            is_recovery = bolos_is_recovery();

            // if wiped, then restart the onboarding if not in recovery
            // if not signed mcu, just redisplay as well, don't throw
            if (G_dashboard.dashboard_state == DASHBOARD_STATE_DASHBOARD &&
                os_perso_isonboarded() != BOLOS_TRUE &&
                is_signed_and_not_recovery) {
              CLOSE_TRY;
              break;
            }

            // will be displayed asynch, don't wait for a UX_OK status
            G_ux_params.ux_id = G_dashboard.bolos_display;
            if (G_dashboard.selected_app != -1 &&
                G_dashboard.dashboard_state == DASHBOARD_STATE_DASHBOARD) {
              G_ux_params.len = sizeof(G_ux_params.u.select_app);
              G_ux_params.u.select_app.app_index = G_dashboard.selected_app;
              G_dashboard.selected_app = -1;
            } else {
              G_ux_params.len = 0;
            }
            os_ux_blocking(&G_ux_params);
          }

          // FLOW: perform pin check after
          // if pin is present and not validated, then revalidate it (due to
          // abort of install for example, when the pin is invalidated
          // beforehand) ROBUSTNESS check
          do {
            bolos_check_pin(&G_ux_params);
            // robustness, check again
          } while (os_perso_is_pin_set() == BOLOS_TRUE &&
                   os_global_pin_is_validated() != BOLOS_TRUE);

          exchange_length = output_length;
          // write only when the secure channel is operational
          if (exchange_length > 2 &&
              G_dashboard.transient_ctx.state == STATE_MUTUAL_AUTHENTICATED) {
            // pad and encrypt data
            // CIHERDATA SW
            // SW are trimmed and readded after padding

            size_t wrapped_length = 0;
            if (dashboard_scp_wrap(&G_dashboard.transient_ctx.secret.scp,
                                   G_io_apdu_buffer, exchange_length - 2,
                                   &wrapped_length)) {
              // Close SCP channel if an error occurs during wrapping.
              dashboard_scp_close(&G_dashboard.transient_ctx.secret.scp);
              G_dashboard.transient_ctx.state = STATE_TARGET_VALIDATED;
              THROW(SWO_UNIQUE_SCP_ERROR);
            }
            // set sw apps_nvram_begin
            exchange_length = wrapped_length;
            G_io_apdu_buffer[exchange_length] = status_word >> 8;
            G_io_apdu_buffer[exchange_length + 1] = status_word;
            exchange_length += 2;
          }
          output_length = 0;  // ensure no race in catch_other if io_exchange
                              // throws an error

          // make sure to protect sensitive zones during IOs
          os_deny_protected_flash();
          os_deny_protected_ram();

          G_io_app.io_flags = G_dashboard.flags;
          G_io_app.io_flags &= ~IO_FINISHED;
          G_io_app.apdu_length = exchange_length;
          // until the io_exchange call is not finished, yield
          while (!(G_io_app.io_flags & IO_FINISHED)) {
            // onboarding ifnished
            if (os_perso_isonboarded() == BOLOS_TRUE &&
                is_onboarded != BOLOS_TRUE && is_recovery != BOLOS_TRUE) {
              G_dashboard.bolos_display = BOLOS_UX_DASHBOARD;
              G_dashboard.dashboard_state = DASHBOARD_STATE_DASHBOARD;
            }

            os_sched_yield(BOLOS_TRUE);

            // check io task status before yielding in case IO request has not
            // finished
            if (os_sched_last_status(TASK_SUBTASKS_START) ==
                EXCEPTION_IO_RESET) {
              THROW(SWO_IOL_RST_05);
            }
          }

          exchange_length = G_io_app.apdu_length;
          G_io_app.apdu_length = 0;
          G_dashboard.flags = 0;
          status_word = SWO_SUCCESS;  // default is ok

          if (G_dashboard.transient_ctx.state == STATE_MCU_RDP2_THEN_RESET) {
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_MCU;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_MCU_TYPE_PROTECT;
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
            G_dashboard.transient_ctx.state = STATE_SE_RESET;
          }

          if (G_dashboard.transient_ctx.state == STATE_SE_RESET) {
            bolos_err_t err = SWO_OK;
            if ((err = os_watchdog_arm(((200 /*ms*/)) * 1000UL,
                                       OS_WATCHDOG_NOACTION))) {
              THROW(err);
            }
            while (os_watchdog_value())
              ;
            io_seph_ble_enable(0);
            io_seproxyhal_disable_io();
            io_seproxyhal_se_reset();
            for (;;)
              ;
          }

          // run the application as requested
          if (G_dashboard.transient_ctx.state == STATE_RUN_APP) {
            // reset ux before any command sending to avoid lockups
            G_ux_params.len = 0;
            G_ux_params.ux_id = BOLOS_UX_PREPARE_RUN_APP;
            os_ux_blocking(&G_ux_params);

            // just in case
            io_seproxyhal_disable_io();

            // run the app
            os_sched_exec(G_dashboard.run_index);
          }

          // now upgrader is run as a n upgrade app, so it must not try to jump
          // back into the currently loaded app, or it's the infinite loop
          // problem here :D jump in the upgrade code
          if (bolos_registry_is_upgrade_app_ready() == BOLOS_TRUE) {
            // force the user to power cycle before processing the upgrade
            io_seproxyhal_se_reset();
            for (;;)
              ;
          }

          // avoid overflows
          if (exchange_length > sizeof(G_io_apdu_buffer)) {
            THROW(SWO_SEC_CHK_02);
          }

          // no apdu received, well, reset the session, and reset the bootloader
          // configuration
          if (exchange_length == 0) {
            THROW(SWO_SEC_CHK_03);
          }

          if (G_io_apdu_buffer[APDU_OFF_CLA] != CLA) {
            THROW(SWO_APD_CLA_01);
          }

          bolos_err_t err =
              dashboard_is_instruction_allowed(G_io_apdu_buffer[APDU_OFF_INS]);
          if (err != SWO_OK) {
            THROW(err);
          } else {
            size_t apdu_output_len = 0;
            err = dashboard_handle_apdu(G_io_apdu_buffer, exchange_length,
                                        &apdu_output_len);
            if (err) {
              status_word = (unsigned short)err;
              output_length = 0;
              // redisplay the default screen (kill the current load sequence
              // which may have failed)
              G_dashboard.reinit_display = G_dashboard.reinit_display_on_error;
            } else {
              output_length = apdu_output_len;
            }
          }
        }
        CATCH(SWO_IOL_RST_05) {
          // ensure cleaning the display (if still in a consent, but it's
          // unlikely) do it only if onboarding is really ended (all screens)
          if (bolos_get_onboarding_state() == ONBOARDING_STATUS_READY) {
            G_dashboard.reinit_display = true;
          }
          output_length = 0;

          dashboard_restart_iotask();

          // clean the security context
          memset(&G_dashboard.transient_ctx, 0,
                 sizeof(G_dashboard.transient_ctx));
          // io link reset detected. reset the communication channels
          G_dashboard.transient_ctx.state = STATE_BOOT;

          // skip the finally and wait for next apdu immediately
          continue;
        }
        //#error FIND A WAY FOR IO_TASK TO NOTIFY BOLOS TO RESET
        // EXCEPTION_IO_RESET is returned through the yield status
        CATCH_OTHER(e) {
          if (e != SWO_SUCCESS) {
            // redisplay the default screen (kill the current load sequence
            // which may have failed)
            G_dashboard.reinit_display = G_dashboard.reinit_display_on_error;
          }
          // In any case, we send back the received error code.
          status_word = e;
        }
        FINALLY {
          // Unexpected exception => security erase
          G_io_apdu_buffer[output_length] = status_word >> 8;
          G_io_apdu_buffer[output_length + 1] = status_word;
          output_length += 2;
          // error detected !!
          if (status_word != SWO_SUCCESS) {
            /// BEGIN WIPE STATE
            // wipe the session (key, state, etc)
            memset(&G_dashboard.transient_ctx, 0,
                   sizeof(G_dashboard.transient_ctx));
            /// END WIPE STATE
          }
        }
      }
      END_TRY;
    }
  }
}

void init_task(void) __attribute__((alias("dashboard_task")));

void dashboard_task(void) {
  // setup the task stack pointer
  __set_PSP((uint32_t)&_estack_app);

  // ensure the stack pointer is set before jumping into the bolos task to
  // avoid the sp being set after the locals have been reserved by a stack
  // decrement.
  dashboard_task_core();
}