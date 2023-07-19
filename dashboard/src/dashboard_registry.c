/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <string.h>

#include "bolos_privileged.h"
#include "bolos_privileged_mem.h"
#include "bolos_privileged_ux.h"

#include "cx_ecdsa_internal.h"

#include "dashboard_constants.h"
#include "dashboard_prototypes.h"
#include "dashboard_ram.h"

#include "errors.h"
#include "exceptions.h"

#include "bolos.h"
#include "bolos_ux.h"
#include "check_language_pack.h"
#include "cx_sha256.h"
#include "lcx_aes.h"
#include "lcx_ecdsa.h"
#include "os.h"
#include "os_apdu.h"
#include "os_helpers.h"
#include "os_io.h"
#include "os_io_seproxyhal.h"
#include "os_nvm.h"
#include "os_registry.h"
#include "os_types.h"
#include "os_utils.h"
#include "os_ux.h"

#define VERSION "dummy"

// Return the total length of the input app.
// An error is raised if an overflow is detected.
static unsigned int compute_app_length(const application_t* app) {
  unsigned int len = app->code_length;

  if (app->data_length > UINT32_MAX - len) {
    THROW(SWO_SEC_APP_21);
  } else {
    len += app->data_length;
  }

  if (app->params_length > UINT32_MAX - len) {
    THROW(SWO_SEC_APP_21);
  } else {
    len += app->params_length;
  }

  return len;
}

// This function fetches the icon from the NVM to-be-installed
// application by successive blocks and sends it to the UX application.
static void dashboard_stream_icon(application_t* current_application) {
  uint8_t* tlv_icon;
  void* output_address;

  // First we retrieve the length of the icon.
  G_ux_params.u.icon_stream.icon_stream_total_length =
      os_parse_installparam_tlv(current_application, NULL, BOLOS_TAG_ICON,
                                OS_REGISTRY_GET_TAG_OFFSET_GET_LENGTH | 0,
                                (void**)&tlv_icon, 0);

  // Then we initialize the global shared RAM.
  G_ux_params.u.icon_stream.icon_stream_first = BOLOS_TRUE;
  G_ux_params.u.icon_stream.icon_stream_last = BOLOS_FALSE;
  G_ux_params.u.icon_stream.icon_stream_block_length = 0;
  G_ux_params.u.icon_stream.icon_stream_block_offset = 0;
  output_address = (void*)&G_ux_params.u.icon_stream.icon_stream_block;

  // And we stream the icon.
  do {
    G_ux_params.u.icon_stream.icon_stream_block_length =
        os_parse_installparam_tlv(
            current_application, NULL, BOLOS_TAG_ICON,
            G_ux_params.u.icon_stream.icon_stream_block_offset, &output_address,
            ICON_STREAM_BLOCK_LEN_B);

    // We indicate whether the block is the last.
    if ((G_ux_params.u.icon_stream.icon_stream_block_offset +
         G_ux_params.u.icon_stream.icon_stream_block_length) >=
        G_ux_params.u.icon_stream.icon_stream_total_length) {
      G_ux_params.u.icon_stream.icon_stream_last = BOLOS_TRUE;
    }

    // We set these information right before the call to the UX application
    // because its yields might change the id and length in between the current
    // internal dashboard processing.
    G_ux_params.ux_id = BOLOS_UX_ICON_STREAM;
    G_ux_params.len = sizeof(G_ux_params.u.icon_stream);

    // We send the information to the UX application.
    os_ux(&G_ux_params);

    // We prepare for the next block if necessary.
    G_ux_params.u.icon_stream.icon_stream_first = BOLOS_FALSE;
    G_ux_params.u.icon_stream.icon_stream_block_offset +=
        G_ux_params.u.icon_stream.icon_stream_block_length;

  } while (G_ux_params.u.icon_stream.icon_stream_block_offset <
           G_ux_params.u.icon_stream.icon_stream_total_length);
}

// This function looks for, and copies, the required information from the
// NVM install parameters of the to-be-installed application (which data
// are already stored in NVM even if the registry is not yet updated).
static unsigned int dashboard_get_app_info(application_t* current_application,
                                           unsigned int tag,
                                           void* buffer,
                                           unsigned int max_length) {
  void** buffer_address = &buffer;
  return os_parse_installparam_tlv(current_application, NULL, tag, 0,
                                   buffer_address, max_length);
}

void dashboard_app_ux_processing(void) {
  // the UX has changed to processing, need to reset the display to dashboard
  // upon error
  G_dashboard.reinit_display_on_error = true;
}

void dashboard_update_progress_bar(unsigned int chunk_length) {
  unsigned int former_length =
      (unsigned int)(G_dashboard.transient_ctx.load_address -
                     (unsigned int)G_dashboard.transient_ctx.current_application
                         .nvram_begin);
  unsigned int loaded_length = former_length + chunk_length;

  // The total installation length is not the number of blocks, but really the
  // to-be-copied data length.
  unsigned int total_length =
      G_dashboard.transient_ctx.current_application.code_length +
      G_dashboard.transient_ctx.current_application.data_length +
      G_dashboard.transient_ctx.current_application.params_length;

  // We want to split into different displays across the loading of the
  // application.
  unsigned int percentage_ranges_split = 20;
  unsigned int former_percentage_range =
      (percentage_ranges_split * former_length) / total_length;
  unsigned int loaded_percentage_range =
      (percentage_ranges_split * loaded_length) / total_length;

  if (loaded_percentage_range < (percentage_ranges_split - 1)) {
    G_io_app.transfer_mode = 1;
  } else {
    G_io_app.transfer_mode = 0;
  }

  // We don't want to update the UI at each APDU processing, otherwise it will
  // consume too much resources. We want to update the display either when the
  // percentage is 0, or when a given step is reached.
  if ((!former_length) || (loaded_percentage_range > former_percentage_range)) {
    // A distinction is made between regular applications and OSU loading.
    if ((G_dashboard.transient_ctx.current_application.flags &
         (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER)) ==
        (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER)) {
      G_ux_params.ux_id = BOLOS_UX_DOWNLOAD_OSU;
      G_ux_params.len = sizeof(G_ux_params.u.download_osu);
      G_ux_params.u.download_osu.percent =
          (unsigned short)((100 * loaded_length) / total_length);
    } else {
      G_ux_params.ux_id = BOLOS_UX_INSTALL_APP_PROGRESS_BAR;
      G_ux_params.len = sizeof(G_ux_params.u.progress_bar);
      G_ux_params.u.progress_bar.mode = PROGRESS_BAR_MODE_LOAD;
      G_ux_params.u.progress_bar.percent =
          (unsigned short)((100 * loaded_length) / total_length);
      if (G_dashboard.transient_ctx.current_application.flags &
          APPLICATION_FLAG_BOLOS_UPGRADE) {
        G_ux_params.u.progress_bar.type = PROGRESS_BAR_TYPE_OSU_INSTALL;
      } else if (G_dashboard.transient_ctx.current_application.flags &
                 APPLICATION_FLAG_LANGUAGE_PACK) {
        G_ux_params.u.progress_bar.type = PROGRESS_BAR_TYPE_LANG_INSTALL;
      } else if (G_dashboard.transient_ctx.current_application.flags &
                 APPLICATION_FLAG_BACKGROUND_IMG) {
        G_ux_params.u.progress_bar.type = PROGRESS_BAR_TYPE_BACKGND_IMG;
      } else {
        G_ux_params.u.progress_bar.type = PROGRESS_BAR_TYPE_APP_INSTALL;
      }
    }

    // The UX will block while the display has not been entirely done, but it
    // will be fast enough for our needs.
    os_ux_blocking(&G_ux_params);
  }
}

static int get_app_slot(const application_t* app,
                        unsigned int* app_slot,
                        uint8_t** start_addr) {
  // grab the application total size
  unsigned int len = compute_app_length(app);
  unsigned int align = bootloader_align_app(&len);

  // start placing the app at the start of nvram container. increase that
  // address if apps are already present there
  *app_slot = APPLICATION_MAXCOUNT;

  // find the application with the highest address (apps are compacted at delete
  // time)
  unsigned int num_entries = os_registry_count();
  if ((app->flags &
       (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_BOLOS_UPGRADE)) ==
      (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_BOLOS_UPGRADE)) {
    // Registry has been wiped before for the OSU
    *start_addr = (unsigned char*)UPPER_ALIGN(
        ((size_t)&_bootloader_apps_nvram_end) - len, align, size_t);
    if (((size_t)*start_addr >= ((size_t)&_bootloader_apps_nvram_begin)) &&
        ((size_t)*start_addr <= ((size_t)&_bootloader_apps_nvram_end))) {
      *app_slot = 0;
    } else {
      return -1;
    }
  } else if (num_entries < APPLICATION_MAXCOUNT) {
    // Free entry found
    if (num_entries) {
      *start_addr =
          N_application_registry.applications[num_entries - 1].nvram_end + 1;
    } else {
      *start_addr = (unsigned char*)UPPER_ALIGN(
          (size_t)&_bootloader_apps_nvram_begin, align, size_t);
    }
    *app_slot = num_entries;
  } else {
    return -1;
  }

  // not enough place remaining to fit the application?
  if ((size_t)&_bootloader_apps_nvram_end - (size_t)*start_addr < len) {
    return -1;
  }
  return 0;
}

size_t dashboard_create_slot(unsigned int flags,
                             unsigned int code_length,
                             unsigned int data_length,
                             unsigned int params_length,
                             appmain_t boot_offset,
                             const uint8_t* apdu_buffer) {
  uint8_t param_off = APDU_SECURE_DATA_OFF;
  uint8_t param_len = LC_SECURE_CREATE_APP - 1;
  // set the waiting screen
  dashboard_app_ux_processing();

  // delay the power-off/lock timers of 1min
  G_ux_params.ux_id = BOLOS_UX_DELAY_LOCK;
  G_ux_params.u.lock_delay.delay_ms = 60 * 1000;
  G_ux_params.len = sizeof(G_ux_params.u.lock_delay);
  os_ux_blocking(&G_ux_params);

  dashboard_ctx* ctx = &G_dashboard.transient_ctx;
  application_t* app = &ctx->current_application;
  memset(app, 0,
         sizeof(application_t));  // wipe the current application structure

  // grab requested flags, discarding automatically authentication flags to
  // avoid security breach
  app->code_length = code_length;
  app->data_length = data_length;
  app->params_length = params_length;

  // mask off security flags
  app->flags =
      ctx->auth_source_flags |
      ((flags & (~(APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_CUSTOM_CA |
                   APPLICATION_FLAG_SIGNED))) &
       APPLICATION_FLAGS_MASK);
  app->main = (appmain_t)boot_offset;

  if ((int)app->code_length < 0 || (int)app->data_length < 0 ||
      (int)app->params_length < 0) {
    THROW(SWO_APD_DAT_08);
  }

  // cannot load an upgrade without being auth as issuer
  if ((app->flags &
       (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_BOLOS_UPGRADE)) ==
      APPLICATION_FLAG_BOLOS_UPGRADE) {
    THROW(SWO_APD_STA_17);
  }

  // initialize the loaded data hash (context will be used to produce both
  // code_data and install_params hashes)
  cx_sha256_init_no_throw(&ctx->load_hash_ctx);
  cx_sha256_init_no_throw(&ctx->load_hash_code_data_ctx);

  // update full hash (signed one) with target id and target version
  // (not used with language packs/background img)
  if (apdu_buffer) {
    cx_sha256_update(&ctx->load_hash_ctx, U_bolos_target_id,
                     sizeof(U_bolos_target_id));
    // only add FW version to the hash computation of an upgrade
    // as an app holds no reference to a firmware version
    if (app->flags & APPLICATION_FLAG_BOLOS_UPGRADE) {
      cx_sha256_update(&ctx->load_hash_ctx, (const uint8_t*)VERSION,
                       strlen(VERSION));
      // skip the API Level in upgrade hash computation
      param_off += 1;
      param_len -= 1;
    }
    // update full hash with create app parameters (the full hash will be the
    // signed one)
    cx_sha256_update(&ctx->load_hash_ctx, apdu_buffer + param_off, param_len);
  }

  // no check when no data section declared (alignment won't disturb page upon
  // erasure as there won't be any erasure)
  if (app->data_length > 0) {
    // check for correct alignment of the data_section to avoid loosing some
    // code due to tearing effect of on the first page of data
    if (app->code_length != bootloader_align_page(app->code_length)) {
      THROW(SWO_APD_DAT_09);
    }

    // check for correct alignment of the install parameters against data to
    // avoid loosing install params due to tearing in data section
    if (app->code_length + app->data_length !=
        bootloader_align_page(app->code_length + app->data_length)) {
      THROW(SWO_APD_DAT_0A);
    }
  }

  // wipe registry when requesting to load an OSU. to always ensure sufficient
  // space is present (don't care the tearing during osu load. the user would
  // redo it afterwards) only do that when the scp is opened by the issuer !
  if ((app->flags &
       (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_BOLOS_UPGRADE)) ==
      (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_BOLOS_UPGRADE)) {
    os_registry_wipe();
  }

  // can't add bolos_ux if not in recovery (missing bolos_ux init when called
  // with a consent)
  if (app->flags & APPLICATION_FLAG_BOLOS_UX) {
    if (bolos_is_recovery() != BOLOS_TRUE) {
      THROW(SWO_APD_STA_19);
    }
    // avoid installing multiple UX apps
    unsigned int i = os_registry_count();
    while (i--) {
      if (N_application_registry.applications[i].flags &
          APPLICATION_FLAG_BOLOS_UX) {
        THROW(SWO_SEC_APP_01);
      }
    }
  }

  uint8_t* start_address = NULL;
  if (get_app_slot(app, &ctx->current_application_index, &start_address)) {
    THROW(SWO_SEC_APP_02);
  }

  app->nvram_begin = start_address;

  // use the len size and not all the free size
  unsigned int len = compute_app_length(app);
  bootloader_align_app(&len);
  app->nvram_end = app->nvram_begin + len - 1;

  // compute offset of main within the application, now that we know the
  // effective load address
  app->main = (appmain_t)((size_t)app->nvram_begin + (size_t)app->main);
  // ensure main is in the loaded region, avoid calling code from someone else
  // :D
  if ((size_t)app->main < (size_t)app->nvram_begin ||
      (size_t)app->main >= (size_t)app->nvram_begin + app->code_length) {
    THROW(SWO_SEC_APP_04);
  }
  // erase the nvram memory corresponding to the application to be loaded, to
  // avoid data leak from previous apps installation. TEARING: redone if teared
  os_nvm_set(app->nvram_begin, 0, len);

  return 0L;
}

size_t dashboard_load_chunk(uint8_t* chunk_ptr,
                            size_t chunk_length,
                            unsigned int offset,
                            bool secure) {
  size_t max_params_addr;
  size_t out_len;
  unsigned char tmp_iv[CX_AES_BLOCK_SIZE];
  dashboard_ctx* ctx = &G_dashboard.transient_ctx;
  application_t* app = &ctx->current_application;

  if (app->nvram_begin == NULL) {
    THROW(SWO_SEC_APP_06);
  }

  if (secure && ctx->state != STATE_MUTUAL_AUTHENTICATED) {
    THROW(SWO_APD_STA_12);
  }

  // decrypt using NEK if upgrade bit is set
  if (secure && chunk_length &&
      (app->flags & (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER |
                     APPLICATION_FLAG_CUSTOM_CA)) ==
          (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER)) {
    // malformed data ?
    if ((chunk_length < CX_AES_BLOCK_SIZE) ||
        (chunk_length % CX_AES_BLOCK_SIZE)) {
      THROW(SWO_APD_LEN_0D);
    }
    // hold next iv
    memcpy(tmp_iv, chunk_ptr + chunk_length - CX_AES_BLOCK_SIZE,
           CX_AES_BLOCK_SIZE);

    os_allow_protected_flash();
    // assert decrypted length is expected.
    out_len = chunk_length;
    if (bolos_aes_decrypt_with_code_key(
            ctx->secret.scp.nek_iv, CX_AES_BLOCK_SIZE, chunk_ptr, chunk_length,
            chunk_ptr, &out_len) != CX_OK ||
        out_len != chunk_length) {
      THROW(SWO_APD_LEN_0E);
    }
    os_deny_protected_flash();
    // output next iv
    memcpy(ctx->secret.scp.nek_iv, tmp_iv, CX_AES_BLOCK_SIZE);
  }

  ctx->load_address = (unsigned int)((size_t)app->nvram_begin + offset);

  // check for loading out of the defined area (and ensure loading is correct
  // with created application)
  if (ctx->load_address + chunk_length > (size_t)app->nvram_end + 1 ||
      ctx->load_address < (size_t)&_bootloader_apps_nvram_begin ||
      (size_t)app->nvram_end > (size_t)&_bootloader_apps_nvram_end ||
      ctx->load_address + chunk_length > (size_t)&_bootloader_apps_nvram_end ||
      ctx->load_address < (size_t)app->nvram_begin) {
    THROW(SWO_APD_DAT_0B);
  }

  // update code+data hash (if at least a piece of loaded data lies within the
  // code or data section)
  max_params_addr =
      (size_t)app->nvram_begin + app->code_length + app->data_length;
  if (ctx->load_address < max_params_addr) {
    // only hash the piece overlapping code+data (ignore the install params)
    cx_sha256_update(&ctx->load_hash_code_data_ctx, chunk_ptr,
                     MIN(chunk_length, max_params_addr - ctx->load_address));
  }

  // update full hash
  cx_sha256_update(&ctx->load_hash_ctx, chunk_ptr, chunk_length);

  // write data
  os_nvm_write((unsigned char*)ctx->load_address, chunk_ptr, chunk_length);

  dashboard_update_progress_bar(chunk_length);

  // No output.
  return 0L;
}

bool dashboard_commit_check_signature(const uint8_t* sig,
                                      unsigned int sig_len,
                                      const cx_ecfp_public_key_t* public_key) {
  bool result;
  dashboard_ctx* ctx = &G_dashboard.transient_ctx;
  application_t* app = &ctx->current_application;

  // Security check.
  if (app->nvram_begin == NULL) {
    THROW(SWO_SEC_CHK_01);
  }
  os_allow_protected_flash();
  result = cx_ecdsa_internal_verify(public_key, app->sha256_full,
                                    CX_SHA256_SIZE, sig, sig_len);
  os_deny_protected_flash();

  return result;
}

bolos_err_t dashboard_commit_finalize(void) {
  bolos_err_t err = SWO_OK;
  dashboard_ctx* ctx = &G_dashboard.transient_ctx;
  application_t* app = &ctx->current_application;

  // complement flags before storage
  app->flags = GET_COMPLEMENTED_APPLICATION_FLAGS(app->flags);

  // write the address of the main (using the given offset and the load memmory
  // (PIC compliance)) to be done in called code // ramconf.vtor =
  // (appmain_t)U4BE(apdu_buffer, 6+4);

  // write the app slot and the crc value
  os_nvm_write(
      &N_application_registry.applications[ctx->current_application_index], app,
      sizeof(application_t));
  uint16_t crc16 = STRUCT_CRC16(N_application_registry);
  os_nvm_write(&N_application_registry.crc, &crc16,
               sizeof(N_application_registry.crc));

  if (app->flags & APPLICATION_FLAG_LANGUAGE_PACK) {
    uint16_t error;
    LANGUAGE_PACK* lp = (LANGUAGE_PACK*)(app->nvram_begin);

    PRINTF(
        "Inside dashboard_commit_finalize, flags=0x%04X, nvram_begin=%p, "
        "nvram_end=%p, code_lenth=%d, data_length=%d, params_length=%d\n",
        app->flags, app->nvram_begin, app->nvram_end, app->code_length,
        app->data_length, app->params_length);

    // Check it is a valid language pack
    if (!(error = check_language_pack(lp, app->code_length))) {
      // Let the OS know we want to switch to this language
      set_os_language(lp->language);

      PRINTF("Inside dashboard_commit_finalize, called set_os_language(%d)\n",
             lp->language);
    } else {
      PRINTF(
          "Inside dashboard_commit_finalize, the language pack is invalid => "
          "we will delete it!");
      if ((err =
               dashboard_delete_slot(ctx->current_application_index, false))) {
        return err;
      }
      ctx->current_application_index = -1;
      // the UX has changed to processing, need to reset the display to
      // dashboard upon error
      dashboard_app_ux_processing();
      return (SWO_SEC_CHK_1C + error - 1);  // Error start at 1
    }
  }

  // wipe to avoid strange calls to registry_get_icon at another moment
  memset(app, 0, sizeof(application_t));

  // from now on, the application can boot, prepare a new loader to take action
  // into
  G_dashboard.selected_app = ctx->current_application_index;
  G_dashboard.reinit_display = true;

  // avoid use of loader until the app is selected by update_app or create_app.
  ctx->current_application_index = -1;
  app->nvram_begin = NULL;
  return err;
}

bolos_err_t dashboard_apdu_secure_commit(uint8_t* apdu_buffer,
                                         size_t in_length,
                                         size_t* out_length) {
  bolos_err_t err = SWO_OK;
  bolos_bool_t crc;
  unsigned char* tlv_data;
  unsigned int tlv_len;
  unsigned int depi;
  unsigned int i;
  unsigned char found;
  // Offset of the byte containing the signature len, in apdu_buffer
  uint8_t sig_offset = 5 + 1;

  // without signature
  if (in_length != 1) {
    // with signature
    if (in_length < 1 + 1 || in_length != 1U + 1U + apdu_buffer[sig_offset]) {
      return SWO_APD_LEN_11;
    }
  }
  dashboard_ctx* ctx = &G_dashboard.transient_ctx;
  application_t* app = &ctx->current_application;
  if (app->nvram_begin == NULL) {
    return SWO_SEC_APP_09;
  }

  if (ctx->state != STATE_MUTUAL_AUTHENTICATED) {
    return SWO_APD_STA_13;
  }

  // finalize hashes
  cx_hash_no_throw((cx_hash_t*)&ctx->load_hash_code_data_ctx, CX_LAST, NULL, 0,
                   app->sha256_code_data, CX_SHA256_SIZE);

  cx_hash_no_throw((cx_hash_t*)&ctx->load_hash_ctx, CX_LAST, NULL, 0,
                   app->sha256_full, CX_SHA256_SIZE);

  // check signature for upgrade as well
  // finalize and check signature if a signature has been provided with.
  if (in_length >= 1 + 1) {
    const cx_ecfp_public_key_t* public_key = NULL;
    bool signature_verified = false;
    // upgrade are signed with the const code signing key
    if ((app->flags &
         (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER)) ==
        (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER)) {
      public_key = &U_secure_element_codesign_public_key;
    } else {
      // check issuer's signature,MUST BE top level to avoid intermediate signer
      // certificate forgery if SCP opened with custom ca => then don't check
      // with hsm key to avoid potential wipe. prefer a load error instead
      if ((app->flags & APPLICATION_FLAG_CUSTOM_CA) !=
          APPLICATION_FLAG_CUSTOM_CA) {
        // legacy use the hsm key to check app signature
        public_key =
            &N_secure_element_nvram_factory_settings.batch_signer_public;
      }
    }
    if (public_key && (signature_verified = dashboard_commit_check_signature(
                           apdu_buffer + sig_offset + 1,
                           apdu_buffer[sig_offset], public_key))) {
      app->flags |= APPLICATION_FLAG_SIGNED;
    } else {
      if ((err = bolos_check_crc_consistency(CRC_CUSTOM_CA, &crc))) {
        return err;
      }
      if (BOLOS_TRUE == crc) {
        public_key = &N_secure_element_nvram_customca_settings.ca_public;
        if ((signature_verified = dashboard_commit_check_signature(
                 apdu_buffer + sig_offset + 1, apdu_buffer[sig_offset],
                 public_key))) {
          app->flags |= APPLICATION_FLAG_SIGNED | APPLICATION_FLAG_CUSTOM_CA;
        }
      }
    }
    if (!signature_verified) {
      if (public_key) {
        // Signature is invalid
        return SWO_SEC_SIG_0A;
      } else {
        // application is NOT verified with the given signature
        return SWO_SEC_SIG_0B;
      }
    }
  }
  // can't upgrade without a signature
  else if (app->flags & APPLICATION_FLAG_BOLOS_UPGRADE) {
    return SWO_APD_STA_1A;
  }

  // wipe the hsm second cert when application is loaded without the ISSUER flag
  // or not SIGNED
  if (
      // issuer scp + issuer signature
      (app->flags & (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_SIGNED |
                     APPLICATION_FLAG_CUSTOM_CA)) !=
          (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_SIGNED)
      // issuer scp
      &&
      (app->flags & (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_SIGNED |
                     APPLICATION_FLAG_CUSTOM_CA)) != (APPLICATION_FLAG_ISSUER)
      // issuer signed and foreign key load
      && (app->flags & (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_SIGNED |
                        APPLICATION_FLAG_CUSTOM_CA)) !=
             (APPLICATION_FLAG_SIGNED)) {
    if ((err = bolos_check_crc_consistency(CRC_FACTORY_2, &crc))) {
      return err;
    } else if (crc == BOLOS_TRUE) {
      if ((err = bolos_factory_settings_wipe(FACTORY_SETTINGS_SLOT_2))) {
        return err;
      }
    }
  }

  // upgrade the antitearing entry: upgrade application are not entered into the
  // registry as they only perform once and are discarded after wards (or patch
  // the code to avoid loading over the zone where they are loaded). upgrade
  // must be signed by issuer, not by customca.
  if ((app->flags & (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_BOLOS_UPGRADE |
                     APPLICATION_FLAG_SIGNED | APPLICATION_FLAG_CUSTOM_CA)) ==
      (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_BOLOS_UPGRADE |
       APPLICATION_FLAG_SIGNED)) {
    // DESIGN NOTE: upgrades are not meant to express dependencies

    // enable the application slot to enable tag extraction from its tlv zone
    app->flags |= APPLICATION_FLAG_ENABLED;

    // ask_user_consent if user_settings are not wiped
    G_ux_params.ux_id = BOLOS_UX_CONSENT_UPGRADE;

    // The name tag actually contains the version, for upgrades.
    memset(G_ux_params.u.upgrade.version, 0x00,
           sizeof(G_ux_params.u.upgrade.version));
    G_ux_params.u.upgrade.version_length = dashboard_get_app_info(
        app, BOLOS_TAG_APPNAME, (void*)&G_ux_params.u.upgrade.version,
        sizeof(G_ux_params.u.upgrade.version));

    G_ux_params.len = sizeof(G_ux_params.u.upgrade);

    // We don't check the PIN when upgrading the firmware, hence the last
    // parameter's value.
    if ((err = bolos_check_consent(&G_ux_params,
                                   &G_dashboard.reinit_display_on_error,
                                   G_dashboard.bolos_display, 0))) {
      return err;
    }
    bolos_registry_upgrade_app_init(app->main);

    // ensure replying gently to the user interface before going through the
    // upgrade
    G_dashboard.flags |= IO_RETURN_AFTER_TX;
    // make sure to reset after reply has been sent to jump into the loaded code
    ctx->state = STATE_SE_RESET;
    *out_length = 0L;
    return err;
  }

  if (app->flags & APPLICATION_FLAG_BOLOS_UPGRADE) {
    return SWO_APD_STA_1C;
  }

  // ensure application has a version ?
  // ensure application has an icon ?

  // ensure application has a name
  if ((tlv_len =
           os_parse_installparam_tlv(app, NULL, BOLOS_TAG_APPNAME,
                                     OS_REGISTRY_GET_TAG_OFFSET_GET_LENGTH | 0,
                                     (void**)&tlv_data, 0)) == 0) {
    // no name found :(
    return SWO_APD_DAT_0D;
  }

  // arbitrary max application name size to avoid OOB in other os's parts
  if (tlv_len > BOLOS_APPNAME_MAX_SIZE_B) {
    return SWO_APD_LEN_12;
  }

  // ensure another app with the same hash is not yet installed
  i = os_registry_count();
  while (i--) {
    // check if the application hash conflict
    if (memcmp(N_application_registry.applications[i].sha256_full,
               app->sha256_full, sizeof(app->sha256_full)) == 0) {
      return SWO_APD_DAT_0E;
    }
    // compare name with the newly installed application
    if (os_parse_installparam_tlv(
            &N_application_registry.applications[i], NULL, BOLOS_TAG_APPNAME,
            OS_REGISTRY_GET_TAG_OFFSET_COMPARE_WITH_BUFFER | 0,
            (void**)&tlv_data, tlv_len) == 1) {
      return SWO_APD_DAT_0F;
    }
  }

  // check dependencies requirements if dependencies are expressed to avoid
  // installing an app which dependencies are missing
  depi = 0;  // offset in the install params, to read all dependency occurences
  for (;;) {
    tlv_data = apdu_buffer + 1;
    apdu_buffer[0] = os_parse_installparam_tlv(
        app, &depi, BOLOS_TAG_DEPENDENCY, 0,
        // use apdu buffer to read the dependency structure
        (void**)&tlv_data, IO_APDU_BUFFER_SIZE - 0x01);
    depi++;  // won't reread the same entry, we've likely read the whole content
             // at once
    // no more tag found
    if (apdu_buffer[0] == 0) {
      break;
    }
    // malformed dependency, at least L and V appname
    if (apdu_buffer[0] < 2) {
      continue;
    }

    // check if any application has such a name and version, else THROW
    found = 0;
    i = os_registry_count();
    while (i--) {
      // compare name with the newly installed application dependency
      tlv_len = apdu_buffer[1];
      tlv_data = apdu_buffer + 1 + 1;
      if (os_parse_installparam_tlv(
              &N_application_registry.applications[i], NULL, BOLOS_TAG_APPNAME,
              OS_REGISTRY_GET_TAG_OFFSET_COMPARE_WITH_BUFFER | 0,
              (void**)&tlv_data, tlv_len) != 1) {
        continue;
      } else {
        if (apdu_buffer[0] > apdu_buffer[1] + 1) {
          tlv_len = apdu_buffer[1 + 1 + apdu_buffer[1]];
          tlv_data = apdu_buffer + 1 + 1 + apdu_buffer[1] + 1;
          if (os_parse_installparam_tlv(
                  &N_application_registry.applications[i], NULL,
                  BOLOS_TAG_APPVERSION,
                  OS_REGISTRY_GET_TAG_OFFSET_COMPARE_WITH_BUFFER | 0,
                  (void**)&tlv_data, tlv_len) != 1) {
            continue;
          }
        }
        // check dependency has not a lower security level as ours (else deny
        // it)
        switch (app->flags &
                (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_CUSTOM_CA |
                 APPLICATION_FLAG_SIGNED)) {
          // loaded from custom ca AND issuer at once => impossible
          case APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_CUSTOM_CA:
            // loaded via custom_ca, and given a hsm signature => not taken into
            // account (product limitation)
          case APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_CUSTOM_CA |
              APPLICATION_FLAG_SIGNED:
            return SWO_APD_DAT_10;

            // loaded using custom ca
          case APPLICATION_FLAG_CUSTOM_CA:
            // loaded using custom and given either a issuer signature OR a
            // custom ca signature
          case APPLICATION_FLAG_CUSTOM_CA | APPLICATION_FLAG_SIGNED:
            // if the is not ISSUER or CUSTOM_CA then deny
            if ((N_application_registry.applications[i].flags &
                 (APPLICATION_FLAG_SIGNED | APPLICATION_FLAG_CUSTOM_CA |
                  APPLICATION_FLAG_ISSUER)) == 0) {
              return SWO_SEC_APP_0A;
            }
            break;

            // loaded via hsm
          case APPLICATION_FLAG_ISSUER:
            // loaded with foreign and given a hsm signature
          case APPLICATION_FLAG_SIGNED:
            // loaded with hsm, and given a hsm signature
          case APPLICATION_FLAG_SIGNED | APPLICATION_FLAG_ISSUER:
            // the dependency MUST be ISSUER or SIGNED only (no custom CA)
            if ((N_application_registry.applications[i].flags &
                 (APPLICATION_FLAG_SIGNED | APPLICATION_FLAG_ISSUER)) == 0
                // if custom ca is set then the dependency has not been loaded
                // only by the issuer (or signed by the issuer => probably
                // signed by the customca)
                ||
                (N_application_registry.applications[i].flags &
                 (APPLICATION_FLAG_CUSTOM_CA)) == APPLICATION_FLAG_CUSTOM_CA) {
              return SWO_SEC_APP_0B;
            }
            break;

            // foreign, not signed
          default:
            // no condition on the dependency, the new app IS the untrusted
            // piece
            break;
        }
        found = 1;
        break;
      }
    }

    if (!found) {
      return SWO_APD_DAT_11;
    }
  }

  // set application slot enabled before consent to allow for icon to be
  // displayed
  app->flags |= APPLICATION_FLAG_ENABLED;

  // implicit consent if SCP ISSUER or CUSTOM CA flag are set
  if (!(app->flags & (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_CUSTOM_CA))) {
    // if not with a trusted SCP and not signed, then deny ask for installation
    // (and more importantly ask the pin)
    if (!(app->flags & APPLICATION_FLAG_SIGNED)) {
      // compute app index in the bolos ux coordinate
      G_ux_params.u.appadd.app_idx =
          bolos_registry_check_app_idx(ctx->current_application_index);

      // We retrieve the icon bitmap, name and version of the application to be
      // installed, in order to send them to the UX.
      dashboard_stream_icon(app);

      // Now that we finished forwarding the icon to the UX application, we can
      // send the rest of the needed data.
      memmove(&G_ux_params.u.appadd.appentry, app, sizeof(application_t));

      G_ux_params.u.appadd.name_length = dashboard_get_app_info(
          app, BOLOS_TAG_APPNAME, (void*)&G_ux_params.u.appadd.name,
          sizeof(G_ux_params.u.appadd.name));

      G_ux_params.u.appadd.version_length = dashboard_get_app_info(
          app, BOLOS_TAG_APPVERSION, (void*)&G_ux_params.u.appadd.version,
          sizeof(G_ux_params.u.appadd.version));

      // ask_user_consent (always, onboarding must have been done before
      // installing any application)
      G_ux_params.ux_id = BOLOS_UX_CONSENT_APP_ADD;
      G_ux_params.len = sizeof(G_ux_params.u.appadd);
      if ((err = bolos_check_consent(&G_ux_params,
                                     &G_dashboard.reinit_display_on_error,
                                     G_dashboard.bolos_display, 1))) {
        return err;
      }
    }
  }

  if ((err = dashboard_commit_finalize())) {
    return err;
  }

  // No output.
  *out_length = 0L;
  return err;
}

// ask for a new application slot in nvram
// <CREATE_APP> <code_length (4BE)> <data_length (4BE)>
// <install_parameters_length (4BE)> <flags (4BE)> <main_offset(4BE)>
//              all parameters are part of the signature to be signed along with
//              it.
bolos_err_t dashboard_apdu_secure_create_app(uint8_t* apdu_buffer,
                                             size_t in_length,
                                             size_t* out_length) {
  uint8_t api_level = apdu_buffer[APDU_SECURE_DATA_OFF];
  unsigned int code_length = U4BE(apdu_buffer, APDU_SECURE_DATA_OFF + 1);
  unsigned int data_length = U4BE(apdu_buffer, APDU_SECURE_DATA_OFF + 1 + 4);
  unsigned int params_length =
      U4BE(apdu_buffer, APDU_SECURE_DATA_OFF + 1 + 4 + 4);
  unsigned int flags = U4BE(apdu_buffer, APDU_SECURE_DATA_OFF + 1 + 4 + 4 + 4);
  appmain_t boot_offset =
      (appmain_t)U4BE(apdu_buffer, APDU_SECURE_DATA_OFF + 1 + 4 + 4 + 4 + 4);

  UNUSED(in_length);

  // Mismatch between SDK API Level and FW one
  // Does not apply to firmware upgrades
  if (!(flags & APPLICATION_FLAG_BOLOS_UPGRADE) &&
      (api_level != (const uint8_t)API_LEVEL)) {
    return SWO_SEC_APP_1F;
  }

  *out_length = dashboard_create_slot(flags, code_length, data_length,
                                      params_length, boot_offset, apdu_buffer);
  return SWO_OK;
}

bolos_err_t dashboard_apdu_secure_set_load_offset(uint8_t* apdu_buffer,
                                                  size_t in_length,
                                                  size_t* out_length) {
  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  if (G_dashboard.transient_ctx.current_application.nvram_begin == NULL) {
    return SWO_SEC_APP_05;
  }
  G_dashboard.transient_ctx.load_offset32 = U4BE(apdu_buffer, 6);
  *out_length = 0;
  return SWO_OK;
}

bolos_err_t dashboard_apdu_secure_load(uint8_t* apdu_buffer,
                                       size_t in_length,
                                       size_t* out_length) {
  // at least: 1 byte instruction | 2 bytes offset | 1 byte to patch
  if (in_length < 1 + 2 + 1) {
    return SWO_APD_LEN_0F;
  }

  size_t chunk_length = in_length - 1L - 2L;
  uint8_t* chunk_ptr = apdu_buffer + APDU_OFF_DATA + 1 + 2;
  unsigned int offset = U2BE(apdu_buffer, APDU_OFF_DATA + 1);

  offset += (unsigned int)G_dashboard.transient_ctx.load_offset32;
  *out_length = dashboard_load_chunk(chunk_ptr, chunk_length, offset, true);
  return SWO_OK;
}

bolos_err_t dashboard_apdu_secure_flush(uint8_t* apdu_buffer,
                                        size_t in_length,
                                        size_t* out_length) {
  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(apdu_buffer);
  UNUSED(in_length);
  *out_length = 0;

  if (G_dashboard.transient_ctx.current_application.nvram_begin == NULL) {
    return SWO_SEC_APP_07;
  }
  return SWO_OK;
  // no flush needed, just kept to avoid recoding yet another load tool
}

bolos_err_t dashboard_apdu_secure_crc(uint8_t* apdu_buffer,
                                      size_t in_length,
                                      size_t* out_length) {
  unsigned int addr;

  // No output.
  *out_length = 0;

  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  if (G_dashboard.transient_ctx.current_application.nvram_begin == NULL) {
    return SWO_SEC_APP_08;
  }
  // crc is not checkable the way it is currently generated on the host side.
  if ((G_dashboard.transient_ctx.current_application.flags &
       (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER)) !=
      (APPLICATION_FLAG_BOLOS_UPGRADE | APPLICATION_FLAG_ISSUER)) {
    addr = (unsigned int)
               G_dashboard.transient_ctx.current_application.nvram_begin +
           (unsigned int)G_dashboard.transient_ctx.load_offset32 +
           (unsigned int)U2BE(apdu_buffer, 6);

    unsigned int length = U4BE(apdu_buffer, 8);

    // avoid uint overflow
    if (addr + length < addr || addr + length < length) {
      return SWO_APD_DAT_17;
    }

    // check for loading out of the defined area (and ensure loading is correct
    // with created application)
    if (addr + length > (unsigned int)G_dashboard.transient_ctx
                                .current_application.nvram_end +
                            1 ||
        addr < (unsigned int)
                   G_dashboard.transient_ctx.current_application.nvram_begin ||
        addr < (unsigned int)&_bootloader_apps_nvram_begin ||
        (unsigned int)G_dashboard.transient_ctx.current_application.nvram_end >
            (unsigned int)&_bootloader_apps_nvram_end ||
        addr + length > (unsigned int)&_bootloader_apps_nvram_end
        // deny CRCizing in the user protected memory (robustness in the general
        // case, could happen in the OSU context)
        || (G_dashboard.transient_ctx.load_address <
                (unsigned int)&_euser_perso_flash &&
            G_dashboard.transient_ctx.load_address + length >
                (unsigned int)&_user_perso_flash)) {
      // screen_printf("%08X %08X, %08X %04X\n",
      // G_dashboard.transient_ctx.current_application.nvram_begin,
      // G_dashboard.transient_ctx.current_application.nvram_end, addr, rx-3);
      return SWO_APD_DAT_0C;
    }

    // check crc, OR security error
    if (cx_crc16((uint8_t*)addr, length) != U2BE(apdu_buffer, 12)) {
      return SWO_SEC_CRC_17;
    }
  }
  return SWO_OK;
}

static bool slot_deletion_needs_user_consent(unsigned int slot_idx) {
  uint32_t flags =
      (uint32_t)N_application_registry.applications[slot_idx].flags;

  // only ask consent if SCP without ISSUER or CUSTOM CA (global accept for
  // issuer scp)
  if ((G_dashboard.transient_ctx.auth_source_flags &
       (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_CUSTOM_CA))) {
    return false;
  }

  // Deleting a language pack never needs consent
  if (flags & APPLICATION_FLAG_LANGUAGE_PACK) {
    return false;
  }

  return true;
}

// Trigger a user consent of an app deletion
static bolos_err_t check_consent_delete_app_slot(unsigned int slot_idx) {
  G_ux_params.ux_id = BOLOS_UX_CONSENT_APP_DEL;
  G_ux_params.u.appdel.app_idx = slot_idx;
  os_registry_get(G_ux_params.u.appdel.app_idx, &G_ux_params.u.appdel.appentry);
  G_ux_params.len = sizeof(G_ux_params.u.appdel);

  return bolos_check_consent(&G_ux_params, &G_dashboard.reinit_display_on_error,
                             G_dashboard.bolos_display, 0);
}

bolos_err_t dashboard_delete_slot(unsigned int slot_idx,
                                  bool force_skip_consent) {
  bolos_err_t err = SWO_OK;

  // Check if we are deleting the currently used language pack
  if (N_application_registry.applications[slot_idx].flags &
      APPLICATION_FLAG_LANGUAGE_PACK) {
    LANGUAGE_PACK* lp =
        (LANGUAGE_PACK*)(N_application_registry.applications[slot_idx]
                             .nvram_begin);
    if (lp->language == get_os_language()) {
      set_os_language(OS_LANGUAGE);
    }
  }
  // Common preprocess whether we want to delete the app by name or by hash.
  dashboard_app_ux_processing();

  // can't delete bolos_ux if not in recovery (egg/chicken problem).
  if ((bolos_is_recovery() != BOLOS_TRUE) &&
      (N_application_registry.applications[slot_idx].flags &
       APPLICATION_FLAG_BOLOS_UX)) {
    return SWO_APD_STA_21;
  }

  if ((!force_skip_consent) && slot_deletion_needs_user_consent(slot_idx)) {
    err = check_consent_delete_app_slot(slot_idx);

    if (err != SWO_OK) {
      return err;
    }
  }

  // We perform the actual deletion of the application in the registry, the
  // deletion of its potential dependencies, and the potential defragmentation
  // of the other applications.
  bolos_del_check_dependencies_and_delete(slot_idx);
  return err;
}

bolos_err_t dashboard_apdu_secure_delete_app_by_hash(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length) {
  unsigned int app_idx;
  bolos_err_t err = SWO_OK;
  bolos_bool_t app_found = BOLOS_FALSE;

  // The plaintext length basic test has been performed in the dispatcher.
  UNUSED(in_length);

  // Search for an application with the specified hash
  app_idx = os_registry_count();
  while (app_idx--) {
    if (memcmp(N_application_registry.applications[app_idx].sha256_full,
               apdu_buffer + 5 + 1, CX_SHA256_SIZE) == 0) {
      app_found = BOLOS_TRUE;
      break;
    }
  }

  if (BOLOS_TRUE == app_found) {
    if ((err = dashboard_delete_slot(app_idx, false))) {
      return err;
    }
    // ask to reinit UX (mostly to refresh dashboard)
    G_dashboard.reinit_display = true;
  }

  *out_length = 0;
  return err;
}

bolos_err_t dashboard_apdu_secure_delete_app_by_name(uint8_t* apdu_buffer,
                                                     size_t in_length,
                                                     size_t* out_length) {
  unsigned int app_idx;
  uint8_t* tlv_data;
  bolos_bool_t app_found = BOLOS_FALSE;
  bolos_err_t err = SWO_OK;

  if (in_length < 1 + 1 + 1) {
    return SWO_APD_LEN_19;
  }

  // Search for an application with the specified name.
  app_idx = os_registry_count();
  while (app_idx--) {
    tlv_data = &apdu_buffer[6 + 1];
    if (os_parse_installparam_tlv(
            &N_application_registry.applications[app_idx], NULL,
            BOLOS_TAG_APPNAME,
            OS_REGISTRY_GET_TAG_OFFSET_COMPARE_WITH_BUFFER | 0,
            (void**)&tlv_data, apdu_buffer[6]) == 1) {
      app_found = BOLOS_TRUE;
      break;
    }
  }

  if (BOLOS_TRUE == app_found) {
    if ((err = dashboard_delete_slot(app_idx, false))) {
      return err;
    }
    // ask to reinit UX (mostly to refresh dashboard)
    G_dashboard.reinit_display = true;
  }

  *out_length = 0;
  return err;
}

bolos_err_t dashboard_apdu_secure_delete_all_apps(uint8_t* apdu_buffer,
                                                  size_t in_length,
                                                  size_t* out_length) {
  bolos_err_t err = SWO_OK;
  unsigned int app_count;
  UNUSED(apdu_buffer);
  UNUSED(in_length);

  // Is there at least one application?
  app_count = os_registry_count();
  if (app_count) {
    dashboard_app_ux_processing();

    // If needed, ask for user consent only once
    // Only ask consent if SCP without ISSUER or CUSTOM CA (global accept for
    // issuer scp)
    if (!(G_dashboard.transient_ctx.auth_source_flags &
          (APPLICATION_FLAG_ISSUER | APPLICATION_FLAG_CUSTOM_CA))) {
      G_ux_params.ux_id = BOLOS_UX_CONSENT_APP_DEL_ALL;
      if ((err = bolos_check_consent(&G_ux_params,
                                     &G_dashboard.reinit_display_on_error,
                                     G_dashboard.bolos_display, 0))) {
        return err;
      }
    }
    // Delete all applications
    os_registry_wipe();

    // ask to reinit UX (mostly to refresh dashboard)
    G_dashboard.reinit_display = true;
  }
  *out_length = 0;
  return err;
}