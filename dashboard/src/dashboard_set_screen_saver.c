/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bagl_animate.h"
#include "bolos.h"
#include "bolos_privileged_ux.h"
#include "dashboard_constants.h"
#include "dashboard_ram.h"
#include "errors.h"
#include "os_apdu.h"

/**
 * The goal of this APDU is to configure the screen saver for LNX and LNS+
 *
 * Depending of the value of P1, the APDU:
 * + Change the default screen saver to a custom one (scrolling text).
 * + Reset the screensaver to the default one (icon random moving).
 *
 * The APDU let the user choice for the custom screen saver:
 * + the text to scroll
 * + the animation type
 * + the animation speed
 */

// TLV properties for the APDU "Set Screen Saver"
#define TLV_TAG_SZ 1
#define TLV_LEN_SZ 1
#define TLV_TAG_IDX 0
#define TLV_LEN_IDX (TLV_TAG_IDX + TLV_TAG_SZ)
#define TLV_VAL_IDX (TLV_LEN_IDX + TLV_LEN_SZ)

// Static magic data element
#define MAGIC_TAG 0x01
#define MAGIC_LEN (sizeof(MAGIC_VAL) - 1)
#define MAGIC_VAL "Screensaver Perso"
_Static_assert(MAGIC_LEN <= 0xff, "Screen saver magic value is too big");

// Dynamic text data element
#define TEXT_TAG 0x02
#define MIN_TEXT_SZ 1
#define MAX_TEXT_SZ 52

// Total size of the magic TLV.
#define TLV_MAGIC_SZ (TLV_TAG_SZ + TLV_LEN_SZ + MAGIC_LEN)

// APDU minimum length required to have a message of size MIN_EXT_SZ (P1==0x00)
#define MIN_CUSTOM_LEN_DATA \
  (TLV_MAGIC_SZ + TLV_TAG_SZ + TLV_LEN_SZ + MIN_TEXT_SZ)

/**
 * Structure used to parse the APDU buffer for
 * the custom/default screen saver.
 */
typedef struct screen_saver_parser_s {
  uint8_t* apdu;
  size_t out_length;
  const char* text;
  uint8_t text_len;
  anim_type_t type;
  anim_speed_t speed;
} screen_saver_parser_t;

/**
 * In [P2]:
 *   + 4th first bits: Type of the scrolling animation
 *   + 4th last bits: Speed of the scrolling animation
 */
static bool parse_custom_p2(screen_saver_parser_t* parser) {
  uint8_t p2 = parser->apdu[APDU_OFF_P2];

  parser->type = (p2 >> 4) & 0x0f;
  parser->speed = p2 & 0x0f;

  if (parser->type >= ANIMATION_TYPE_END ||
      parser->speed >= ANIMATION_SPEED_END) {
    return false;
  }
  return true;
}

static bool parse_custom_length(screen_saver_parser_t* parser) {
  uint8_t len = parser->apdu[APDU_OFF_LC];
  if (len < MIN_CUSTOM_LEN_DATA) {
    return false;
  }
  return true;
}

static bool parse_default_length(screen_saver_parser_t* parser) {
  uint8_t len = parser->apdu[APDU_OFF_LC];
  if (len != TLV_MAGIC_SZ) {
    return false;
  }
  return true;
}

static bool parse_magic(screen_saver_parser_t* parser) {
  const uint8_t* tlv_magic = &parser->apdu[APDU_OFF_DATA];

  if (tlv_magic[TLV_TAG_IDX] != MAGIC_TAG) {
    return false;
  }
  if (tlv_magic[TLV_LEN_IDX] != MAGIC_LEN) {
    return false;
  }
  if (memcmp(&tlv_magic[TLV_VAL_IDX], MAGIC_VAL, MAGIC_LEN) != 0) {
    return false;
  }
  return true;
}

static bool parse_custom_text(screen_saver_parser_t* parser) {
  const uint8_t* tlv_text = &parser->apdu[APDU_OFF_DATA + TLV_MAGIC_SZ];

  if (tlv_text[TLV_TAG_IDX] != TEXT_TAG) {
    return false;
  }
  parser->text_len = tlv_text[TLV_LEN_IDX];
  if (parser->text_len < MIN_TEXT_SZ || parser->text_len > MAX_TEXT_SZ) {
    return false;
  }
  parser->text = (const char*)&tlv_text[TLV_VAL_IDX];

  /* check the content of the text  */
  for (unsigned i = 0; i < parser->text_len; ++i) {
    if (parser->text[i] < 0x20 || parser->text[i] >= 0x7f) {
      return false;
    }
  }

  return true;
}

/* Parse the APDU buffer for a custom screen saver. */
static bool parse_custom(screen_saver_parser_t* parser) {
  if (parse_custom_p2(parser) != true) {
    return false;
  }
  if (parse_custom_length(parser) != true) {
    return false;
  }
  if (parse_magic(parser) != true) {
    return false;
  }
  if (parse_custom_text(parser) != true) {
    return false;
  }
  return true;
}

/* Parse the APDU buffer for the default and get command screen saver. */
bolos_err_t parse_default(screen_saver_parser_t* parser) {
  if (parse_default_length(parser) != true) {
    return false;
  }
  if (parse_magic(parser) != true) {
    return false;
  }
  return true;
}

/**
 * Save custom screen saver settings in NVRAM.
 *
 * If the value of settings[OS_SETTING_SAVER_STRING] is different
 * than 0 means we are using a custom screen saver, otherwise
 * we are using the default screen_saver.
 *
 * The format of the buffer to write is:
 *  + 1 byte:    [type]
 *  + 1 byte:    [speed]
 *  + 1 byte:    [len]
 *  + len bytes: [text]
 */
static void save_custom(screen_saver_parser_t* parser) {
  char* buffer = G_ux_params.u.screen_saver.buffer;
  // We don't need to check an overflow here because
  // the max length of the text is 52 and already checked.
  uint8_t tot_len = parser->text_len + IDX_TEXT + 1;  // for the '\0'

  buffer[IDX_TYPE] = parser->type;
  buffer[IDX_SPEED] = parser->speed;
  buffer[IDX_LEN] = parser->text_len;

  memcpy(&buffer[IDX_TEXT], parser->text, parser->text_len);
  buffer[IDX_TEXT + parser->text_len] = 0;

  os_setting_set(OS_SETTING_SAVER_STRING, (unsigned char*)buffer, tot_len);
}

/**
 * Reset the default screen saver. Value has not to be NULL,
 * but the meaning of the value doens't have any impact.
 */
static void save_default(void) {
  os_setting_set(OS_SETTING_SAVER_STRING, (unsigned char*)"foo", 0);
}

#define SET true
#define RESET false

/**
 * If set == true -> consent to set the custom screen saver
 * If set == false -> consent to reset the default screen saver
 */
static bool set_screen_saver_consent(screen_saver_parser_t* parser, bool set) {
  memcpy(G_ux_params.u.screen_saver.buffer, parser->text, parser->text_len);
  G_ux_params.u.screen_saver.buffer[parser->text_len] = 0;
  G_ux_params.u.screen_saver.buffer_len = parser->text_len;
  G_ux_params.u.screen_saver.set = set;
  G_ux_params.ux_id = BOLOS_UX_CONSENT_SET_SCREEN_SAVER;
  G_ux_params.len = 0;

  if (bolos_check_consent(&G_ux_params, &G_dashboard.reinit_display_on_error,
                          G_dashboard.bolos_display, 0)) {
    return false;
  }
  return true;
}

static bool set_screen_saver_custom(screen_saver_parser_t* parser) {
  if (parse_custom(parser) != true) {
    return false;
  }
  if (set_screen_saver_consent(parser, SET) != true) {
    return false;
  }
  save_custom(parser);
  return true;
}

static bool set_screen_saver_default(screen_saver_parser_t* parser) {
  if (parse_default(parser) != true) {
    return false;
  }
  if (set_screen_saver_consent(parser, RESET) != true) {
    return false;
  }
  save_default();
  return true;
}

#undef SET
#undef RESET

bool screen_saver_get_status(screen_saver_parser_t* parser) {
  if (parse_default(parser) != true) {
    return false;
  }

  char* buffer = G_ux_params.u.screen_saver.buffer;
  parser->out_length = os_setting_get(
      OS_SETTING_SAVER_STRING, (unsigned char*)buffer, SETTING_SAVER_STRING_SZ);
  if (parser->out_length != 0) {
    memcpy(parser->apdu, buffer, parser->out_length);
  }
  return true;
}

// APDU command "Set Screen Saver"
bolos_err_t dashboard_apdu_set_screen_saver(uint8_t* apdu_buffer,
                                            size_t in_length,
                                            size_t* out_length) {
  UNUSED(in_length);
  bool ret;
  screen_saver_parser_t parser = {apdu_buffer, 0, NULL, 0, 0, 0};

  // We only accept this command in recovery mode, and in other cases,
  // we don't want to distinguish the error from the 'unknown INS' error.
  unsigned char is_recovery = bolos_is_recovery();
  if (is_recovery != BOLOS_TRUE) {
    return SWO_APD_INS_02;
  }

  switch (apdu_buffer[APDU_OFF_P1]) {
    case P1_SET_CUSTOM_SCREEN_SAVER:
      ret = set_screen_saver_custom(&parser);
      break;
    case P1_SET_DEFAULT_SCREEN_SAVER:
      ret = set_screen_saver_default(&parser);
      break;
    case P1_GET_SCREEN_SAVER_STATUS:
      ret = screen_saver_get_status(&parser);
      break;
    default:
      ret = false;
      break;
  };

  *out_length = parser.out_length;
  return ret == true ? SWO_OK : SWO_APD_INS_02;
}