/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#define DASHBOARD_CONSTANTS_H

// clang-format off

//////////////////////////////////////////////////
// Dashboard CLA value.
//////////////////////////////////////////////////
#define CLA 0xE0

//////////////////////////////////////////////////
// Non-secure INS codes.
//////////////////////////////////////////////////
#define INS_SECURE_COMMAND                    0x00
#define INS_GET_VERSION                       0x01
#define INS_RESET                             0x02
#define INS_CREATE_LANGUAGE_PACK              0x30
#define INS_LOAD_LANGUAGE_PACK                0x31
#define INS_COMMIT_LANGUAGE_PACK              0x32
#define INS_DEL_LANGUAGE_PACK                 0x33
#define INS_LIST_LANGUAGE_PACKS               0x34



#define INS_VALIDATE_TARGET_ID                0x04
#define INS_GET_BATTERY_STATE                 0x10
#define INS_SET_MAX_BATT_PERC                 0x19
#define LC_SET_MAX_BATT_PERC                  0x01
//#define INS_MCU_BOOTLOADER                    0x0B // avoid

// fab commands
#define INS_GET_DEVICE_PUBLIC_KEY             0x40
#define INS_SET_CERTIFICATE                   0x41
#define INS_FACTORY_TEST                      0x44
#define P1_FACTORY_TEST_START_STOP            0x00
#define P1_FACTORY_TEST_SCREEN                0x10
#define P1_FACTORY_TEST_BUTTON                0x20
#define P1_FACTORY_TEST_BATTERY               0x30
#define P1_FACTORY_TEST_GET_SE_SN             0xD0
#define P1_FACTORY_TEST_RESET                 0xE0
#define P1_FACTORY_TEST_SERIAL_NUMBER         0xF0
#define P1_FACTORY_TEST_BACKUP_SERIAL_NUMBER  0xF1
#define P1_FACTORY_TEST_MCU_SERIAL_NUMBER     0xF2
#define P1_FACTORY_RESET_SERIAL_NUMBER        0xFF

#define P1_FAT_FACTORY_WRITE_TEXT             0xFB
#define P1_FAT_FACTORY_TEST_SCREEN            0xFC
#define P1_FAT_FACTORY_TEST_TOUCH             0xFD

#define P2_FAT_FACTORY_TEST_TOUCH_GET_CONF    0x30

// deployed commands
#define INS_INITIALIZE_AUTHENTICATION         0x50
#define INS_VALIDATE_CERTIFICATE              0x51
#define INS_VALIDATE_CERTIFICATE_P1_LAST      0x80 // sign with SN8/DN8
#define INS_GET_CERTIFICATE                   0x52
#define INS_GET_CERTIFICATE_P1_LAST           0x80 // sign with DN8/SN8
#define INS_MUTUAL_AUTHENTICATE               0x53
#define INS_SET_CXPORT                        0xC4
#define INS_GET_CXPORT                        0xC5

// endorsement personalization commands
#define INS_ENDORSE_SET_START                 0xC0
#define INS_ENDORSE_SET_COMMIT                0xC2

# define INS_ENDORSEMENT_INFO_RETRIEVAL       0xC6

// host personalization
#define INS_ONBOARD                           0xD0
#define INS_ONBOARD_P1_ID0                    0x00
#define INS_ONBOARD_P1_ID1                    0x01
#define INS_ONBOARD_P1_IDTMP                  0x02

#define INS_GET_DEVICE_NAME                   0xD2
#define INS_SET_DEVICE_NAME                   0xD4

#define INS_GET_DEVICE_MAC                    0xD5

#define INS_SET_SCREEN_SAVER                  0xD6
#define P1_SET_CUSTOM_SCREEN_SAVER            0x00
#define P1_GET_SCREEN_SAVER_STATUS            0x40
#define P1_SET_DEFAULT_SCREEN_SAVER           0x80

#define INS_OPEN_APP                          0xD8








#define INS_LIST_APPS                         0xDE
#define INS_LIST_APPS_CONTINUE                0xDF

//////////////////////////////////////////////////
// Secure INS codes.
//////////////////////////////////////////////////
#define SECUREINS_SET_LOAD_OFFSET             0x05
#define SECUREINS_LOAD                        0x06
#define SECUREINS_FLUSH                       0x07
#define SECUREINS_CRC                         0x08
// start at given address (app main)
#define SECUREINS_COMMIT                      0x09
#define SECUREINS_CREATE_APP                  0x0B
#define SECUREINS_DELETE_APP                  0x0C
#define SECUREINS_LIST_APPS                   0x0E
#define SECUREINS_LIST_APPS_CONTINUE          0x0F
#define SECUREINS_GET_VERSION                 0x10
#define SECUREINS_GET_MEMORY_INFORMATION      0x11
#define SECUREINS_SETUP_CUSTOM_CERTIFICATE    0x12
#define SECUREINS_RESET_CUSTOM_CERTIFICATE    0x13
#define SECUREINS_DELETE_APP_BY_HASH          0x15
#define SECUREINS_RESET_ENDORSEMENT           22
#define SECUREINS_HASH_FIRMWARE               0x17
#define SECUREINS_MCU_BOOTLOADER              0xB0

#  define SECUREINS_DELETE_ALL_APPS           0x14


#define SECUREINS_RECOVER_SET_CA                    (0xD2)
#define SECUREINS_RECOVER_DELETE_CA                 (0xD3)
#define SECUREINS_RECOVER_VALIDATE_BACKUP_DATA      (0xD4)
#define SECUREINS_RECOVER_VALIDATE_CERTIFICATE      (0xD5)
#define SECUREINS_RECOVER_MUTUAL_AUTHENTICATE       (0xD6)
#define SECUREINS_RECOVER_VALIDATE_BACKUP_DATA_HASH (0xD7)
#define SECUREINS_RECOVER_GET_SHARE                 (0xD8)
#define SECUREINS_RECOVER_VALIDATE_COMMIT           (0xD9)
#define SECUREINS_RECOVER_RESTORE_SEED              (0xDA)
#define SECUREINS_RECOVER_DELETE_BACKUP             (0xDB)

#define INS_RECOVER_GET_SHARE_P1                    (0x00)
#define INS_RECOVER_GET_SHARE_P1_COMMIT             (0x01)
#define INS_RECOVER_GET_SHARE_P1_COMMIT_POINT       (0x10)
#define INS_RECOVER_VALIDATE_P1_COMMIT              (0x02)
#define INS_RECOVER_VALIDATE_P1_COMMIT_HASH         (0x03)
#define INS_RECOVER_VALIDATE_P1_COMMIT_LAST         (0x04)

// Within the data field

// Offset of the secure INS within the APDU buffer.
#define APDU_OFF_SECINS                       0x05
// Offset of the first byte of plaintext data (secure INS excluded).
#define APDU_SECURE_DATA_OFF                  0x06

// Lc-related values.
#define LC_RESET                              0x00
#define LC_GET_VERSION                        0x00
#define LC_VAL_TARGET_ID                      0x04
#define LC_GET_BATTERY_STATE                  0x00

#define LC_VAL_CREATE_LANGUAGE_PACK           0x04


#define LC_GET_PUB_KEY                        0x00
#define LC_INIT_AUTH                          0x08
#define LC_GET_CERTIFICATE                    0x00
#define LC_MUTUAL_AUTH                        0x00
#define LC_ENDORSE_START                      0x00
#define LC_LIST_APPS_START                    0x00
#define LC_LIST_APPS_CONTINUE                 0x00
#define LC_ENDORSEMENT_INFO                   0x00
#define LC_GET_DEVICE_NAME                    0x00
#define LC_GET_DEVICE_MAC                     0x00
#define LC_GET_CXPORT			      0x00
#define LC_LIST_LANGUAGE_PACKS_START          0x00
#define LC_LIST_LANGUAGE_PACKS_CONTINUE       0x00


// Lc fields for secure commmands once the plaintext is retrieved.
#define LC_SECURE_CREATE_APP                  0x16
#define LC_SECURE_SET_LOAD_OFF                0x05
#define LC_SECURE_FLUSH                       0x01
#define LC_SECURE_CRC                         0x09
#define LC_SECURE_GET_VERSION                 0x01
#define LC_SECURE_DELETE_BY_HASH              0x21
#define LC_SECURE_LIST_APPS_START             0x01
#define LC_SECURE_LIST_APPS_CONT              0x01
#define LC_SECURE_GET_MEM_INFO                0x01
#define LC_SECURE_HASH_FIRMWARE               0x19

#  define LC_SECURE_DELETE_ALL                0x01





// Dispatcher-related indicators.
#define P1_VAR                                0xFF
#define P2_VAR                                0xFF
#define LC_VAR                                0xFF

// P1-specific values.
#define P1_DEL_ALL_LANGUAGE_PACK              0xFF
#define P1_LIST_LANGUAGE_PACKS_FIRST          0x00
#define P1_LIST_LANGUAGE_PACKS_NEXT           0x01

//////////////////////////////////////////////////
// Transient context states.
//////////////////////////////////////////////////
#define STATE_NONE                            0x00FF
#define STATE_TARGET_VALIDATED                0x0FF0
#define STATE_DEVICE_PUBLIC_KEY               0x1EE1
#define STATE_INITIALIZE_AUTHENTICATION       0x2DD2
#define STATE_VALIDATE_CERTIFICATE            0x3CC3
#define STATE_VALIDATE_CERTIFICATE_LAST       0x4BB4
#define STATE_GET_CERTIFICATE                 0x5AA5
#define STATE_GET_CERTIFICATE_LAST            0x6996
#define STATE_MUTUAL_AUTHENTICATED            0x7887
#define STATE_SET_CERTIFICATE                 0x8778
#define STATE_BOOT                            0x9669
#define STATE_SE_RESET                        0xA55A
#define STATE_MCU_BOOTLOADER                  0xB44B
#define STATE_RUN_APP                         0xC33C
#define STATE_MCU_RDP2_THEN_RESET             0xD22D
#define STATE_MCU_SHIP_THEN_RESET             0xE11E

//////////////////////////////////////////////////
// MCU signature checking-related information.
//////////////////////////////////////////////////

// Miscellaneous defines.
#define ECDSA_SHA256_SIG_MAX_ASN1_LENGTH      (1 + 1 + 2 * (1 + 1 + 33))
#define PBKDF2_SALT_MAX_LENGTH                380

//////////////////////////////////////////////////
// Taget Identifier array.
//////////////////////////////////////////////////
static const unsigned char U_bolos_target_id[4] = {
  (TARGET_ID>>24)&0xFF,
  (TARGET_ID>>16)&0xFF,
  (TARGET_ID>>8)&0xFF,
  (TARGET_ID>>0)&0xFF,
};

// clang-format on