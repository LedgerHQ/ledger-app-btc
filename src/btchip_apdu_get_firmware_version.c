/*******************************************************************************
*   Ledger Blue - Counoscoin Wallet
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define FEATURES_COMPRESSED_KEYS 0x01
#define FEATURES_SELF_SCREEN_BUTTONS 0x02
#define FEATURES_EXTERNAL_SCREEN_BUTTONS 0x04
#define FEATURES_NFC 0x08
#define FEATURES_BLE 0x10
#define FEATURES_TEE 0x20

#define MODE_SETUP 0x01
#define MODE_OPERATION 0x02

#define ARCH_ID 0x30

// Java Card is 0x60

void get_firmware_version(unsigned char *buffer) {
    buffer[0] = ARCH_ID;
    buffer[1] = LEDGER_MAJOR_VERSION;
    buffer[2] = LEDGER_MINOR_VERSION;
    buffer[3] = LEDGER_PATCH_VERSION;
    buffer[4] = 1;
    buffer[5] = TCS_LOADER_PATCH_VERSION;
}

unsigned short btchip_apdu_get_firmware_version() {
    G_io_apdu_buffer[0] =
        (((N_btchip.bkp.config.options & BTCHIP_OPTION_UNCOMPRESSED_KEYS) != 0)
             ? 0x00
             : 0x01);

    G_io_apdu_buffer[0] |= FEATURES_NFC;
    G_io_apdu_buffer[0] |= FEATURES_BLE;

    G_io_apdu_buffer[0] |= FEATURES_SELF_SCREEN_BUTTONS;

    get_firmware_version(G_io_apdu_buffer + 1);

    G_io_apdu_buffer[7] = 0x00;
    G_io_apdu_buffer[7] |= MODE_SETUP;
    G_io_apdu_buffer[7] |= MODE_OPERATION;

    btchip_context_D.outLength = 0x08;

    return BTCHIP_SW_OK;
}
