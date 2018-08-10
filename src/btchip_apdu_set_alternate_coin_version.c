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

#define P1_VERSION_ONLY 0x00
#define P1_VERSION_COINID 0x01

unsigned short btchip_apdu_set_alternate_coin_version() {
    uint8_t offset = ISO_OFFSET_CDATA;
    unsigned char p1 = G_io_apdu_buffer[ISO_OFFSET_P1];
    if ((p1 != P1_VERSION_ONLY) && (p1 != P1_VERSION_COINID)) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if (p1 == P1_VERSION_ONLY) {
        if (G_io_apdu_buffer[ISO_OFFSET_LC] != 0x05) {
            return BTCHIP_SW_INCORRECT_LENGTH;
        }
    } else {
        if (G_io_apdu_buffer[ISO_OFFSET_LC] >
            7 + MAX_COIN_ID + MAX_SHORT_COIN_ID) {
            return BTCHIP_SW_INCORRECT_LENGTH;
        }
    }

    SB_CHECK(N_btchip.bkp.config.operationMode);
    if ((SB_GET(N_btchip.bkp.config.operationMode) ==
         BTCHIP_MODE_SETUP_NEEDED) ||
        (SB_GET(N_btchip.bkp.config.operationMode) == BTCHIP_MODE_ISSUER)) {
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (!os_global_pin_is_validated()) {
        return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    switch (G_io_apdu_buffer[offset + 4]) {
    case BTCHIP_FAMILY_COUNOSCOIN:
        break;
    case BTCHIP_FAMILY_PEERCOIN:
        if (!(G_coin_config->flags & FLAG_PEERCOIN_SUPPORT)) {
            goto incorrect_family;
        }
        break;
    case BTCHIP_FAMILY_QTUM:
        if (!(G_coin_config->kind == COIN_KIND_QTUM)) {
            goto incorrect_family;
        }
        break;
    default:
    incorrect_family:
        return BTCHIP_SW_INCORRECT_DATA;
    }

    btchip_context_D.payToAddressVersion =
        (G_io_apdu_buffer[offset] << 8) | (G_io_apdu_buffer[offset + 1]);
    offset += 2;
    btchip_context_D.payToScriptHashVersion =
        (G_io_apdu_buffer[offset] << 8) | (G_io_apdu_buffer[offset + 1]);
    offset += 2;
    btchip_context_D.coinFamily = G_io_apdu_buffer[offset++];
    if (p1 == P1_VERSION_COINID) {
        uint8_t coinIdLength = G_io_apdu_buffer[offset];
        uint8_t shortCoinIdLength = G_io_apdu_buffer[offset + 1 + coinIdLength];
        if ((coinIdLength > MAX_COIN_ID) ||
            (shortCoinIdLength > MAX_SHORT_COIN_ID)) {
            return BTCHIP_SW_INCORRECT_DATA;
        }
        os_memmove(btchip_context_D.coinId, G_io_apdu_buffer + offset + 1,
                   coinIdLength);
        btchip_context_D.coinIdLength = coinIdLength;
        offset += 1 + coinIdLength;
        os_memmove(btchip_context_D.shortCoinId, G_io_apdu_buffer + offset + 1,
                   shortCoinIdLength);
        btchip_context_D.shortCoinIdLength = shortCoinIdLength;
    }

    return BTCHIP_SW_OK;
}
