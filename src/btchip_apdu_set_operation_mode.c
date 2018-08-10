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

// TODO BAGL : validate operation mode change

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define P1_DISABLE_KEYCARD 0x00
#define P1_ENABLE_KEYCARD 0x01
#define P1_ENABLE_KEYCARD_PERMANENTLY 0x02

unsigned short btchip_apdu_set_operation_mode() {
    unsigned char operationMode;

    if (G_io_apdu_buffer[ISO_OFFSET_LC] != 0x01) {
        return BTCHIP_SW_INCORRECT_LENGTH;
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
    operationMode = G_io_apdu_buffer[ISO_OFFSET_CDATA];

    if (operationMode == BTCHIP_MODE_WALLET) {
    }

    if (operationMode == SB_GET(N_btchip.bkp.config.operationMode)) {
        return BTCHIP_SW_OK;
    }

    switch (operationMode) {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
    case BTCHIP_MODE_DEVELOPER:
        break;
    default:
        return BTCHIP_SW_INCORRECT_DATA;
    }

    SB_CHECK(N_btchip.bkp.config.supportedModes);
    if ((SB_GET(N_btchip.bkp.config.supportedModes) & operationMode) == 0) {
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    // commit new operation
    btchip_set_operation_mode(operationMode);

    return BTCHIP_SW_OK;
}
