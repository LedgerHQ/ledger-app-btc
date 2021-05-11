/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
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
#include "btchip_bagl_extensions.h"

#define P1_FIRST 0x00
#define P1_NEXT 0x80
#define P2_NEW 0x00
#define P2_NEW_SEGWIT 0x02
#define P2_NEW_SEGWIT_CASHADDR 0x03
#define P2_NEW_SEGWIT_OVERWINTER 0x04
#define P2_NEW_SEGWIT_SAPLING 0x05
#define P2_CONTINUE 0x80
#define P2_NEW_SENDER 0x81

#define IS_INPUT()                                                          \
    (G_io_apdu_buffer[ISO_OFFSET_LC] - 1 > 8                                \
     && G_io_apdu_buffer[ISO_OFFSET_LC] - 1 <= TRUSTED_INPUT_TOTAL_SIZE + 2  \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA] <= 0x02)                         \

#define IS_INPUT_TRUSTED()                                                  \
    (G_io_apdu_buffer[ISO_OFFSET_CDATA] == 0x01                             \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA + 1] == TRUSTED_INPUT_TOTAL_SIZE   \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA + 2] == MAGIC_TRUSTED_INPUT       \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA + 3] == 0x00)

unsigned short btchip_apdu_hash_input_start() {
    unsigned char apduLength;
    apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode)) {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_FIRST) {
        // Initialize
        btchip_context_D.transactionContext.transactionState =
            BTCHIP_TRANSACTION_NONE;
        btchip_set_check_internal_structure_integrity(1);
        btchip_context_D.transactionHashOption = TRANSACTION_HASH_BOTH;
    } else if (G_io_apdu_buffer[ISO_OFFSET_P1] != P1_NEXT) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if ((G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW) ||
        #ifdef HAVE_QTUM_SUPPORT
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SENDER) ||
        #endif
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_CASHADDR) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_OVERWINTER) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_SAPLING)) {
        // btchip_context_D.transactionContext.consumeP2SH =
        // ((N_btchip.bkp.config.options & BTCHIP_OPTION_SKIP_2FA_P2SH) != 0);
        if (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_FIRST) {
            unsigned char usingSegwit =
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT) ||
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_CASHADDR) ||
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_OVERWINTER) ||
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_SAPLING);
            unsigned char usingCashAddr =
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_CASHADDR);
            #ifdef HAVE_QTUM_SUPPORT
            unsigned char signOpSender =
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SENDER);
            #endif
            // Request PIN validation
            // Only request PIN validation (user presence) to start a new
            // transaction signing flow.
            // Thus allowing for numerous output to be processed in the
            // background without
            // requiring to disable autolock/autopoweroff
            if (!btchip_context_D.transactionContext.firstSigned &&
                os_global_pin_is_validated() != BOLOS_UX_OK) {
                return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
            }
            // Master transaction reset
            btchip_context_D.transactionContext.firstSigned = 1;
            btchip_context_D.transactionContext.consumeP2SH = 0;
            btchip_context_D.transactionContext.relaxed = 0;
            #ifdef HAVE_QTUM_SUPPORT
            if(signOpSender)
                usingSegwit = 1;
            #endif
            btchip_context_D.usingSegwit = usingSegwit;
            #ifdef HAVE_QTUM_SUPPORT
            btchip_context_D.signOpSender = signOpSender;
            #endif
            btchip_context_D.usingCashAddr =
                (G_coin_config->kind == COIN_KIND_BITCOIN_CASH ? usingCashAddr
                                                               : 0);
            btchip_context_D.usingOverwinter = 0;
            if ((G_coin_config->kind == COIN_KIND_ZCASH) || (G_coin_config->kind == COIN_KIND_KOMODO) || (G_coin_config->kind == COIN_KIND_ZCLASSIC) || (G_coin_config->kind == COIN_KIND_RESISTANCE)) {
                if (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_OVERWINTER) {
                    btchip_context_D.usingOverwinter = ZCASH_USING_OVERWINTER;
                }
                else
                if (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_SAPLING) {
                    btchip_context_D.usingOverwinter = ZCASH_USING_OVERWINTER_SAPLING;
                }
            }
            btchip_context_D.overwinterSignReady = 0;
            btchip_context_D.segwitParsedOnce = 0;
            btchip_set_check_internal_structure_integrity(1);
            // Initialize for screen pairing
            os_memset(&btchip_context_D.tmpCtx.output, 0,
                      sizeof(btchip_context_D.tmpCtx.output));
            btchip_context_D.tmpCtx.output.changeAccepted = 1;
            // Reset segwitWarningSeen flag to prevent displaying the warning for each
            // segwit input when coontinuing from a previous session (P2=0x80)
            btchip_context_D.segwitWarningSeen = 0;
        }
    } else if (G_io_apdu_buffer[ISO_OFFSET_P2] != P2_CONTINUE) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    // In segwit mode, warn user one time only to update its client wallet...
    if (btchip_context_D.usingSegwit
        && !btchip_context_D.segwitWarningSeen
        &&(G_io_apdu_buffer[ISO_OFFSET_P1] == P1_NEXT)
        && (G_io_apdu_buffer[ISO_OFFSET_P2] != P2_CONTINUE)
        // ...if input is not passed as a TrustedInput
        && IS_INPUT()
        && !IS_INPUT_TRUSTED())
    {
        if(btchip_context_D.called_from_swap){
            /* There is no point in displaying a warning when the app is signing
            in silent mode, as its UI is hidden behind the exchange app*/
            return BTCHIP_SW_SWAP_WITHOUT_TRUSTED_INPUTS;
        }
        btchip_context_D.segwitWarningSeen = 1;
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_request_segwit_input_approval();
    }

    // Start parsing of the 1st chunk
    btchip_context_D.transactionBufferPointer =
        G_io_apdu_buffer + ISO_OFFSET_CDATA;
    btchip_context_D.transactionDataRemaining = apduLength;

    transaction_parse(PARSE_MODE_SIGNATURE);

    return BTCHIP_SW_OK;
}
