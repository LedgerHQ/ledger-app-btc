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

#include "segwit_addr.h"
#include "cashaddr.h"
#include "multichainaddr.h"

#define P1_NO_DISPLAY 0x00
#define P1_DISPLAY 0x01
#define P1_REQUEST_TOKEN 0x02

#define P2_LEGACY 0x00
#define P2_SEGWIT 0x01
#define P2_NATIVE_SEGWIT 0x02
#define P2_CASHADDR 0x03

unsigned short btchip_apdu_get_wallet_public_key() {
    unsigned char keyLength;
    unsigned char uncompressedPublicKeys =
        ((N_btchip.bkp.config.options & BTCHIP_OPTION_UNCOMPRESSED_KEYS) != 0);
    unsigned char keyPath[MAX_BIP32_PATH_LENGTH];
    uint32_t request_token;
    unsigned char chainCode[32];
    bool display = (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_DISPLAY);
    bool display_request_token = N_btchip.pubKeyRequestRestriction && (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_REQUEST_TOKEN) && G_io_apdu_media == IO_APDU_MEDIA_U2F;
    bool require_user_approval = N_btchip.pubKeyRequestRestriction && !(display_request_token || display) && G_io_apdu_media == IO_APDU_MEDIA_U2F;
    bool segwit = (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_SEGWIT);
    bool nativeSegwit = (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NATIVE_SEGWIT);
    bool cashAddr = (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_CASHADDR);

    switch (G_io_apdu_buffer[ISO_OFFSET_P1]) {
    case P1_NO_DISPLAY:
    case P1_DISPLAY:
    case P1_REQUEST_TOKEN:
        break;
    default:
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    switch (G_io_apdu_buffer[ISO_OFFSET_P2]) {
    case P2_NATIVE_SEGWIT:
        if (!(G_coin_config->native_segwit_prefix)) {
            return BTCHIP_SW_INCORRECT_P1_P2;
        }
    case P2_LEGACY:
    case P2_SEGWIT:
        break;
    case P2_CASHADDR:
        if (G_coin_config->kind != COIN_KIND_BITCOIN_CASH) {
            return BTCHIP_SW_INCORRECT_P1_P2;
        }
        break;
    default:
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_LC] < 0x01) {
        return BTCHIP_SW_INCORRECT_LENGTH;
    }
    os_memmove(keyPath, G_io_apdu_buffer + ISO_OFFSET_CDATA,
               MAX_BIP32_PATH_LENGTH);

    if(display_request_token){
        uint8_t request_token_offset = ISO_OFFSET_CDATA + G_io_apdu_buffer[ISO_OFFSET_CDATA]*4 + 1;
        request_token = btchip_read_u32(G_io_apdu_buffer + request_token_offset, true, false);
    }

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode)) {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (!os_global_pin_is_validated()) {
        return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    PRINTF("pin ok\n");

    btchip_private_derive_keypair(keyPath, 1, chainCode);


    G_io_apdu_buffer[0] = 65;

    // Then encode it
    if (uncompressedPublicKeys) {
        keyLength = 65;
    } else {
        btchip_compress_public_key_value(btchip_public_key_D.W);
        keyLength = 33;
    }

    os_memmove(G_io_apdu_buffer + 1, btchip_public_key_D.W,
               sizeof(btchip_public_key_D.W));
    if (cashAddr) {
        uint8_t tmp[20];
        btchip_public_key_hash160(G_io_apdu_buffer + 1, // IN
                                  keyLength,            // INLEN
                                  tmp);
        keyLength =
            cashaddr_encode(tmp, 20, G_io_apdu_buffer + 67, 50, CASHADDR_P2PKH);
    } else if (G_coin_config->flags & FLAG_MULTICHAIN) {
        keyLength = multichainaddr_encode(
            G_io_apdu_buffer + 1,            // IN
            keyLength,                       // INLEN
            G_io_apdu_buffer + 67,           // OUT
            150,                             // MAXOUTLEN
            G_coin_config->mc_p2pkh_version, // VERSION
            G_coin_config->mc_addr_checksum, // CHECKSUM
            0                                // alreadyHashed
        );
    } else if (!(segwit || nativeSegwit)) {
        keyLength = btchip_public_key_to_encoded_base58(
            G_io_apdu_buffer + 1,  // IN
            keyLength,             // INLEN
            G_io_apdu_buffer + 67, // OUT
            150,                   // MAXOUTLEN
            btchip_context_D.payToAddressVersion, 0);
    } else {
        uint8_t tmp[22];
        tmp[0] = 0x00;
        tmp[1] = 0x14;
        btchip_public_key_hash160(G_io_apdu_buffer + 1, // IN
                                  keyLength,            // INLEN
                                  tmp + 2               // OUT
                                  );
        if (!nativeSegwit) {
            keyLength = btchip_public_key_to_encoded_base58(
                tmp,                   // IN
                22,                    // INLEN
                G_io_apdu_buffer + 67, // OUT
                150,                   // MAXOUTLEN
                btchip_context_D.payToScriptHashVersion, 0);
        } else {
            if (G_coin_config->native_segwit_prefix) {
                keyLength = segwit_addr_encode(
                    (char *)(G_io_apdu_buffer + 67),
                    PIC(G_coin_config->native_segwit_prefix), 0, tmp + 2, 20);
                if (keyLength == 1) {
                    keyLength = strlen((char *)(G_io_apdu_buffer + 67));
                }
            }
        }
    }
    G_io_apdu_buffer[66] = keyLength;
    PRINTF("Length %d\n", keyLength);
    if (!uncompressedPublicKeys) {
        // Restore for the full key component
        G_io_apdu_buffer[1] = 0x04;
    }

    // output chain code
    os_memmove(G_io_apdu_buffer + 1 + 65 + 1 + keyLength, chainCode,
               sizeof(chainCode));
    btchip_context_D.outLength = 1 + 65 + 1 + keyLength + sizeof(chainCode);

    if (display) {
        if (keyLength > 50) {
            return BTCHIP_SW_INCORRECT_DATA;
        }
        // Hax, avoid wasting space
        os_memmove(G_io_apdu_buffer + 200, G_io_apdu_buffer + 67, keyLength);
        G_io_apdu_buffer[200 + keyLength] = '\0';
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_display_public_key(keyPath);
    }
    // If the token requested has already been approved in a previous call, the source is trusted so don't ask for approval again
    else if(display_request_token &&
           (!btchip_context_D.has_valid_token || os_memcmp(&request_token, btchip_context_D.last_token, 4)))
    {
        // disable the has_valid_token flag and store the new token
        btchip_context_D.has_valid_token = false;
        os_memcpy(btchip_context_D.last_token, &request_token, 4);
        // Hax, avoid wasting space
        snprintf(G_io_apdu_buffer + 200, 9, "%08X", request_token);
        G_io_apdu_buffer[200 + 8] = '\0';
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_display_token();
    }
    else if(require_user_approval)
    {
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_request_pubkey_approval();
    }

    return BTCHIP_SW_OK;
}

void btchip_bagl_user_action_display(unsigned char confirming) {
    unsigned short sw = BTCHIP_SW_OK;
    // confirm and finish the apdu exchange //spaghetti
    if (confirming) {
        btchip_context_D.outLength -=
            2; // status was already set by the last call

    } else {
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);
}
