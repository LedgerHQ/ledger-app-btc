/*******************************************************************************
*   Ledger Blue - Bitcoin Wallet
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

#define SIGHASH_ALL 0x01

#ifdef HAVE_PART_SUPPORT
static const unsigned char order[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};
#endif

unsigned short btchip_apdu_hash_sign() {
    unsigned long int lockTime;
    uint32_t sighashType;
    unsigned char dataBuffer[8];
    unsigned char hash1[32];
    unsigned char hash2[32];
    unsigned char authorizationLength;
    unsigned char *parameters = G_io_apdu_buffer + ISO_OFFSET_CDATA;
    btchip_transaction_summary_t
        transactionSummary; // could be removed with a refactor
    unsigned char *authorization;
    unsigned short sw;
    unsigned char keyPath[MAX_BIP32_PATH_LENGTH];
    cx_sha256_t localHash;
#ifdef HAVE_PART_SUPPORT
    unsigned char lenSharedSecret;
#endif

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode)) {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if ((G_io_apdu_buffer[ISO_OFFSET_P1] != 0) &&
        (G_io_apdu_buffer[ISO_OFFSET_P2] != 0)) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_LC] < (1 + 1 + 4 + 1)) {
        return BTCHIP_SW_INCORRECT_LENGTH;
    }

    // Check state
    BEGIN_TRY {
        TRY {
            btchip_set_check_internal_structure_integrity(0);
            if (btchip_context_D.transactionContext.transactionState !=
                BTCHIP_TRANSACTION_SIGN_READY) {
                L_DEBUG_APP(
                    ("Invalid transaction state %d\n",
                     btchip_context_D.transactionContext.transactionState));
                sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                goto discardTransaction;
            }

            // Read parameters
            if (G_io_apdu_buffer[ISO_OFFSET_CDATA] > MAX_BIP32_PATH) {
                sw = BTCHIP_SW_INCORRECT_DATA;
            discardTransaction:
                CLOSE_TRY;
                goto catch_discardTransaction;
            }
            os_memmove(keyPath, G_io_apdu_buffer + ISO_OFFSET_CDATA,
                       MAX_BIP32_PATH_LENGTH);
            parameters += (4 * G_io_apdu_buffer[ISO_OFFSET_CDATA]) + 1;
            authorizationLength = *(parameters++);
            authorization = parameters;
            parameters += authorizationLength;
            lockTime = btchip_read_u32(parameters, 1, 0);
            parameters += 4;
            sighashType = *(parameters++);

            if (((N_btchip.bkp.config.options &
                  BTCHIP_OPTION_FREE_SIGHASHTYPE) == 0)) {
                // if bitcoin cash OR forkid is set, then use the fork id
                if (G_coin_config->kind == COIN_KIND_BITCOIN_CASH ||
                    G_coin_config->forkid) {
#define SIGHASH_FORKID 0x40
                    if (sighashType != (SIGHASH_ALL | SIGHASH_FORKID)) {
                        sw = BTCHIP_SW_INCORRECT_DATA;
                        goto discardTransaction;
                    }
                    sighashType |= (G_coin_config->forkid << 8);
                } else {
                    if (sighashType != SIGHASH_ALL) {
                        sw = BTCHIP_SW_INCORRECT_DATA;
                        goto discardTransaction;
                    }
                }
            }

            // Read transaction parameters
            // TODO : remove copy
            os_memmove(&transactionSummary,
                       &btchip_context_D.transactionSummary,
                       sizeof(transactionSummary));

            // Fetch the private key

            btchip_private_derive_keypair(keyPath, 0, NULL);

            // TODO optional : check the public key against the associated non
            // blank input to sign

#ifdef HAVE_PART_SUPPORT
            lenSharedSecret = *(parameters++);
            if (lenSharedSecret == 32)
            {
                cx_math_addm(btchip_private_key_D.d, btchip_private_key_D.d, parameters, order, 32);
            };
#endif
            // Finalize the hash

            btchip_write_u32_le(dataBuffer, lockTime);
            btchip_write_u32_le(dataBuffer + 4, sighashType);
            L_DEBUG_BUF(
                ("Finalize hash with\n", dataBuffer, sizeof(dataBuffer)));

            cx_hash(&btchip_context_D.transactionHashFull.header, CX_LAST,
                    dataBuffer, sizeof(dataBuffer), hash1);
            L_DEBUG_BUF(("Hash1\n", hash1, sizeof(hash1)));

            // Rehash
            cx_sha256_init(&localHash);
            cx_hash(&localHash.header, CX_LAST, hash1, sizeof(hash1), hash2);
            L_DEBUG_BUF(("Hash2\n", hash2, sizeof(hash2)));

            // Sign
            btchip_signverify_finalhash(
                &btchip_private_key_D, 1, hash2, sizeof(hash2),
                G_io_apdu_buffer, sizeof(G_io_apdu_buffer),
                ((N_btchip.bkp.config.options &
                  BTCHIP_OPTION_DETERMINISTIC_SIGNATURE) != 0));

            btchip_context_D.outLength = G_io_apdu_buffer[1] + 2;
            G_io_apdu_buffer[btchip_context_D.outLength++] = sighashType;

            sw = BTCHIP_SW_OK;

            // Then discard the transaction and reply
        }
        CATCH_ALL {
            sw = SW_TECHNICAL_DETAILS(0xF);
        catch_discardTransaction:
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
        }
        FINALLY {
            btchip_set_check_internal_structure_integrity(1);
            return sw;
        }
    }
    END_TRY;
}
