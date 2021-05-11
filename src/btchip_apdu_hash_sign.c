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
#include "btchip_display_variables.h"

#define SIGHASH_ALL 0x01

unsigned short btchip_apdu_hash_sign() {
    unsigned long int lockTime;
    uint32_t sighashType;
    unsigned char dataBuffer[8];
    unsigned char authorizationLength;
    unsigned char *parameters = G_io_apdu_buffer + ISO_OFFSET_CDATA;
    unsigned short sw;

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode)) {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if ((G_io_apdu_buffer[ISO_OFFSET_P1] != 0) ||
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

            // Zcash special - store parameters for later

            #ifndef USE_NO_OVERWINTER
            if ((btchip_context_D.usingOverwinter) &&
                (!btchip_context_D.overwinterSignReady) &&
                (btchip_context_D.segwitParsedOnce) &&
                (btchip_context_D.transactionContext.transactionState == BTCHIP_TRANSACTION_NONE)) {
                unsigned long int expiryHeight;
                parameters += (4 * G_io_apdu_buffer[ISO_OFFSET_CDATA]) + 1;
                authorizationLength = *(parameters++);
                parameters += authorizationLength;
                lockTime = btchip_read_u32(parameters, 1, 0);
                parameters += 4;
                sighashType = *(parameters++);
                expiryHeight = btchip_read_u32(parameters, 1, 0);
                btchip_write_u32_le(btchip_context_D.nLockTime, lockTime);
                btchip_write_u32_le(btchip_context_D.sigHashType, sighashType);
                btchip_write_u32_le(btchip_context_D.nExpiryHeight, expiryHeight);
                btchip_context_D.overwinterSignReady = 1;
                CLOSE_TRY;
                return BTCHIP_SW_OK;
            }
            #endif

            if (btchip_context_D.transactionContext.transactionState !=
                BTCHIP_TRANSACTION_SIGN_READY) {
                PRINTF("Invalid transaction state %d\n", btchip_context_D.transactionContext.transactionState);
                sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                goto discardTransaction;
            }

            #ifndef USE_NO_OVERWINTER
            if (btchip_context_D.usingOverwinter && !btchip_context_D.overwinterSignReady) {
                PRINTF("Overwinter not ready to sign\n");
                sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                goto discardTransaction;
            }
            #endif

            // Read parameters
            if (G_io_apdu_buffer[ISO_OFFSET_CDATA] > MAX_BIP32_PATH) {
                sw = BTCHIP_SW_INCORRECT_DATA;
            discardTransaction:
                CLOSE_TRY;
                goto catch_discardTransaction;
            }
            os_memmove(btchip_context_D.transactionSummary.keyPath,
                G_io_apdu_buffer + ISO_OFFSET_CDATA,
                MAX_BIP32_PATH_LENGTH);
            parameters += (4 * G_io_apdu_buffer[ISO_OFFSET_CDATA]) + 1;
            authorizationLength = *(parameters++);
            parameters += authorizationLength;
            lockTime = btchip_read_u32(parameters, 1, 0);
            parameters += 4;
            sighashType = *(parameters++);
            btchip_context_D.transactionSummary.sighashType = sighashType;

            if (((N_btchip.bkp.config.options &
                  BTCHIP_OPTION_FREE_SIGHASHTYPE) == 0)) {
                // if bitcoin cash OR forkid is set, then use the fork id
                if (G_coin_config->kind == COIN_KIND_BITCOIN_CASH ||
                    (G_coin_config->forkid)) {
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

            // Finalize the hash
            if (!btchip_context_D.usingOverwinter) {
                btchip_write_u32_le(dataBuffer, lockTime);
                btchip_write_u32_le(dataBuffer + 4, sighashType);
                #ifdef HAVE_QTUM_SUPPORT
                if(btchip_context_D.signOpSender)
                {
                    btchip_hash_sender_finalize(dataBuffer, sizeof(dataBuffer));
                }
                else
                #endif
                {
                    PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(dataBuffer), dataBuffer);
                    cx_hash(&btchip_context_D.transactionHashFull.sha256.header, 0,
                        dataBuffer, sizeof(dataBuffer), NULL, 0);
                }
            }

            // Check if the path needs to be enforced
            if (!enforce_bip44_coin_type(btchip_context_D.transactionSummary.keyPath, false)) {
                btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
                btchip_bagl_request_sign_path_approval(btchip_context_D.transactionSummary.keyPath);
            }
            else {
                // Sign immediately
                btchip_bagl_user_action_signtx(1, 1);
            }
            sw = BTCHIP_SW_OK;
            if (btchip_context_D.called_from_swap) {
                // if we signed all outputs we should exit,
                // but only after sending response, so lets raise the
                // vars.swap_data.should_exit flag and check it on timer later
                vars.swap_data.alreadySignedInputs++;
                if (vars.swap_data.alreadySignedInputs >= vars.swap_data.totalNumberOfInputs) {
                    vars.swap_data.should_exit = 1;
                }
            }

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

void btchip_bagl_user_action_signtx(unsigned char confirming, unsigned char direct) {
    cx_ecfp_private_key_t private_key;
    unsigned short sw = BTCHIP_SW_OK;
    // confirm and finish the apdu exchange //spaghetti
    if (confirming) {
        unsigned char hash[32];
        // Fetch the private key
        btchip_private_derive_keypair(btchip_context_D.transactionSummary.keyPath, 0, NULL, &private_key, NULL);
        #ifndef USE_NO_OVERWINTER
        if (btchip_context_D.usingOverwinter) {
            cx_hash(&btchip_context_D.transactionHashFull.blake2b.header, CX_LAST, hash, 0, hash, 32);
        }
        else
        #endif
        {
            cx_sha256_t localHash;
            #ifdef HAVE_QTUM_SUPPORT
            if(btchip_context_D.signOpSender)
            {
                cx_hash(&btchip_context_D.transactionOutputHash.header, CX_LAST,
                    hash, 0, hash, 32);
            }
            else
            #endif
            {
                cx_hash(&btchip_context_D.transactionHashFull.sha256.header, CX_LAST,
                    hash, 0, hash, 32);
            }
            PRINTF("Hash1\n%.*H\n", sizeof(hash), hash);

            // Rehash
            cx_sha256_init(&localHash);
            cx_hash(&localHash.header, CX_LAST, hash, sizeof(hash), hash, 32);
        }
        PRINTF("Hash2\n%.*H\n", sizeof(hash), hash);
        // Sign
        btchip_sign_finalhash(
            &private_key, hash, sizeof(hash),
            G_io_apdu_buffer, sizeof(G_io_apdu_buffer),
            ((N_btchip.bkp.config.options &
                BTCHIP_OPTION_DETERMINISTIC_SIGNATURE) != 0));

        btchip_context_D.outLength = G_io_apdu_buffer[1] + 2;
        G_io_apdu_buffer[btchip_context_D.outLength++] = btchip_context_D.transactionSummary.sighashType;
    } else {
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }

    if (!direct) {
        G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
        G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);
    }
}

