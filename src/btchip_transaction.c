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

#define DEBUG_LONG "%ld"

void check_transaction_available(unsigned char x) {
    if (btchip_context_D.transactionDataRemaining < x) {
        L_DEBUG_APP(("Check transaction available failed %d < %d\n",
                     btchip_context_D.transactionDataRemaining, x));
        THROW(EXCEPTION);
    }
}

#define OP_HASH160 0xA9
#define OP_EQUAL 0x87
#define OP_CHECKMULTISIG 0xAE

unsigned char transaction_amount_add_be(unsigned char *target,
                                        unsigned char WIDE *a,
                                        unsigned char WIDE *b) {
    unsigned char carry = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short val = a[8 - 1 - i] + b[8 - 1 - i] + (carry ? 1 : 0);
        carry = (val > 255);
        target[8 - 1 - i] = (val & 255);
    }
    return carry;
}

unsigned char transaction_amount_sub_be(unsigned char *target,
                                        unsigned char WIDE *a,
                                        unsigned char WIDE *b) {
    unsigned char borrow = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short tmpA = a[8 - 1 - i];
        unsigned short tmpB = b[8 - 1 - i];
        if (borrow) {
            if (tmpA <= tmpB) {
                tmpA += (255 + 1) - 1;
            } else {
                borrow = 0;
                tmpA--;
            }
        }
        if (tmpA < tmpB) {
            borrow = 1;
            tmpA += 255 + 1;
        }
        target[8 - 1 - i] = (unsigned char)(tmpA - tmpB);
    }
    return borrow;
}

void transaction_offset(unsigned char value) {
    if ((btchip_context_D.transactionHashOption & TRANSACTION_HASH_FULL) != 0) {
        L_DEBUG_BUF(("Add to hash full\n",
                     btchip_context_D.transactionBufferPointer, value));
        cx_hash(&btchip_context_D.transactionHashFull.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL);
    }
    if ((btchip_context_D.transactionHashOption &
         TRANSACTION_HASH_AUTHORIZATION) != 0) {
        cx_hash(&btchip_context_D.transactionHashAuthorization.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL);
    }
}

void transaction_offset_increase(unsigned char value) {
    transaction_offset(value);
    btchip_context_D.transactionBufferPointer += value;
    btchip_context_D.transactionDataRemaining -= value;
}

unsigned long int transaction_get_varint(void) {
    unsigned char firstByte;
    check_transaction_available(1);
    firstByte = *btchip_context_D.transactionBufferPointer;
    if (firstByte < 0xFD) {
        transaction_offset_increase(1);
        return firstByte;
    } else if (firstByte == 0xFD) {
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(2);
        result =
            (unsigned long int)(*btchip_context_D.transactionBufferPointer) |
            ((unsigned long int)(*(btchip_context_D.transactionBufferPointer +
                                   1))
             << 8);
        transaction_offset_increase(2);
        return result;
    } else if (firstByte == 0xFE) {
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(4);
        result =
            btchip_read_u32(btchip_context_D.transactionBufferPointer, 0, 0);
        transaction_offset_increase(4);
        return result;
    } else {
        L_DEBUG_APP(("Varint parsing failed\n"));
        THROW(INVALID_PARAMETER);
        return 0;
    }
}

void transaction_parse(unsigned char parseMode) {
    unsigned char optionP2SHSkip2FA =
        ((N_btchip.bkp.config.options & BTCHIP_OPTION_SKIP_2FA_P2SH) != 0);
    btchip_set_check_internal_structure_integrity(0);
    BEGIN_TRY {
        TRY {
            for (;;) {
                switch (btchip_context_D.transactionContext.transactionState) {
                case BTCHIP_TRANSACTION_NONE: {
                    L_DEBUG_APP(("Init transaction parser\n"));
                    // Reset transaction state
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs = 0;
                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;
                    btchip_context_D.transactionContext.scriptRemaining = 0;
                    os_memset(
                        btchip_context_D.transactionContext.transactionAmount,
                        0, sizeof(btchip_context_D.transactionContext
                                      .transactionAmount));
                    // TODO : transactionControlFid
                    // Reset hashes
                    cx_sha256_init(&btchip_context_D.transactionHashFull);
                    cx_sha256_init(
                        &btchip_context_D.transactionHashAuthorization);
                    if (btchip_context_D.usingSegwit) {
                        btchip_context_D.transactionHashOption = 0;
                        if (!btchip_context_D.segwitParsedOnce) {
                            cx_sha256_init(
                                &btchip_context_D.segwit.hash.hashPrevouts);
                            cx_sha256_init(
                                &btchip_context_D.segwit.hash.hashSequence);
                        } else {
                            L_DEBUG_APP(("Resume SegWit hash\n"));
                            L_DEBUG_BUF(
                                ("SEGWIT Version\n",
                                 btchip_context_D.transactionVersion,
                                 sizeof(btchip_context_D.transactionVersion)));
                            L_DEBUG_BUF(
                                ("SEGWIT HashedPrevouts\n",
                                 btchip_context_D.segwit.cache.hashedPrevouts,
                                 sizeof(btchip_context_D.segwit.cache
                                            .hashedPrevouts)));
                            L_DEBUG_BUF(
                                ("SEGWIT HashedSequence\n",
                                 btchip_context_D.segwit.cache.hashedSequence,
                                 sizeof(btchip_context_D.segwit.cache
                                            .hashedSequence)));
                            cx_hash(
                                &btchip_context_D.transactionHashFull.header, 0,
                                btchip_context_D.transactionVersion,
                                sizeof(btchip_context_D.transactionVersion),
                                NULL);
                            cx_hash(
                                &btchip_context_D.transactionHashFull.header, 0,
                                btchip_context_D.segwit.cache.hashedPrevouts,
                                sizeof(btchip_context_D.segwit.cache
                                           .hashedPrevouts),
                                NULL);
                            cx_hash(
                                &btchip_context_D.transactionHashFull.header, 0,
                                btchip_context_D.segwit.cache.hashedSequence,
                                sizeof(btchip_context_D.segwit.cache
                                           .hashedSequence),
                                NULL);
                            cx_hash(&btchip_context_D
                                         .transactionHashAuthorization.header,
                                    0,
                                    (unsigned char WIDE *)&btchip_context_D
                                        .segwit.cache,
                                    sizeof(btchip_context_D.segwit.cache),
                                    NULL);
                        }
                    }
                    // Parse the beginning of the transaction
                    // Version
                    check_transaction_available(4);
                    os_memmove(btchip_context_D.transactionVersion,
                               btchip_context_D.transactionBufferPointer, 4);
                    transaction_offset_increase(4);

                    if (G_coin_config->flags & FLAG_PEERCOIN_SUPPORT) {
                        if (btchip_context_D.coinFamily ==
                            BTCHIP_FAMILY_PEERCOIN) {
                            // Timestamp
                            check_transaction_available(4);
                            transaction_offset_increase(4);
                        }
                    }

                    // Number of inputs
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    L_DEBUG_APP(("Number of inputs : " DEBUG_LONG "\n",
                                 btchip_context_D.transactionContext
                                     .transactionRemainingInputsOutputs));
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;

                    // no break is intentional
                }

                case BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT: {
                    unsigned char trustedInputFlag = 1;
                    L_DEBUG_APP(("Process input\n"));
                    if (btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more inputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_INPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Proceed with the next input
                    if (parseMode == PARSE_MODE_TRUSTED_INPUT) {
                        check_transaction_available(
                            36); // prevout : 32 hash + 4 index
                        transaction_offset_increase(36);
                    }
                    if (parseMode == PARSE_MODE_SIGNATURE) {
                        unsigned char trustedInputLength;
                        unsigned char trustedInput[0x38];
                        unsigned char amount[8];
                        unsigned char *savePointer;

                        // Expect the trusted input flag and trusted input
                        // length
                        check_transaction_available(2);
                        switch (*btchip_context_D.transactionBufferPointer) {
                        case 0:
                            if (btchip_context_D.usingSegwit) {
                                L_DEBUG_APP(
                                    ("Non trusted input used in segwit mode"));
                                goto fail;
                            }
                            trustedInputFlag = 0;
                            break;
                        case 1:
                            if (btchip_context_D.usingSegwit) {
                                L_DEBUG_APP(
                                    ("Trusted input used in segwit mode"));
                                goto fail;
                            }
                            trustedInputFlag = 1;
                            break;
                        case 2:
                            if (!btchip_context_D.usingSegwit) {
                                L_DEBUG_APP(
                                    ("Segwit input not used in segwit mode"));
                                goto fail;
                            }
                            break;
                        default:
                            L_DEBUG_APP(("Invalid trusted input flag\n"));
                            goto fail;
                        }
                        /*
                        trustedInputLength =
                        *(btchip_context_D.transactionBufferPointer + 1);
                        if (trustedInputLength > sizeof(trustedInput)) {
                          L_DEBUG_APP(("Trusted input too long\n"));
                          goto fail;
                        }
                        */
                        if (btchip_context_D.usingSegwit) {
                            transaction_offset_increase(1);
                            check_transaction_available(
                                36); // prevout : 32 hash + 4 index
                            if (!btchip_context_D.segwitParsedOnce) {
                                cx_hash(
                                    &btchip_context_D.segwit.hash.hashPrevouts
                                         .header,
                                    0,
                                    btchip_context_D.transactionBufferPointer,
                                    36, NULL);
                                transaction_offset_increase(36);
                                check_transaction_available(8); // update amount
                                btchip_swap_bytes(
                                    amount,
                                    btchip_context_D.transactionBufferPointer,
                                    8);
                                if (transaction_amount_add_be(
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                        amount)) {
                                    L_DEBUG_APP(("Overflow\n"));
                                    goto fail;
                                }
                                L_DEBUG_BUF(
                                    ("Adding amount\n",
                                     btchip_context_D.transactionBufferPointer,
                                     8));
                                L_DEBUG_BUF(("New amount\n",
                                             btchip_context_D.transactionContext
                                                 .transactionAmount,
                                             8));
                                transaction_offset_increase(8);
                            } else {
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                                transaction_offset_increase(36);
                                btchip_context_D.transactionHashOption = 0;
                                check_transaction_available(8); // save amount
                                os_memmove(
                                    btchip_context_D.inputValue,
                                    btchip_context_D.transactionBufferPointer,
                                    8);
                                transaction_offset_increase(8);
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                            }
                        } else if (!trustedInputFlag) {
                            // Only authorized in relaxed wallet and server
                            // modes
                            SB_CHECK(N_btchip.bkp.config.operationMode);
                            switch (SB_GET(N_btchip.bkp.config.operationMode)) {
                            case BTCHIP_MODE_WALLET:
                                if (!optionP2SHSkip2FA) {
                                    L_DEBUG_APP(
                                        ("Untrusted input not authorized\n"));
                                    goto fail;
                                }
                                break;
                            case BTCHIP_MODE_RELAXED_WALLET:
                            case BTCHIP_MODE_SERVER:
                                break;
                            default:
                                L_DEBUG_APP(
                                    ("Untrusted input not authorized\n"));
                                goto fail;
                            }
                            btchip_context_D.transactionBufferPointer++;
                            btchip_context_D.transactionDataRemaining--;
                            check_transaction_available(
                                36); // prevout : 32 hash + 4 index
                            transaction_offset_increase(36);
                            L_DEBUG_APP(("Marking relaxed input\n"));
                            btchip_context_D.transactionContext.relaxed = 1;
                            /*
                            L_DEBUG_APP(("Clearing P2SH consumption\n"));
                            btchip_context_D.transactionContext.consumeP2SH = 0;
                            */
                        } else {
                            trustedInputLength = *(
                                btchip_context_D.transactionBufferPointer + 1);
                            if ((trustedInputLength > sizeof(trustedInput)) ||
                                (trustedInputLength < 8)) {
                                L_DEBUG_APP(("Invalid trusted input size\n"));
                                goto fail;
                            }

                            check_transaction_available(2 + trustedInputLength);
                            cx_hmac_sha256(
                                N_btchip.bkp.trustedinput_key,
                                sizeof(N_btchip.bkp.trustedinput_key),
                                btchip_context_D.transactionBufferPointer + 2,
                                trustedInputLength - 8, trustedInput);
                            if (btchip_secure_memcmp(
                                    trustedInput,
                                    btchip_context_D.transactionBufferPointer +
                                        2 + trustedInputLength - 8,
                                    8) != 0) {
                                L_DEBUG_APP(("Invalid signature\n"));
                                goto fail;
                            }
                            os_memmove(
                                trustedInput,
                                btchip_context_D.transactionBufferPointer + 2,
                                trustedInputLength - 8);
                            if (trustedInput[0] != MAGIC_TRUSTED_INPUT) {
                                L_DEBUG_APP(("Failed to verify trusted input "
                                             "signature\n"));
                                goto fail;
                            }
                            // Update the hash with prevout data
                            savePointer =
                                btchip_context_D.transactionBufferPointer;
                            /*
                            // Check if a P2SH script is used
                            if ((trustedInput[1] & FLAG_TRUSTED_INPUT_P2SH) ==
                            0) {
                              L_DEBUG_APP(("Clearing P2SH consumption\n"));
                              btchip_context_D.transactionContext.consumeP2SH =
                            0;
                            }
                            */
                            btchip_context_D.transactionBufferPointer =
                                trustedInput + 4;
                            L_DEBUG_BUF((
                                "Trusted input hash\n",
                                btchip_context_D.transactionBufferPointer, 36));
                            transaction_offset(36);

                            btchip_context_D.transactionBufferPointer =
                                savePointer + (2 + trustedInputLength);
                            btchip_context_D.transactionDataRemaining -=
                                (2 + trustedInputLength);

                            // Update the amount

                            btchip_swap_bytes(amount, trustedInput + 40, 8);
                            if (transaction_amount_add_be(
                                    btchip_context_D.transactionContext
                                        .transactionAmount,
                                    btchip_context_D.transactionContext
                                        .transactionAmount,
                                    amount)) {
                                L_DEBUG_APP(("Overflow\n"));
                                goto fail;
                            }

                            L_DEBUG_BUF(
                                ("Adding amount\n", (trustedInput + 40), 8));
                            L_DEBUG_BUF(("New amount\n",
                                         btchip_context_D.transactionContext
                                             .transactionAmount,
                                         8));
                        }

                        if (!btchip_context_D.usingSegwit) {
                            // Do not include the input script length + value in
                            // the authentication hash
                            btchip_context_D.transactionHashOption =
                                TRANSACTION_HASH_FULL;
                        }
                    }
                    // Read the script length
                    btchip_context_D.transactionContext.scriptRemaining =
                        transaction_get_varint();
                    L_DEBUG_APP(
                        ("Script to read " DEBUG_LONG "\n",
                         btchip_context_D.transactionContext.scriptRemaining));

                    if ((parseMode == PARSE_MODE_SIGNATURE) &&
                        !trustedInputFlag && !btchip_context_D.usingSegwit) {
                        // Only proceeds if this is not to be signed - so length
                        // should be null
                        if (btchip_context_D.transactionContext
                                .scriptRemaining != 0) {
                            L_DEBUG_APP(("Request to sign relaxed input\n"));
                            if (!optionP2SHSkip2FA) {
                                goto fail;
                            }
                        }
                    }
                    // Move on
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;

                    // no break is intentional
                }
                case BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    L_DEBUG_APP(
                        ("Process input script, remaining " DEBUG_LONG "\n",
                         btchip_context_D.transactionContext.scriptRemaining));
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Scan for P2SH consumption - huge shortcut, but fine
                    // enough
                    // Also usable in SegWit mode
                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        1) {
                        if (*btchip_context_D.transactionBufferPointer ==
                            OP_CHECKMULTISIG) {
                            if (optionP2SHSkip2FA) {
                                L_DEBUG_APP(("Marking P2SH consumption\n"));
                                btchip_context_D.transactionContext
                                    .consumeP2SH = 1;
                            }
                        } else {
                            // When using the P2SH shortcut, all inputs must use
                            // P2SH
                            L_DEBUG_APP(("Disabling P2SH consumption\n"));
                            btchip_context_D.transactionContext.consumeP2SH = 0;
                        }
                        transaction_offset_increase(1);
                        btchip_context_D.transactionContext.scriptRemaining--;
                    }

                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        if (parseMode == PARSE_MODE_SIGNATURE) {
                            if (!btchip_context_D.usingSegwit) {
                                // Restore dual hash for signature +
                                // authentication
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_BOTH;
                            } else {
                                if (btchip_context_D.segwitParsedOnce) {
                                    // Append the saved value
                                    L_DEBUG_BUF(("SEGWIT Add value\n",
                                                 btchip_context_D.inputValue,
                                                 8));

#ifdef HAVE_PART_SUPPORT
                                    char amountZero = 1;
                                    for (size_t k = 0; k < 8; ++k) {
                                        if (btchip_context_D.inputValue[k] == 0)
                                            continue;
                                        amountZero = 0;
                                        break;
                                    };
                                    if (!amountZero) // No amount on data output
#endif
                                    cx_hash(&btchip_context_D
                                                 .transactionHashFull.header,
                                            0, btchip_context_D.inputValue, 8,
                                            NULL);
                                }
                            }
                        }
                        // Sequence
                        check_transaction_available(4);
                        if (btchip_context_D.usingSegwit &&
                            !btchip_context_D.segwitParsedOnce) {
                            cx_hash(&btchip_context_D.segwit.hash.hashSequence
                                         .header,
                                    0,
                                    btchip_context_D.transactionBufferPointer,
                                    4, NULL);
                        }
                        transaction_offset_increase(4);
                        // Move to next input
                        btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs--;
                        btchip_context_D.transactionContext
                            .transactionCurrentInputOutput++;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;
                        continue;
                    }
                    // Save the last script byte for the P2SH check
                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                         .scriptRemaining -
                                     1
                             ? btchip_context_D.transactionContext
                                       .scriptRemaining -
                                   1
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }
                case BTCHIP_TRANSACTION_INPUT_HASHING_DONE: {
                    L_DEBUG_APP(("Input hashing done\n"));
                    if (parseMode == PARSE_MODE_SIGNATURE) {
                        // inputs have been prepared, stop the parsing here
                        if (btchip_context_D.usingSegwit &&
                            !btchip_context_D.segwitParsedOnce) {
                            unsigned char hashedPrevouts[32];
                            unsigned char hashedSequence[32];
                            // Flush the cache
                            cx_hash(&btchip_context_D.segwit.hash.hashPrevouts
                                         .header,
                                    CX_LAST, hashedPrevouts, 0, hashedPrevouts);
                            cx_sha256_init(
                                &btchip_context_D.segwit.hash.hashPrevouts);
                            cx_hash(&btchip_context_D.segwit.hash.hashPrevouts
                                         .header,
                                    CX_LAST, hashedPrevouts,
                                    sizeof(hashedPrevouts), hashedPrevouts);
                            cx_hash(&btchip_context_D.segwit.hash.hashSequence
                                         .header,
                                    CX_LAST, hashedSequence, 0, hashedSequence);
                            cx_sha256_init(
                                &btchip_context_D.segwit.hash.hashSequence);
                            cx_hash(&btchip_context_D.segwit.hash.hashSequence
                                         .header,
                                    CX_LAST, hashedSequence,
                                    sizeof(hashedSequence), hashedSequence);
                            os_memmove(
                                btchip_context_D.segwit.cache.hashedPrevouts,
                                hashedPrevouts, sizeof(hashedPrevouts));
                            os_memmove(
                                btchip_context_D.segwit.cache.hashedSequence,
                                hashedSequence, sizeof(hashedSequence));
                            L_DEBUG_BUF(
                                ("hashPrevout\n",
                                 btchip_context_D.segwit.cache.hashedPrevouts,
                                 32));
                            L_DEBUG_BUF(
                                ("hashSequence\n",
                                 btchip_context_D.segwit.cache.hashedSequence,
                                 32));
                        }
                        if (btchip_context_D.usingSegwit &&
                            btchip_context_D.segwitParsedOnce) {
                            L_DEBUG_BUF(
                                ("SEGWIT hashedOutputs\n",
                                 btchip_context_D.segwit.cache.hashedOutputs,
                                 sizeof(btchip_context_D.segwit.cache
                                            .hashedOutputs)));
                            cx_hash(
                                &btchip_context_D.transactionHashFull.header, 0,
                                btchip_context_D.segwit.cache.hashedOutputs,
                                sizeof(btchip_context_D.segwit.cache
                                           .hashedOutputs),
                                NULL);
                            btchip_context_D.transactionContext
                                .transactionState =
                                BTCHIP_TRANSACTION_SIGN_READY;
                        } else {
                            btchip_context_D.transactionContext
                                .transactionState =
                                BTCHIP_TRANSACTION_PRESIGN_READY;
                        }
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Number of outputs
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;
                    L_DEBUG_APP(("Number of outputs : " DEBUG_LONG "\n",
                                 btchip_context_D.transactionContext
                                     .transactionRemainingInputsOutputs));
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;

                    // no break is intentional
                }
                case BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT: {
                    if (btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more outputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Amount
                    check_transaction_available(8);
                    if ((parseMode == PARSE_MODE_TRUSTED_INPUT) &&
                        (btchip_context_D.transactionContext
                             .transactionCurrentInputOutput ==
                         btchip_context_D.transactionTargetInput)) {
                        // Save the amount
                        os_memmove(btchip_context_D.transactionContext
                                       .transactionAmount,
                                   btchip_context_D.transactionBufferPointer,
                                   8);
                        btchip_context_D.trustedInputProcessed = 1;
                    }
                    transaction_offset_increase(8);
                    // Read the script length
                    btchip_context_D.transactionContext.scriptRemaining =
                        transaction_get_varint();

                    L_DEBUG_APP(
                        ("Script to read " DEBUG_LONG "\n",
                         btchip_context_D.transactionContext.scriptRemaining));
                    // Move on
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;

                    // no break is intentional
                }
                case BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    L_DEBUG_APP(
                        ("Process output script, remaining " DEBUG_LONG "\n",
                         btchip_context_D.transactionContext.scriptRemaining));
                    /*
                    // Special check if consuming a P2SH script
                    if (parseMode == PARSE_MODE_TRUSTED_INPUT) {
                      // Assume the full input script is sent in a single APDU,
                    then do the ghetto validation
                      if ((btchip_context_D.transactionBufferPointer[0] ==
                    OP_HASH160) &&
                          (btchip_context_D.transactionBufferPointer[btchip_context_D.transactionDataRemaining
                    - 1] == OP_EQUAL)) {
                        L_DEBUG_APP(("Marking P2SH output\n"));
                        btchip_context_D.transactionContext.consumeP2SH = 1;
                      }
                    }
                    */
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        // Move to next output
                        btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs--;
                        btchip_context_D.transactionContext
                            .transactionCurrentInputOutput++;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;
                        continue;
                    }
                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                     .scriptRemaining
                             ? btchip_context_D.transactionContext
                                   .scriptRemaining
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }
                case BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE: {
                    L_DEBUG_APP(("Output hashing done\n"));
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Locktime
                    check_transaction_available(4);
                    transaction_offset_increase(4);

                    if (btchip_context_D.transactionDataRemaining == 0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PARSED;
                        continue;
                    } else {
                        btchip_context_D.transactionHashOption = 0;
                        btchip_context_D.transactionContext.scriptRemaining =
                            transaction_get_varint();
                        btchip_context_D.transactionHashOption =
                            TRANSACTION_HASH_FULL;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_EXTRA;
                        continue;
                    }
                }

                case BTCHIP_TRANSACTION_PROCESS_EXTRA: {
                    unsigned char dataAvailable;

                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PARSED;
                        continue;
                    }

                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }

                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                     .scriptRemaining
                             ? btchip_context_D.transactionContext
                                   .scriptRemaining
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }

                case BTCHIP_TRANSACTION_PARSED: {
                    L_DEBUG_APP(("Transaction parsed\n"));
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PRESIGN_READY: {
                    L_DEBUG_APP(("Presign ready\n"));
                    goto ok;
                }

                case BTCHIP_TRANSACTION_SIGN_READY: {
                    L_DEBUG_APP(("Sign ready\n"));
                    goto ok;
                }
                }
            }

        fail:
            L_DEBUG_APP(("Transaction parse - fail\n"));
            THROW(EXCEPTION);
        ok : {}
        }
        CATCH_OTHER(e) {
            L_DEBUG_APP(("Transaction parse - surprise fail\n"));
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
            btchip_set_check_internal_structure_integrity(1);
            THROW(e);
        }
        // before the finally to restore the surrounding context if an exception
        // is raised during finally
        FINALLY {
            btchip_set_check_internal_structure_integrity(1);
        }
    }
    END_TRY;
}
