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

#define SCRATCH_SIZE 21

unsigned char
btchip_convert_hex_amount_to_displayable(unsigned char WIDE *amount) {
    unsigned char LOOP1;
    unsigned char LOOP2;
    if (!(G_coin_config->flags & FLAG_PEERCOIN_UNITS)) {
        LOOP1 = 13;
        LOOP2 = 8;
    } else {
        LOOP1 = 15;
        LOOP2 = 6;
    }
    unsigned short scratch[SCRATCH_SIZE];
    unsigned char offset = 0;
    unsigned char nonZero = 0;
    unsigned char i;
    unsigned char targetOffset = 0;
    unsigned char workOffset;
    unsigned char j;
    unsigned char nscratch = SCRATCH_SIZE;
    unsigned char smin = nscratch - 2;
    unsigned char comma = 0;

    for (i = 0; i < SCRATCH_SIZE; i++) {
        scratch[i] = 0;
    }
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            unsigned char k;
            unsigned short shifted_in =
                (((amount[i] & 0xff) & ((1 << (7 - j)))) != 0) ? (short)1
                                                               : (short)0;
            for (k = smin; k < nscratch; k++) {
                scratch[k] += ((scratch[k] >= 5) ? 3 : 0);
            }
            if (scratch[smin] >= 8) {
                smin -= 1;
            }
            for (k = smin; k < nscratch - 1; k++) {
                scratch[k] =
                    ((scratch[k] << 1) & 0xF) | ((scratch[k + 1] >= 8) ? 1 : 0);
            }
            scratch[nscratch - 1] = ((scratch[nscratch - 1] << 1) & 0x0F) |
                                    (shifted_in == 1 ? 1 : 0);
        }
    }

    for (i = 0; i < LOOP1; i++) {
        if (!nonZero && (scratch[offset] == 0)) {
            offset++;
        } else {
            nonZero = 1;
            btchip_context_D.tmp[targetOffset++] = scratch[offset++] + '0';
        }
    }
    if (targetOffset == 0) {
        btchip_context_D.tmp[targetOffset++] = '0';
    }
    workOffset = offset;
    for (i = 0; i < LOOP2; i++) {
        unsigned char allZero = 1;
        unsigned char j;
        for (j = i; j < LOOP2; j++) {
            if (scratch[workOffset + j] != 0) {
                allZero = 0;
                break;
            }
        }
        if (allZero) {
            break;
        }
        if (!comma) {
            btchip_context_D.tmp[targetOffset++] = '.';
            comma = 1;
        }
        btchip_context_D.tmp[targetOffset++] = scratch[offset++] + '0';
    }
    return targetOffset;
}
