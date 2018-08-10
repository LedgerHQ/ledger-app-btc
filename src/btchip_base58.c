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

unsigned char btchip_decode_base58(unsigned char WIDE *in, unsigned char length,
                                   unsigned char *out,
                                   unsigned char maxoutlen) {
    unsigned char tmp[164];
    unsigned char buffer[164];
    unsigned char i;
    unsigned char j;
    unsigned char startAt;
    unsigned char zeroCount = 0;
    if (length > sizeof(tmp)) {
        THROW(INVALID_PARAMETER);
    }
    os_memmove(tmp, in, length);
    L_DEBUG_BUF(("To decode\n", tmp, length));
    for (i = 0; i < length; i++) {
        if (in[i] > 128) {
            THROW(EXCEPTION);
        }
        tmp[i] = BASE58TABLE[in[i]];
        if (tmp[i] == 0xff) {
            THROW(EXCEPTION);
        }
    }
    while ((zeroCount < length) && (tmp[zeroCount] == 0)) {
        ++zeroCount;
    }
    j = length;
    startAt = zeroCount;
    while (startAt < length) {
        unsigned short remainder = 0;
        unsigned char divLoop;
        for (divLoop = startAt; divLoop < length; divLoop++) {
            unsigned short digit256 = (unsigned short)(tmp[divLoop] & 0xff);
            unsigned short tmpDiv = remainder * 58 + digit256;
            tmp[divLoop] = (unsigned char)(tmpDiv / 256);
            remainder = (tmpDiv % 256);
        }
        if (tmp[startAt] == 0) {
            ++startAt;
        }
        buffer[--j] = (unsigned char)remainder;
    }
    while ((j < length) && (buffer[j] == 0)) {
        ++j;
    }
    length = length - (j - zeroCount);
    if (maxoutlen < length) {
        L_DEBUG_APP(("Decode overflow %d %d\n", length, maxoutlen));
        THROW(EXCEPTION_OVERFLOW);
    }
    os_memmove(out, buffer + j - zeroCount, length);
    L_DEBUG_BUF(("Decoded\n", out, length));
    return length;
}

unsigned char btchip_encode_base58(unsigned char WIDE *in, unsigned char length,
                                   unsigned char *out,
                                   unsigned char maxoutlen) {
    unsigned char tmp[164];
    unsigned char buffer[164];
    unsigned char j;
    unsigned char startAt;
    unsigned char zeroCount = 0;
    if (length > sizeof(tmp)) {
        THROW(INVALID_PARAMETER);
    }
    os_memmove(tmp, in, length);
    L_DEBUG_APP(("Length to encode %d\n", length));
    L_DEBUG_BUF(("To encode\n", tmp, length));
    while ((zeroCount < length) && (tmp[zeroCount] == 0)) {
        ++zeroCount;
    }
    j = 2 * length;
    startAt = zeroCount;
    while (startAt < length) {
        unsigned short remainder = 0;
        unsigned char divLoop;
        for (divLoop = startAt; divLoop < length; divLoop++) {
            unsigned short digit256 = (unsigned short)(tmp[divLoop] & 0xff);
            unsigned short tmpDiv = remainder * 256 + digit256;
            tmp[divLoop] = (unsigned char)(tmpDiv / 58);
            remainder = (tmpDiv % 58);
        }
        if (tmp[startAt] == 0) {
            ++startAt;
        }
        buffer[--j] = (unsigned char)BASE58ALPHABET[remainder];
    }
    while ((j < (2 * length)) && (buffer[j] == BASE58ALPHABET[0])) {
        ++j;
    }
    while (zeroCount-- > 0) {
        buffer[--j] = BASE58ALPHABET[0];
    }
    length = 2 * length - j;
    if (maxoutlen < length) {
        L_DEBUG_APP(("Encode overflow %d %d\n", length, maxoutlen));
        THROW(EXCEPTION_OVERFLOW);
    }
    os_memmove(out, (buffer + j), length);
    L_DEBUG_APP(("Length encoded %d\n", length));
    L_DEBUG_BUF(("Encoded\n", out, length));
    return length;
}
