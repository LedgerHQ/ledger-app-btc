/* Copyright (c) 2019 Smirnov Dmitry
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "os.h"
#include "cx.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "multichainaddr.h"
#include "btchip_internal.h"

unsigned char get_uint_buffer_index(unsigned int uint, unsigned char i) {
    unsigned char uintSize = 1;

    if (uint > 16777215) {
        uintSize = 4;
    } else if (uint > 65535) {
        uintSize = 3;
    } else if (uint > 255) {
        uintSize = 2;
    }

    if (uintSize == 4) {
        if (i == 0) {
            return (uint >> 24) & 0xFF;
        } else if (i == 1) {
            return (uint >> 16) & 0xFF;
        } else if (i == 2) {
            return (uint >> 8) & 0xFF;
        } else if (i == 3) {
             return uint & 0xFF;
         }
    } else if (uintSize == 3) {
       if (i == 0) {
           return (uint >> 16) & 0xFF;
       } else if (i == 1) {
           return (uint >> 8) & 0xFF;
       } else if (i == 2) {
           return uint & 0xFF;
       }
   } else if (uintSize == 2) {
       if (i == 0) {
           return (uint >> 8) & 0xFF;
       } else if (i == 1) {
           return uint & 0xFF;
       }
   } else if (uintSize == 1) {
       if (i == 0) {
           return uint & 0xFF;
       }
   }

   return 0;
}

// https://www.multichain.com/developers/address-key-format/
int multichainaddr_encode(unsigned char *in, unsigned short inlen, unsigned char *out,
                          unsigned short outlen, unsigned int version, unsigned int checksum, unsigned char alreadyHashed) {
    unsigned char versionSize = 1;

    if (version > 16777215) {
        versionSize = 4;
    } else if (version > 65535) {
        versionSize = 3;
    } else if (version > 255) {
        versionSize = 2;
    }

    unsigned char tmpBuffer[20 + 4 + versionSize];
    unsigned char checksumBuffer[32];
    cx_sha256_t hash;
    unsigned char i;

    size_t outputLen;

    // Add the first version byte from the address-pubkeyhash-version blockchain parameter to the start of the RIPEMD-160 hash.
    tmpBuffer[0] = get_uint_buffer_index(version, 0);

    if (!alreadyHashed) {
        btchip_public_key_hash160(in, inlen, tmpBuffer + 1);
    } else {
        os_memmove(tmpBuffer + 1, in, inlen);
    }

    // If it is more than one byte long, insert each subsequent byte of it after every floor(20/len(address-pubkeyhash-version)) bytes of the hash.
    // Positions: 0, 6, 12, 18
    if (versionSize >= 2) {
        for (i = 20 + 4 + versionSize - 1; i > 6; i--) {
            tmpBuffer[i] = tmpBuffer[i - 1];
        }
        tmpBuffer[6] = get_uint_buffer_index(version, 1);
    }
    if (versionSize >= 3) {
        for (i = 20 + 4 + versionSize - 1; i > 12; i--) {
            tmpBuffer[i] = tmpBuffer[i - 1];
        }
        tmpBuffer[12] = get_uint_buffer_index(version, 2);
    }
    if (versionSize >= 4) {
        for (i = 20 + 4 + versionSize - 1; i > 18; i--) {
            tmpBuffer[i] = tmpBuffer[i - 1];
        }
        tmpBuffer[18] = get_uint_buffer_index(version, 3);
    }

    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, tmpBuffer, 20 + versionSize, checksumBuffer, 32);
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, checksumBuffer, 32, checksumBuffer, 32);

    // XOR this checksum with the address-checksum-value blockchain parameter
    for (i = 0; i < versionSize; i++) {
        checksumBuffer[i] = checksumBuffer[i] ^ get_uint_buffer_index(checksum, i);
    }

    os_memmove(tmpBuffer + 20 + versionSize, checksumBuffer, 4);

    outputLen = outlen;
    if (btchip_encode_base58(tmpBuffer, 20 + 4 + versionSize, out, &outputLen) < 0) {
        THROW(EXCEPTION);
    }
    return outputLen;
}
