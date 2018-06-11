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

const unsigned char TRANSACTION_OUTPUT_SCRIPT_PRE[] = {
    0x19, 0x76, 0xA9,
    0x14}; // script length, OP_DUP, OP_HASH160, address length
const unsigned char TRANSACTION_OUTPUT_SCRIPT_POST[] = {
    0x88, 0xAC}; // OP_EQUALVERIFY, OP_CHECKSIG

const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = {
    0x17, 0xA9, 0x14}; // script length, OP_HASH160, address length
const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = {0x87}; // OP_EQUAL

const unsigned char ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = {
        0x3D, 0xA9,
        0x14}; // script length, OP_HASH160, address length

const unsigned char ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = {
        0x87, // OP_EQUAL
        0x20, 0x9E, 0xC9, 0x84, 0x5A, 0xCB, 0x02, 0xFA, 0XB2, 0X4E,
        0x1C, 0x03, 0x68, 0xB3, 0xB5, 0x17, 0xC1, 0xA4, 0x48, 0x8F,
        0xBA, 0x97, 0xF0, 0xE3, 0x45, 0x9A, 0xC0, 0x53, 0xEA, 0x01,
        0x00, 0x00, 0x00, // ParamHash
        0x03, // Push 3 bytes to stack to make ParamHeight line up properly
        0xC0, 0x1F, 0x02, // ParamHeight (139200) -> hex -> endianness swapped
        0xB4};            // OP_CHECKBLOCKATHEIGHT

const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE[] = {0x16, 0x00, 0x14};
const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE[] = {0x22, 0x00, 0x20};

const unsigned char ZEN_OUTPUT_SCRIPT_PRE[] = {
    0x3F, 0x76, 0xA9,
    0x14}; // script length, OP_DUP, OP_HASH160, address length
const unsigned char ZEN_OUTPUT_SCRIPT_POST[] = {
    0x88, 0xAC, // OP_EQUALVERIFY, OP_CHECKSIG
    0x20, 0x9e, 0xc9, 0x84, 0x5a, 0xcb, 0x02, 0xfa, 0xb2, 0x4e, 0x1c, 0x03,
    0x68, 0xb3, 0xb5, 0x17, 0xc1, 0xa4, 0x48, 0x8f, 0xba, 0x97, 0xf0, 0xe3,
    0x45, 0x9a, 0xc0, 0x53, 0xea, 0x01, 0x00, 0x00, 0x00, // ParamHash
    0x03, // Push 3 bytes to stack to make ParamHeight line up properly
    0xc0, 0x1f, 0x02, // ParamHeight (139200) -> hex -> endianness swapped
    0xb4              // OP_CHECKBLOCKATHEIGHT
};                    // BIP0115 Replay Protection

unsigned char btchip_output_script_is_regular(unsigned char *buffer) {
    if (G_coin_config->native_segwit_prefix) {
        if ((os_memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE)) == 0) ||
            (os_memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE)) == 0)) {
            return 1;
        }
    }
    if (G_coin_config->kind == COIN_KIND_ZENCASH) {
        if ((os_memcmp(buffer, ZEN_OUTPUT_SCRIPT_PRE,
                       sizeof(ZEN_OUTPUT_SCRIPT_PRE)) == 0) &&
            (os_memcmp(buffer + sizeof(ZEN_OUTPUT_SCRIPT_PRE) + 20,
                       ZEN_OUTPUT_SCRIPT_POST,
                       sizeof(ZEN_OUTPUT_SCRIPT_POST)) == 0)) {
            return 1;
        }
    } else {
        if ((os_memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_PRE)) == 0) &&
            (os_memcmp(buffer + sizeof(TRANSACTION_OUTPUT_SCRIPT_PRE) + 20,
                       TRANSACTION_OUTPUT_SCRIPT_POST,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_POST)) == 0)) {
            return 1;
        }
    }
    return 0;
}

unsigned char btchip_output_script_is_p2sh(unsigned char *buffer) {
    if (G_coin_config->kind == COIN_KIND_ZENCASH) {
        if ((os_memcmp(buffer, ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE,
                       sizeof(ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)) == 0) &&
            (os_memcmp(buffer + sizeof(ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE) + 20,
                       ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_POST,
                       sizeof(ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)) == 0)) {
            return 1;
        }
    } else {
        if ((os_memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)) == 0) &&
            (os_memcmp(buffer + sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE) + 20,
                       TRANSACTION_OUTPUT_SCRIPT_P2SH_POST,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)) == 0)) {
            return 1;
        }
    }
    return 0;
}

unsigned char btchip_output_script_is_native_witness(unsigned char *buffer) {
    if (G_coin_config->native_segwit_prefix) {
        if ((os_memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE)) == 0) ||
            (os_memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE)) == 0)) {
            return 1;
        }
    }
    return 0;
}

unsigned char btchip_output_script_is_op_return(unsigned char *buffer) {
    return (buffer[1] == 0x6A);
}

unsigned char btchip_output_script_is_op_create(unsigned char *buffer) {
    return (!btchip_output_script_is_regular(buffer) &&
            !btchip_output_script_is_p2sh(buffer) &&
            !btchip_output_script_is_op_return(buffer) && (buffer[0] <= 0xEA) &&
            (buffer[buffer[0]] == 0xC1));
}

unsigned char btchip_output_script_is_op_call(unsigned char *buffer) {
    return (!btchip_output_script_is_regular(buffer) &&
            !btchip_output_script_is_p2sh(buffer) &&
            !btchip_output_script_is_op_return(buffer) && (buffer[0] <= 0xEA) &&
            (buffer[buffer[0]] == 0xC2));
}

#ifdef HAVE_PART_SUPPORT
unsigned char btchip_output_script_is_coldstake(unsigned char *buffer) {
    static const unsigned char OP_ISCOINSTAKE = 0xb8;
    static const unsigned char OP_HASH160 = 0xa9;

    //if (buffer[0] == 64 &&
    if (buffer[1] == OP_ISCOINSTAKE
        && buffer[4] == OP_HASH160)
        return 1;

    return 0;
}
#endif

unsigned char btchip_rng_u8_modulo(unsigned char modulo) {
    unsigned int rng_max = 256 % modulo;
    unsigned int rng_limit = 256 - rng_max;
    unsigned char candidate;
    while ((candidate = cx_rng_u8()) > rng_limit)
        ;
    return (candidate % modulo);
}

unsigned char btchip_secure_memcmp(const void WIDE *buf1, const void WIDE *buf2,
                                   unsigned short length) {
    unsigned char error = 0;
    while (length--) {
        error |= ((unsigned char WIDE *)buf1)[length] ^
                 ((unsigned char WIDE *)buf2)[length];
    }
    if (length != 0xffff) {
        return 1;
    }
    return error;
}

unsigned long int btchip_read_u32(unsigned char WIDE *buffer, unsigned char be,
                                  unsigned char skipSign) {
    unsigned char i;
    unsigned long int result = 0;
    unsigned char shiftValue = (be ? 24 : 0);
    for (i = 0; i < 4; i++) {
        unsigned char x = (unsigned char)buffer[i];
        if ((i == 0) && skipSign) {
            x &= 0x7f;
        }
        result += ((unsigned long int)x) << shiftValue;
        if (be) {
            shiftValue -= 8;
        } else {
            shiftValue += 8;
        }
    }
    return result;
}

void btchip_write_u32_be(unsigned char *buffer, unsigned long int value) {
    buffer[0] = ((value >> 24) & 0xff);
    buffer[1] = ((value >> 16) & 0xff);
    buffer[2] = ((value >> 8) & 0xff);
    buffer[3] = (value & 0xff);
}

void btchip_write_u32_le(unsigned char *buffer, unsigned long int value) {
    buffer[0] = (value & 0xff);
    buffer[1] = ((value >> 8) & 0xff);
    buffer[2] = ((value >> 16) & 0xff);
    buffer[3] = ((value >> 24) & 0xff);
}

void btchip_retrieve_keypair_discard(unsigned char WIDE *privateComponent,
                                     unsigned char derivePublic) {
    BEGIN_TRY {
        TRY {
            cx_ecdsa_init_private_key(BTCHIP_CURVE, privateComponent, 32,
                                      &btchip_private_key_D);

            L_DEBUG_BUF(("Using private component\n", privateComponent, 32));

            if (derivePublic) {
                cx_ecfp_generate_pair(BTCHIP_CURVE, &btchip_public_key_D,
                                      &btchip_private_key_D, 1);
            }
        }
        FINALLY {
        }
    }
    END_TRY;
}

void btchip_public_key_hash160(unsigned char WIDE *in, unsigned short inlen,
                               unsigned char *out) {
    union {
        cx_sha256_t shasha;
        cx_ripemd160_t riprip;
    } u;
    unsigned char buffer[32];

    cx_sha256_init(&u.shasha);
    cx_hash(&u.shasha.header, CX_LAST, in, inlen, buffer);
    cx_ripemd160_init(&u.riprip);
    cx_hash(&u.riprip.header, CX_LAST, buffer, 32, out);
}

unsigned short btchip_public_key_to_encoded_base58(
    unsigned char WIDE *in, unsigned short inlen, unsigned char *out,
    unsigned short outlen, unsigned short version,
    unsigned char alreadyHashed) {
    unsigned char tmpBuffer[26];
    unsigned char checksumBuffer[32];
    cx_sha256_t hash;
    unsigned char versionSize = (version > 255 ? 2 : 1);

    if (!alreadyHashed) {
        L_DEBUG_BUF(("To hash\n", in, inlen));
        btchip_public_key_hash160(in, inlen, tmpBuffer + versionSize);
        L_DEBUG_BUF(("Hash160\n", (tmpBuffer + versionSize), 20));
        if (version > 255) {
            tmpBuffer[0] = (version >> 8);
            tmpBuffer[1] = version;
        } else {
            tmpBuffer[0] = version;
        }
    } else {
        os_memmove(tmpBuffer, in, 20 + versionSize);
    }

    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, tmpBuffer, 20 + versionSize, checksumBuffer);
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, checksumBuffer, 32, checksumBuffer);

    L_DEBUG_BUF(("Checksum\n", checksumBuffer, 4));
    os_memmove(tmpBuffer + 20 + versionSize, checksumBuffer, 4);
    return btchip_encode_base58(tmpBuffer, 24 + versionSize, out, outlen);
}

#ifdef HAVE_PART_SUPPORT
unsigned short btchip_pk256_to_encoded_base58(
    unsigned char WIDE *in, unsigned short inlen, unsigned char *out,
    unsigned short outlen, unsigned short version,
    unsigned char alreadyHashed) {
    unsigned char tmpBuffer[38];
    unsigned char checksumBuffer[32];
    cx_sha256_t hash;
    unsigned char versionSize = (version > 255 ? 2 : 1);

    if (!alreadyHashed) {
        L_DEBUG_BUF(("To hash\n", in, inlen));
        cx_sha256_init(&hash);
        cx_hash(&hash.header, CX_LAST, in, inlen, tmpBuffer + versionSize);
        L_DEBUG_BUF(("Hash160\n", (tmpBuffer + versionSize), 32));
        if (version > 255) {
            tmpBuffer[0] = (version >> 8);
            tmpBuffer[1] = version;
        } else {
            tmpBuffer[0] = version;
        }
    } else {
        os_memmove(tmpBuffer, in, 32 + versionSize);
    }

    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, tmpBuffer, 32 + versionSize, checksumBuffer);
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, checksumBuffer, 32, checksumBuffer);

    L_DEBUG_BUF(("Checksum\n", checksumBuffer, 4));
    os_memmove(tmpBuffer + 32 + versionSize, checksumBuffer, 4);
    return btchip_encode_base58(tmpBuffer, 36 + versionSize, out, outlen);
}
#endif
void btchip_swap_bytes(unsigned char *target, unsigned char *source,
                       unsigned char size) {
    unsigned char i;
    for (i = 0; i < size; i++) {
        target[i] = source[size - 1 - i];
    }
}

unsigned short btchip_decode_base58_address(unsigned char WIDE *in,
                                            unsigned short inlen,
                                            unsigned char *out,
                                            unsigned short outlen) {
    unsigned char hashBuffer[32];
    cx_sha256_t hash;
    outlen = btchip_decode_base58(in, inlen, out, outlen);

    // Compute hash to verify address
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, out, outlen - 4, hashBuffer);
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, hashBuffer, 32, hashBuffer);

    if (os_memcmp(out + outlen - 4, hashBuffer, 4)) {
        L_DEBUG_BUF(
            ("Hash checksum mismatch\n", hashBuffer, sizeof(hashBuffer)));
        THROW(INVALID_CHECKSUM);
    }

    return outlen;
}

void btchip_private_derive_keypair(unsigned char WIDE *bip32Path,
                                   unsigned char derivePublic,
                                   unsigned char *out_chainCode) {
    unsigned char bip32PathLength;
    unsigned char i;
    unsigned int bip32PathInt[MAX_BIP32_PATH];
    unsigned char privateComponent[32];

    bip32PathLength = bip32Path[0];
    if (bip32PathLength > MAX_BIP32_PATH) {
        THROW(INVALID_PARAMETER);
    }
    bip32Path++;
    for (i = 0; i < bip32PathLength; i++) {
        bip32PathInt[i] = btchip_read_u32(bip32Path, 1, 0);
        bip32Path += 4;
    }
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32PathInt, bip32PathLength,
                               privateComponent, out_chainCode);
    btchip_retrieve_keypair_discard(privateComponent, derivePublic);
    os_memset(privateComponent, 0, sizeof(privateComponent));
}

void btchip_transaction_add_output(unsigned char *hash160Address,
                                   unsigned char *amount, unsigned char p2sh) {
    const unsigned char *pre = (p2sh ? TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE
                                     : TRANSACTION_OUTPUT_SCRIPT_PRE);
    const unsigned char *post = (p2sh ? TRANSACTION_OUTPUT_SCRIPT_P2SH_POST
                                      : TRANSACTION_OUTPUT_SCRIPT_POST);
    unsigned char sizePre = (p2sh ? sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)
                                  : sizeof(TRANSACTION_OUTPUT_SCRIPT_PRE));
    unsigned char sizePost = (p2sh ? sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)
                                   : sizeof(TRANSACTION_OUTPUT_SCRIPT_POST));
    if (amount != NULL) {
        btchip_swap_bytes(btchip_context_D.tmp, amount, 8);
        btchip_context_D.tmp += 8;
    }
    os_memmove(btchip_context_D.tmp, (void *)pre, sizePre);
    btchip_context_D.tmp += sizePre;
    os_memmove(btchip_context_D.tmp, hash160Address, 20);
    btchip_context_D.tmp += 20;
    os_memmove(btchip_context_D.tmp, (void *)post, sizePost);
    btchip_context_D.tmp += sizePost;
}


void btchip_signverify_finalhash(void WIDE *keyContext, unsigned char sign,
                                 unsigned char WIDE *in, unsigned short inlen,
                                 unsigned char *out, unsigned short outlen,
                                 unsigned char rfc6979) {
    if (sign) {
        unsigned int info = 0;
        cx_ecdsa_sign((cx_ecfp_private_key_t WIDE *)keyContext,
                      CX_LAST | (rfc6979 ? CX_RND_RFC6979 : CX_RND_TRNG),
                      CX_SHA256, in, inlen, out, &info);
        if (info & CX_ECCINFO_PARITY_ODD) {
            out[0] |= 0x01;
        }
    } else {
        cx_ecdsa_verify((cx_ecfp_public_key_t WIDE *)keyContext, CX_LAST,
                        CX_SHA256, in, inlen, out, outlen);
    }
}
