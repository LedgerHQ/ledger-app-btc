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

#ifndef BTCHIP_HELPERS_H

#define BTCHIP_HELPERS_H

#include "os.h"
#include "cx.h"
#include "stdbool.h"

#define OUTPUT_SCRIPT_REGULAR_PRE_LENGTH 4
#define OUTPUT_SCRIPT_REGULAR_POST_LENGTH 2
#define OUTPUT_SCRIPT_P2SH_PRE_LENGTH 3
#define OUTPUT_SCRIPT_P2SH_POST_LENGTH 1

#define OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET 3

unsigned char btchip_output_script_is_regular(unsigned char *buffer);
unsigned char btchip_output_script_is_p2sh(unsigned char *buffer);
unsigned char btchip_output_script_is_op_return(unsigned char *buffer);
unsigned char btchip_output_script_is_native_witness(unsigned char *buffer);

#ifdef HAVE_QTUM_SUPPORT
unsigned char btchip_output_script_is_op_create(unsigned char *buffer,
                                                size_t size);
unsigned char btchip_output_script_is_op_call(unsigned char *buffer,
                                                size_t size);
unsigned char btchip_output_script_is_op_sender(unsigned char *buffer,
                                                size_t size);
unsigned char btchip_get_script_size(unsigned char *buffer, size_t maxSize, 
                                                unsigned int *scriptSize, unsigned int *discardSize);
unsigned char btchip_get_script_sender_address(unsigned char *buffer,
                                                size_t size, unsigned char *script);
unsigned char btchip_get_sender_sig(unsigned char *buffer,
                                                size_t size, unsigned char **sig, unsigned int *sigSize);
#endif

void btchip_sleep16(unsigned short delay);
void btchip_sleep32(unsigned long int delayEach, unsigned long int delayRepeat);

unsigned long int btchip_read_u16(unsigned char *buffer, unsigned char be,
                                  unsigned char skipSign);
unsigned long int btchip_read_u32(unsigned char *buffer, unsigned char be,
                                  unsigned char skipSign);

void btchip_write_u32_be(unsigned char *buffer, unsigned long int value);
void btchip_write_u32_le(unsigned char *buffer, unsigned long int value);

void btchip_perform_double_hash(unsigned char *in, unsigned short inlen,
                                unsigned char *out,
                                unsigned char hash1Algorithm,
                                unsigned char hash2Algorithm);

void btchip_public_key_hash160(unsigned char *in, unsigned short inlen,
                               unsigned char *out);
unsigned short btchip_public_key_to_encoded_base58(
    unsigned char *in, unsigned short inlen, unsigned char *out,
    unsigned short outlen, unsigned short version, unsigned char alreadyHashed);

unsigned short btchip_decode_base58_address(unsigned char *in,
                                            unsigned short inlen,
                                            unsigned char *out,
                                            unsigned short outlen);

void btchip_private_derive_keypair(unsigned char *bip32Path,
                                   unsigned char derivePublic,
                                   unsigned char *out_chainCode,
                                   cx_ecfp_private_key_t * private_key,
                                   cx_ecfp_public_key_t* public_key);

unsigned char bip44_derivation_guard(unsigned char *bip32Path, bool is_change_path);
unsigned char enforce_bip44_coin_type(unsigned char *bip32Path, bool for_pubkey);
unsigned char bip32_print_path(unsigned char *bip32Path, char* out, unsigned char max_out_len);

// void btchip_set_check_internal_structure_integrity(unsigned char
// setParameter);
#define btchip_set_check_internal_structure_integrity(x)
void btchip_swap_bytes(unsigned char *target, unsigned char *source,
                       unsigned char size);

void btchip_sign_finalhash(void *keyContext,
                           unsigned char *in, unsigned short inlen,
                           unsigned char *out, unsigned short outlen,
                           unsigned char rfc6979);

void btchip_transaction_add_output(unsigned char *hash160Address,
                                   unsigned char *amount, unsigned char p2sh);
unsigned char btchip_rng_u8_modulo(unsigned char modulo);
unsigned char btchip_secure_memcmp(const void *buf1, const void *buf2,
                                   unsigned short length);
unsigned char btchip_decrease_2fa(void);
void btchip_reset_2fa(void);
void btchip_reset_token(void);

#endif
