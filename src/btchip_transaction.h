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

#include "btchip_secure_value.h"

#ifndef BTCHIP_TRANSACTION_H

#define BTCHIP_TRANSACTION_H

#define TRANSACTION_HASH_NONE 0x00
#define TRANSACTION_HASH_FULL 0x01
#define TRANSACTION_HASH_AUTHORIZATION 0x02
#define TRANSACTION_HASH_BOTH 0x03

#define PARSE_MODE_TRUSTED_INPUT 0x01
#define PARSE_MODE_SIGNATURE 0x02

void transaction_parse(unsigned char parseMode);

// target = a + b
unsigned char transaction_amount_add_be(unsigned char *target,
                                        unsigned char WIDE *a,
                                        unsigned char WIDE *b);

// target = a - b
unsigned char transaction_amount_sub_be(unsigned char *target,
                                        unsigned char WIDE *a,
                                        unsigned char WIDE *b);

#endif
