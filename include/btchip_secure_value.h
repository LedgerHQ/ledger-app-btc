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

#ifndef BTCHIP_SECURE_VALUE_H

#define BTCHIP_SECURE_VALUE_H

#include "os.h"

typedef unsigned short secu8;
typedef unsigned long int secu16;

void sbSet(secu8 *target, unsigned char source);
void sbCheck(secu8 source);
void ssSet(secu16 *target, unsigned short source);
void ssCheck(secu16 source);

#define SB_GET(x) ((unsigned char)x)

#define SB_SET(x, y) sbSet(&x, y);

#define SB_CHECK(x) sbCheck(x);

#define SS_GET(x) ((unsigned short)x)

#define SS_SET(x, y) ssSet(&x, y);

#define SS_CHECK(x) ssCheck(x);

#define SSEC_DEF(x) unsigned char x = 0;
#define SSEC_INC(x) x++;
#define SSEC_CHECK(x, value)                                                   \
    if (x != value)                                                            \
        reset();

#endif
