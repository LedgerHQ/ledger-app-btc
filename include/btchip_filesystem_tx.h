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

#ifndef BTCHIP_FS_TX_H

#define BTCHIP_FS_TX_H

#include "os.h"

#define MAX_BIP32_PATH 10
#define MAX_BIP32_PATH_LENGTH (4 * MAX_BIP32_PATH) + 1

struct btchip_transaction_summary_data_s {
    unsigned char
        transactionNonce[8]; // used to bind to the current set of inputs
    unsigned char pin[4];    // transaction PIN
    unsigned char hasChange;
    unsigned char isP2sh;
    unsigned char arbitraryChange;
    unsigned char relaxed;
    unsigned char fees[8];           // only in wallet mode
    unsigned char changeAmount[8];   // only in wallet mode
    unsigned char outputAddress[21]; // only in wallet mode
    unsigned char changeAddress[21]; // only in wallet mode
    unsigned char keyPath[MAX_BIP32_PATH_LENGTH];
};
typedef struct btchip_transaction_summary_data_s
    btchip_transaction_summary_data_t;

struct btchip_transaction_summary_s {
    unsigned char active;
    unsigned char payToAddressVersion;
    unsigned char payToScriptHashVersion;
    unsigned char authorizationHash[32];
    btchip_transaction_summary_data_t summarydata;
    unsigned short messageLength;
};
typedef struct btchip_transaction_summary_s btchip_transaction_summary_t;

#endif
