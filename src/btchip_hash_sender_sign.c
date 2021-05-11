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
#ifdef HAVE_QTUM_SUPPORT
#include "btchip_internal.h"
#include "btchip_hash_sender_sign.h"

unsigned char btchip_hash_sender_start(unsigned char* senderOutput)
{
    cx_sha256_init(&btchip_context_D.transactionOutputHash);

    // Use cache data generated from Segwit
    PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", sizeof(btchip_context_D.transactionVersion), btchip_context_D.transactionVersion);
    cx_hash(
        &btchip_context_D.transactionOutputHash.header, 0,
        btchip_context_D.transactionVersion,
        sizeof(btchip_context_D.transactionVersion),
        NULL, 0);

    PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", sizeof(btchip_context_D.segwit.cache.hashedPrevouts), btchip_context_D.segwit.cache.hashedPrevouts);
    cx_hash(
        &btchip_context_D.transactionOutputHash.header, 0,
        btchip_context_D.segwit.cache.hashedPrevouts,
        sizeof(btchip_context_D.segwit.cache
               .hashedPrevouts),
        NULL, 0);

    PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", sizeof(btchip_context_D.segwit.cache.hashedSequence), btchip_context_D.segwit.cache.hashedSequence);
    cx_hash(
        &btchip_context_D.transactionOutputHash.header, 0,
        btchip_context_D.segwit.cache.hashedSequence,
        sizeof(btchip_context_D.segwit.cache
               .hashedSequence),
        NULL, 0);

    // Op sender specific data
    unsigned int scriptSize = 0;
    unsigned int discardSize = 0;
    if(btchip_get_script_size(senderOutput + 8, sizeof(btchip_context_D.currentOutput), &scriptSize, &discardSize))
    {
        unsigned outputSize = 8 + scriptSize + discardSize;
        PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", outputSize, senderOutput);
        cx_hash(
            &btchip_context_D.transactionOutputHash.header, 0,
            senderOutput,
            outputSize,
            NULL, 0);
        
        unsigned char scriptCode[26];
        if(!btchip_get_script_sender_address(senderOutput + 8, sizeof(btchip_context_D.currentOutput), scriptCode))
            return 0;

        PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", sizeof(scriptCode), scriptCode);
        cx_hash(
            &btchip_context_D.transactionOutputHash.header, 0,
            scriptCode,
            sizeof(scriptCode),
            NULL, 0);

        PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", 8, senderOutput);
        cx_hash(
            &btchip_context_D.transactionOutputHash.header, 0,
            senderOutput,
            8,
            NULL, 0);
    }
    else 
        return 0;

    return 1;
}

void btchip_hash_sender_finalize(unsigned char* dataBuffer, unsigned int bufferSize)
{
    PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", sizeof(btchip_context_D.segwit.cache.hashedOutputs), btchip_context_D.segwit.cache.hashedOutputs);
    cx_hash(
        &btchip_context_D.transactionOutputHash.header, 0,
        btchip_context_D.segwit.cache.hashedOutputs,
        sizeof(btchip_context_D.segwit.cache
               .hashedOutputs),
        NULL, 0);
    PRINTF("--- ADD TO HASH SENDER:\n%.*H\n", bufferSize, dataBuffer);
    cx_hash(&btchip_context_D.transactionOutputHash.header, 0,
        dataBuffer, bufferSize, NULL, 0);
}
#endif
