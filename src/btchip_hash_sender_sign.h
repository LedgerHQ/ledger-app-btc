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

#ifndef BTCHIP_HASH_SENDER_SIGN_H
#define BTCHIP_HASH_SENDER_SIGN_H
#ifdef HAVE_QTUM_SUPPORT
#include "os.h"
#include "cx.h"

unsigned char btchip_hash_sender_start(unsigned char* senderOutput);
void btchip_hash_sender_finalize(unsigned char* dataBuffer, unsigned int bufferSize);
#endif
#endif
