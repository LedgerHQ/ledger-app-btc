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

#ifndef BTCHIP_BASE58_H

#define BTCHIP_BASE58_H

unsigned char btchip_decode_base58(unsigned char WIDE *in, unsigned char length,
                                   unsigned char *out, unsigned char maxoutlen);
unsigned char btchip_encode_base58(unsigned char WIDE *in, unsigned char length,
                                   unsigned char *out, unsigned char maxoutlen);

#endif
