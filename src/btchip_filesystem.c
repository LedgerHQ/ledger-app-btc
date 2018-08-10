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

#include "btchip_public_ram_variables.h"

void btchip_set_operation_mode(unsigned char operationMode) {
    secu8 opMode;
    SB_SET(opMode, operationMode);

    // only modify operation mode
    nvm_write((void *)&N_btchip.bkp.config.operationMode, &opMode,
              sizeof(opMode));
}
