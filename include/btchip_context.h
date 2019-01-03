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

#ifndef BTCHIP_CONTEXT_H

#define BTCHIP_CONTEXT_H

#include "os.h"
#include "btchip_secure_value.h"
#include "btchip_filesystem_tx.h"

#define MAX_OUTPUT_TO_CHECK 200
#define MAX_COIN_ID 13
#define MAX_SHORT_COIN_ID 5 

#define MAGIC_TRUSTED_INPUT 0x32
#define MAGIC_DEV_KEY 0x01

enum btchip_modes_e {
    BTCHIP_MODE_ISSUER = 0x00,
    BTCHIP_MODE_SETUP_NEEDED = 0xff,
    BTCHIP_MODE_WALLET = 0x01,
    BTCHIP_MODE_RELAXED_WALLET = 0x02,
    BTCHIP_MODE_SERVER = 0x04,
    BTCHIP_MODE_DEVELOPER = 0x08,
};

enum btchip_options_e {
    BTCHIP_OPTION_UNCOMPRESSED_KEYS = 0x01,
    BTCHIP_OPTION_DETERMINISTIC_SIGNATURE = 0x02,
    BTCHIP_OPTION_FREE_SIGHASHTYPE = 0x04,
    BTCHIP_OPTION_SKIP_2FA_P2SH = 0x08,
    BTCHIP_OPTION_ALLOW_ARBITRARY_CHANGE = 0x10
};

/**
 * Current state of an untrusted transaction hashing
 */
enum btchip_transaction_state_e {
    /** No transaction in progress */
    BTCHIP_TRANSACTION_NONE = 0x00,
    /** Transaction defined, waiting for an input to be hashed */
    BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT = 0x01,
    /** Transaction defined, input hashing in progress, pending input script
       data */
    BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT = 0x02,
    /** Transaction defined, input hashing done, pending output hashing for this
       input */
    BTCHIP_TRANSACTION_INPUT_HASHING_DONE = 0x03,
    /** Transaction defined, waiting for an output to be hashed */
    BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT = 0x04,
    /** Transaction defined, output hashing in progress for a complex script,
       pending output script data */
    BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT = 0x05,
    /** Transaction defined, output hashing done, pending finalization */
    BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE = 0x06,
    /** Extra data present */
    BTCHIP_TRANSACTION_PROCESS_EXTRA = 0x07,
    /** Transaction parsed */
    BTCHIP_TRANSACTION_PARSED = 0x08,
    /** Transaction parsed, ready to prepare for signature after validating the
       user outputs */
    BTCHIP_TRANSACTION_PRESIGN_READY = 0x09,
    /** Transaction fully parsed, ready to be signed */
    BTCHIP_TRANSACTION_SIGN_READY = 0x0a,
};
typedef enum btchip_transaction_state_e btchip_transaction_state_t;

enum btchip_output_parsing_state_e {
    BTCHIP_OUTPUT_PARSING_NONE = 0x00,
    BTCHIP_OUTPUT_PARSING_NUMBER_OUTPUTS = 0x01,
    BTCHIP_OUTPUT_PARSING_OUTPUT = 0x02,
    BTCHIP_OUTPUT_FINALIZE_TX = 0x03,
    BTCHIP_BIP44_CHANGE_PATH_VALIDATION = 0x04,
    BTCHIP_OUTPUT_HANDLE_LEGACY = 0xFF
};
typedef enum btchip_output_parsing_state_e btchip_output_parsing_state_t;

struct segwit_hash_s {
    cx_sha256_t hashPrevouts;
    cx_sha256_t hashSequence;
};
struct segwit_cache_s {
    unsigned char hashedPrevouts[32];
    unsigned char hashedSequence[32];
    unsigned char hashedOutputs[32];
};

/**
 * Structure defining an operation on a transaction
 */
struct btchip_transaction_context_s {
    /** Transient over signing components */

    /** Remaining number of inputs/outputs to process for this transaction */
    unsigned long int transactionRemainingInputsOutputs;
    /** Index of the currently processed input/output for this transaction */
    unsigned long int transactionCurrentInputOutput;
    /** Remaining script bytes to process for the current input or output */
    unsigned long int scriptRemaining;

    /** Persistent over signing components */

    /** State of the transaction, type btchip_transaction_state_t */
    unsigned char transactionState;
    /** Computed sum of transaction inputs or value of the output to convert to
     * a trusted input */
    unsigned char transactionAmount[8];
    /** Flag indicating if this transaction has been processed before */
    unsigned char firstSigned;
    /** If the transaction is relaxed */
    unsigned char relaxed;
    /** If the transaction consumes a P2SH input */
    unsigned char consumeP2SH;
};
typedef struct btchip_transaction_context_s btchip_transaction_context_t;

struct btchip_tmp_output_s {
    /** Change address if initialized */
    unsigned char changeAddress[21];
    /** Flag set if the change address was initialized */
    unsigned char changeInitialized;
    /** Flag set if the change address was checked */
    unsigned char changeChecked;
    /** Flag set if the change address can be submitted */
    unsigned char changeAccepted;
    /** Flag set if the outputs have been fragmented */
    unsigned char multipleOutput;
};
typedef struct btchip_tmp_output_s btchip_tmp_output_t;

struct btchip_context_s {
    /** Flag if dongle has been halted */
    secu8 halted;
    /** Index of the output to convert into a trusted input in a transaction */
    unsigned long int trustedInputIndex;
    /** (Integrity protected) transaction context */
    btchip_transaction_context_t transactionContext;

    /** Current Pay To Address version */
    unsigned short payToAddressVersion;
    /** Current Pay To Script Hash version */
    unsigned short payToScriptHashVersion;
    /** Current coin family */
    unsigned char coinFamily;
    /** Current Coin ID */
    unsigned char coinId[MAX_COIN_ID];
    /** Current short Coin ID */
    unsigned char shortCoinId[MAX_SHORT_COIN_ID];
    /** Current Coin ID length */
    unsigned char coinIdLength;    
    /** Current short Coin ID length */
    unsigned char shortCoinIdLength;        

    /** Non protected transaction context */

    /** Last U2F Token streamed by host to attempt pubkey request */
    unsigned char last_token[4];
    unsigned char has_valid_token;

    /** Full transaction hash context */
    cx_sha256_t transactionHashFull;
    /** Authorization transaction hash context */
    cx_sha256_t transactionHashAuthorization;
    /** Current hash to perform (TRANSACTION_HASH_) */
    unsigned char transactionHashOption;

    /* Segregated Witness changes */

    union {
        struct segwit_hash_s hash;
        struct segwit_cache_s cache;
    } segwit;
    unsigned char transactionVersion[4];
    unsigned char inputValue[8];
    unsigned char usingSegwit;
    unsigned char usingCashAddr;
    unsigned char segwitParsedOnce;

    /* /Segregated Witness changes */

    /** Size currently available to the transaction parser */
    unsigned char transactionDataRemaining;
    /** Current pointer to the transaction buffer for the transaction parser */
    unsigned char *transactionBufferPointer;
    /** Trusted Input index processed */
    unsigned char trustedInputProcessed;
    /** Transaction input to catch for a Trusted Input lookup */
    unsigned long int transactionTargetInput;

    /** Length of the incoming command */
    unsigned short inLength;
    /** Length of the outgoing command */
    unsigned short outLength;

    /** IO flags to reply with at the end of an APDU handler */
    unsigned char io_flags;

    /** Status Word of the response */
    unsigned short sw;

    /** Current scratch buffer */
    unsigned char *tmp;

    // was previously in NVRAM
    btchip_transaction_summary_t transactionSummary;


    unsigned short hashedMessageLength;

    union {
        btchip_tmp_output_t output;
    } tmpCtx;

    unsigned char currentOutput[MAX_OUTPUT_TO_CHECK];
    unsigned short currentOutputOffset;
    unsigned int remainingOutputs;
    unsigned int totalOutputs;
    unsigned int discardSize;
    unsigned char outputParsingState;
    unsigned char totalOutputAmount[8];
    unsigned char changeOutputFound;    
};
typedef struct btchip_context_s btchip_context_t;


/**
 * Structure to configure the bitcoin application for a given altcoin
 * 
 */
typedef enum btchip_coin_flags_e {
    FLAG_PEERCOIN_UNITS=1,
    FLAG_PEERCOIN_SUPPORT=2,
    FLAG_SEGWIT_CHANGE_SUPPORT=4
} btchip_coin_flags_t;


typedef enum btchip_coin_kind_e {
    COIN_KIND_BITCOIN_TESTNET,
    COIN_KIND_BITCOIN,
    COIN_KIND_BITCOIN_CASH,
    COIN_KIND_BITCOIN_GOLD,
    COIN_KIND_LITECOIN,
    COIN_KIND_DOGE,
    COIN_KIND_DASH,
    COIN_KIND_ZCASH,
    COIN_KIND_KOMODO,
    COIN_KIND_RFU,
    COIN_KIND_STRATIS,
    COIN_KIND_PEERCOIN,
    COIN_KIND_POSW,
    COIN_KIND_PIVX,
    COIN_KIND_STEALTH,
    COIN_KIND_VIACOIN,
    COIN_KIND_VERTCOIN,
    COIN_KIND_DIGIBYTE,
    COIN_KIND_QTUM,
    COIN_KIND_HCASH,
    COIN_KIND_BITCOIN_PRIVATE,
    COIN_KIND_HORIZEN,
    COIN_KIND_GAMECREDITS,
    COIN_KIND_UNOBTANIUM,
    COIN_KIND_ZCOIN,
    COIN_KIND_ZCLASSIC
} btchip_coin_kind_t;

typedef struct btchip_altcoin_config_s {
    unsigned short p2pkh_version;
    unsigned short p2sh_version;
    unsigned char family;
    //unsigned char* iconsuffix;// will use the icon provided on the stack (maybe)
#ifdef TARGET_BLUE
    const char* header_text;
    unsigned int color_header;
    unsigned int color_dashboard;
#endif // TARGET_BLUE
    const char* coinid; // used coind id for message signature prefix
    const char* name; // for ux displays
    const char* name_short; // for unit in ux displays
    const char* native_segwit_prefix; // null if no segwit prefix
    unsigned int forkid;
    btchip_coin_kind_t kind;
    unsigned int flags;
} btchip_altcoin_config_t;

void btchip_context_init(void);

#endif
