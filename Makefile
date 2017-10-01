#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

APP_LOAD_PARAMS=--appFlags 0x50 --path "" --curve secp256k1 $(COMMON_LOAD_PARAMS) 

APPVERSION_M=1
APPVERSION_N=1
APPVERSION_P=8
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

# ifndef COIN
# COIN =bitcoin
# endif

ifeq ($(COIN),bitcoin_testnet)
# Bitcoin testnet
DEFINES  += BTCHIP_P2PKH_VERSION=111 BTCHIP_P2SH_VERSION=196 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Bitcoin\" COINID_UPCASE=\"BITCOIN\" COLOR_HDR=0xFCB653 COLOR_DB=0xFEDBA9 COINID_NAME=\"Bitcoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"TEST\" COIN_BITCOIN_TESTNET
APPNAME ="Bitcoin Test"
else ifeq ($(COIN),bitcoin)
# Bitcoin mainnet
DEFINES   += BTCHIP_P2PKH_VERSION=0 BTCHIP_P2SH_VERSION=5 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Bitcoin\" COINID_UPCASE=\"BITCOIN\" COLOR_HDR=0xFCB653 COLOR_DB=0xFEDBA9 COINID_NAME=\"Bitcoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"BTC\" COIN_BITCOIN
APPNAME ="Bitcoin"
else ifeq ($(COIN),bitcoin_cash)
# Bitcoin cash
DEFINES   += BTCHIP_P2PKH_VERSION=0 BTCHIP_P2SH_VERSION=5 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Bitcoin\" COINID_UPCASE=\"BITCOINCASH\" COLOR_HDR=0x85bb65 COLOR_DB=0xc2ddb2 COINID_NAME=\"BitcoinCash\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"BCH\" COIN_BITCOIN_CASH
APPNAME ="Bitcoin Cash"
else ifeq ($(COIN),litecoin)
# Litecoin
DEFINES   += BTCHIP_P2PKH_VERSION=48 BTCHIP_P2SH_VERSION=5 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Litecoin\" COINID_UPCASE=\"LITECOIN\" COLOR_HDR=0xCCCCCC COLOR_DB=0xE6E6E6 COINID_NAME=\"Litecoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"LTC\" COIN_LITECOIN
APPNAME ="Litecoin"
else ifeq ($(COIN),gamecredits)
# Gamecredits
DEFINES   += BTCHIP_P2PKH_VERSION=38 BTCHIP_P2SH_VERSION=5 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Gamecredits\" COINID_UPCASE=\"GAMECREDITS\" COLOR_HDR=0x535353 COLOR_DB=0xEBEBEB COINID_NAME=\"GAMECREDITS\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"GAME\" COIN_GAMECREDITS
APPNAME ="Gamecredits"
else ifeq ($(COIN),dogecoin)
# Doge
DEFINES   += BTCHIP_P2PKH_VERSION=30 BTCHIP_P2SH_VERSION=22 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Dogecoin\" COINID_UPCASE=\"DOGECOIN\" COLOR_HDR=0x65D196 COLOR_DB=0xB2E8CB COINID_NAME=\"Dogecoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"DOGE\" COIN_DOGE
APPNAME ="Dogecoin"
else ifeq ($(COIN),dash)
# Dash
DEFINES   += BTCHIP_P2PKH_VERSION=76 BTCHIP_P2SH_VERSION=16 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"DarkCoin\" COINID_UPCASE=\"DASH\" COLOR_HDR=0x0E76AA COLOR_DB=0x87BBD5 COINID_NAME=\"Dash\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"DASH\" COIN_DASH
APPNAME ="Dash"
else ifeq ($(COIN),zcash)
# Zcash
DEFINES   += BTCHIP_P2PKH_VERSION=7352 BTCHIP_P2SH_VERSION=7357 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Zcash\" COINID_UPCASE=\"ZCASH\" COLOR_HDR=0x3790CA COLOR_DB=0x9BC8E5 COINID_NAME=\"Zcash\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"ZEC\" COIN_ZCASH
APPNAME ="Zcash"
else ifeq ($(COIN),komodo)
# Komodo
DEFINES   += BTCHIP_P2PKH_VERSION=60 BTCHIP_P2SH_VERSION=85 BTCHIP_COIN_FAMILY=1 BTCHIP_COINID=\"Komodo\" COINID_UPCASE=\"KMD\" COLOR_HDR=0x326464 COLOR_DB=0x99b2b2 COINID_NAME=\"Komodo\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"KMD\" COIN_KOMODO
APPNAME ="Komodo"
else ifeq ($(COIN),stratis)
# Stratis 
DEFINES   += BTCHIP_P2PKH_VERSION=63 BTCHIP_P2SH_VERSION=125 BTCHIP_COIN_FAMILY=2 BTCHIP_COINID=\"Stratis\" COINID_UPCASE=\"STRAT\" COLOR_HDR=0x3790CA COLOR_DB=0x9BC8E5 COINID_NAME=\"Stratis\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"STRAT\" COIN_STRATIS HAVE_PEERCOIN_SUPPORT
APPNAME ="Stratis"
else ifeq ($(COIN),peercoin)
# Peercoin
DEFINES += BTCHIP_P2PKH_VERSION=55 BTCHIP_P2SH_VERSION=117 BTCHIP_COIN_FAMILY=2 BTCHIP_COINID=\"Peercoin\" COINID_UPCASE=\"PPC\" COLOR_HDR=0x3790CA COLOR_DB=0x9BC8E5 COINID_NAME=\"Peercoin\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"PPC\" COIN_PEERCOIN HAVE_PEERCOIN_SUPPORT
APPNAME ="Peercoin"
else ifeq ($(COIN),posw)
DEFINES += BTCHIP_P2PKH_VERSION=55 BTCHIP_P2SH_VERSION=85 BTCHIP_COIN_FAMILY=2 BTCHIP_COINID=\"PoSWallet\" COINID_UPCASE=\"POSW\" COLOR_HDR=0x23273D COLOR_DB=0x91939E COINID_NAME=\"PoSW\" COINID=$(COIN) BTCHIP_COINID_SHORT=\"POSW\" COIN_POSW HAVE_PEERCOIN_SUPPORT
APPNAME ="PoSW"
else
ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use bitcoin_testnet, bitcoin, bitcoin_cash, litecoin, gamecredits, dogecoin, dash, zcash, komodo, stratis, peercoin, posw) 
endif
endif

ifeq ($(TARGET_NAME),TARGET_BLUE)
ICONNAME=blue_app_$(COIN).gif
else
ICONNAME=nanos_app_$(COIN).gif
endif

################
# Default rule #
################

all: default

############
# Platform #
############

DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES   += HAVE_BAGL HAVE_SPRINTF
#DEFINES   += HAVE_PRINTF PRINTF=screen_printf
DEFINES   += PRINTF\(...\)=
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0


# U2F
DEFINES   += HAVE_U2F
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32 #max MTU, min 20
#DEFINES   += U2F_MAX_MESSAGE_SIZE=264 #257+5+2
DEFINES    += U2F_MAX_MESSAGE_SIZE=200
DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

##############
# Compiler #
##############
#GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
#CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
CC       := $(CLANGPATH)clang 

#CFLAGS   += -O0
CFLAGS   += -O3 -Os

AS     := $(GCCPATH)arm-none-eabi-gcc

LD       := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS  += -O3 -Os
LDLIBS   += -lm -lgcc -lc 

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

### variables processed by the common makefile.rules of the SDK to grab source files and include dirs
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb qrcode


load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

