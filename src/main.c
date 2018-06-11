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

#include "os.h"
#include "cx.h"

#include "os_io_seproxyhal.h"
#include "string.h"

#include "btchip_internal.h"

#include "btchip_bagl_extensions.h"

#include "segwit_addr.h"
#include "cashaddr.h"

#include "glyphs.h"

#define __NAME3(a, b, c) a##b##c
#define NAME3(a, b, c) __NAME3(a, b, c)

bagl_element_t tmp_element;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#define BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH 10
#define BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH 8
#define MAX_CHAR_PER_LINE 25

#define COLOR_BG_1 0xF9F9F9
#define COLOR_APP COLOR_HDR      // bitcoin 0xFCB653
#define COLOR_APP_LIGHT COLOR_DB // bitcoin 0xFEDBA9

#if defined(TARGET_BLUE)
#include "qrcodegen.h"

union {
    struct {
        char addressSummary[40]; // beginning of the output address ... end of
        char fullAmount[65];     // full amount
        char fullAddress[65];
        // the address
        char feesAmount[40]; // fees
    } tmp;

    struct {
        char addressSummary[MAX_CHAR_PER_LINE + 1];
        bagl_icon_details_t icon_details;
        unsigned int colors[2];
        unsigned char qrcode[qrcodegen_BUFFER_LEN_FOR_VERSION(3)];
    } tmpqr;

    unsigned int dummy; // ensure the whole vars is aligned for the CM0 to
                        // operate correctly
} vars;

#else

union {
    struct {
        // char addressSummary[40]; // beginning of the output address ... end
        // of

        char fullAddress[43]; // the address
        char fullAmount[20];  // full amount
        char feesAmount[20];  // fees
    } tmp;

    /*
    struct {
      bagl_icon_details_t icon_details;
      unsigned int colors[2];
      unsigned char qrcode[qrcodegen_BUFFER_LEN_FOR_VERSION(3)];
    } tmpqr;

    unsigned int dummy; // ensure the whole vars is aligned for the CM0 to
    operate correctly
    */
} vars;
#endif

unsigned int io_seproxyhal_touch_verify_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_verify_ok(const bagl_element_t *e);
unsigned int
io_seproxyhal_touch_message_signature_verify_cancel(const bagl_element_t *e);
unsigned int
io_seproxyhal_touch_message_signature_verify_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_display_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_display_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
void ui_idle(void);

ux_state_t ux;

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

const bagl_element_t *ui_menu_item_out_over(const bagl_element_t *e) {
    // the selection rectangle is after the none|touchable
    e = (const bagl_element_t *)(((unsigned int)e) + sizeof(bagl_element_t));
    return e;
}

#if defined(TARGET_BLUE)

unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e);
const bagl_element_t ui_idle_blue[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     COINID_UPCASE,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_DASHBOARD,
     0,
     COLOR_APP,
     0xFFFFFF,
     io_seproxyhal_touch_exit,
     NULL,
     NULL},

    // BADGE_<COINID>.GIF
    {{BAGL_ICON, 0x00, 135, 178, 50, 50, 0, 0, BAGL_FILL, 0, COLOR_BG_1, 0, 0},
     &NAME3(C_blue_badge_, COINID, ),
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 270, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Open " COINID_NAME " wallet",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 0, 308, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Connect your Ledger Blue and open your",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 0, 331, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "preferred wallet to view your accounts.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 450, 320, 14, 0, 0, 0, 0x999999, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Validation requests will show automatically.",
     10,
     0,
     COLOR_BG_1,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}
#endif // #if defined(TARGET_BLUE)

#if defined(TARGET_NANOS)

const ux_menu_entry_t menu_main[];

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {menu_main, NULL, 1, &C_nanos_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    //{NULL, NULL, 0, &NAME3(C_nanos_badge_, COINID, ), "Use wallet to", "view
    //accounts", 33, 12},
    {NULL, NULL, 0, NULL, "Use wallet to", "view accounts", 0, 0},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_nanos_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

#endif // #if defined(TARGET_NANOS)

#if defined(TARGET_BLUE)
// reuse vars.tmp.addressSummary for each line content
typedef void (*callback_t)(void);
callback_t ui_details_back_callback;

// don't perform any draw/color change upon finger event over settings
const bagl_element_t *ui_settings_out_over(const bagl_element_t *e) {
    return NULL;
}

const char *ui_details_title;
const char *ui_details_content;

const bagl_element_t *
ui_details_blue_back_callback(const bagl_element_t *element) {
    ui_details_back_callback();
    return 0;
}

const bagl_element_t ui_details_blue[] = {
    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x01, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 50, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_LEFT,
     0,
     COLOR_APP,
     0xFFFFFF,
     ui_details_blue_back_callback,
     NULL,
     NULL},
    //{{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264,  19,  56,  44, 0, 0,
    //BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
    //BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,
    //0 }, BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_APP, 0xFFFFFF,
    //io_seproxyhal_touch_exit, NULL, NULL},

    {{BAGL_LABELINE, 0x00, 30, 106, 320, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "VALUE",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x10, 30, 136, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x11, 30, 159, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x12, 30, 182, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x13, 30, 205, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x14, 30, 228, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x15, 30, 251, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x16, 30, 274, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x17, 30, 297, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x18, 30, 320, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //"..." at the end if too much
    {{BAGL_LABELINE, 0x19, 30, 343, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 450, 320, 14, 0, 0, 0, 0x999999, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Review the whole value before continuing.",
     10,
     0,
     COLOR_BG_1,
     NULL,
     NULL,
     NULL},
};

const bagl_element_t *ui_details_blue_prepro(const bagl_element_t *element) {
    if (element->component.userid == 1) {
        os_memmove(&tmp_element, element, sizeof(bagl_element_t));
        tmp_element.text = ui_details_title;
        return &tmp_element;
    } else if (element->component.userid > 0) {
        unsigned int length = strlen(ui_details_content);
        if (length >= (element->component.userid & 0xF) * MAX_CHAR_PER_LINE) {
            os_memset(vars.tmp.addressSummary, 0, MAX_CHAR_PER_LINE + 1);
            os_memmove(
                vars.tmp.addressSummary,
                ui_details_content +
                    (element->component.userid & 0xF) * MAX_CHAR_PER_LINE,
                MIN(length -
                        (element->component.userid & 0xF) * MAX_CHAR_PER_LINE,
                    MAX_CHAR_PER_LINE));
            return 1;
        }
        // nothing to draw for this line
        return 0;
    }
    return 1;
}

unsigned int ui_details_blue_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
    return 0;
}

void ui_details_init(const char *title, const char *content,
                     callback_t back_callback) {
    ui_details_title = title;
    ui_details_content = content;
    ui_details_back_callback = back_callback;
    UX_DISPLAY(ui_details_blue, ui_details_blue_prepro);
}

// redisplay transaction validation when exiting the details
void ui_transaction_blue_init(void);

bagl_element_callback_t ui_transaction_blue_ok;
bagl_element_callback_t ui_transaction_blue_cancel;

const bagl_element_t *ui_transaction_blue_ok_callback(const bagl_element_t *e) {
    return ui_transaction_blue_ok(e);
}

const bagl_element_t *
ui_transaction_blue_cancel_callback(const bagl_element_t *e) {
    return ui_transaction_blue_cancel(e);
}

typedef enum {
    TRANSACTION_FULL,
    TRANSACTION_OUTPUT,
    TRANSACTION_FINALIZE,
    TRANSACTION_P2SH,
    TRANSACTION_MESSAGE,
} ui_transaction_blue_state_t;
ui_transaction_blue_state_t G_ui_transaction_blue_state;
// pointer to value to be displayed
const char *ui_transaction_blue_values[3];
// variable part of the structure
const char *const ui_transaction_blue_details_name[][5] = {
    /*TRANSACTION_FULL*/
    {
        "AMOUNT", "ADDRESS", "FEES", "CONFIRM TRANSACTION",
        "Transaction details",
    },

    /*TRANSACTION_OUTPUT*/
    {
        "OUTPUT#", "ADDRESS", "AMOUNT", "CONFIRM OUTPUT", "Transaction output",
    },

    /*TRANSACTION_FINALIZE*/
    {"AMOUNT", "FEES", NULL, "CONFIRM TRANSACTION", "Transaction details"},

    /*TRANSACTION_P2SH*/
    {
        NULL, NULL, NULL, "CONFIRM P2SH", "P2SH Transaction",
    },

    /*TRANSACTION_MESSAGE*/
    {
        "HASH", NULL, NULL, "SIGN MESSAGE", "Message signature",
    },
};

const bagl_element_t *ui_transaction_blue_1_details(const bagl_element_t *e) {
    if (strlen(ui_transaction_blue_values[0]) *
            BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH >=
        160) {
        // display details screen
        ui_details_init(
            ui_transaction_blue_details_name[G_ui_transaction_blue_state][0],
            ui_transaction_blue_values[0], ui_transaction_blue_init);
    }
    return 0;
};

const bagl_element_t *ui_transaction_blue_2_details(const bagl_element_t *e) {
    if (strlen(ui_transaction_blue_values[1]) *
            BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
        160) {
        ui_details_init(
            ui_transaction_blue_details_name[G_ui_transaction_blue_state][1],
            ui_transaction_blue_values[1], ui_transaction_blue_init);
    }
    return 0;
};

const bagl_element_t *ui_transaction_blue_3_details(const bagl_element_t *e) {
    if (strlen(ui_transaction_blue_values[2]) *
            BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
        160) {
        ui_details_init(
            ui_transaction_blue_details_name[G_ui_transaction_blue_state][2],
            ui_transaction_blue_values[2], ui_transaction_blue_init);
    }
    return 0;
};

const bagl_element_t ui_transaction_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x60, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // BADGE_TRANSACTION.GIF
    {{BAGL_ICON, 0x40, 30, 98, 50, 50, 0, 0, BAGL_FILL, 0, COLOR_BG_1, 0, 0},
     &C_blue_badge_transaction,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x50, 100, 117, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 100, 138, 320, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_8_11PX, 0},
     "Check and confirm values",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x70, 30, 196, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x10, 130, 200, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | BAGL_FONT_ALIGNMENT_RIGHT,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x20, 284, 196, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 168, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_1_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x20, 0, 168, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    // separator when second details is to be displayed
    {{BAGL_RECTANGLE, 0x31, 30, 216, 260, 1, 1, 0, 0, 0xEEEEEE, COLOR_BG_1, 0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x71, 30, 245, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x11, 130, 245, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x21, 284, 245, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 217, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_2_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x21, 0, 217, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    // separator when third details is to be displayed
    {{BAGL_RECTANGLE, 0x32, 30, 265, 260, 1, 1, 0, 0, 0xEEEEEE, COLOR_BG_1, 0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x72, 30, 294, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x12, 130, 294, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x22, 284, 294, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 266, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_3_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x22, 0, 266, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 40, 414, 115, 36, 0, 18,
      BAGL_FILL, 0xCCCCCC, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "REJECT",
     0,
     0xB7B7B7,
     COLOR_BG_1,
     ui_transaction_blue_cancel_callback,
     NULL,
     NULL},
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 165, 414, 115, 36, 0, 18,
      BAGL_FILL, 0x41ccb4, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x3ab7a2,
     COLOR_BG_1,
     ui_transaction_blue_ok_callback,
     NULL,
     NULL},
};

const bagl_element_t *
ui_transaction_blue_prepro(const bagl_element_t *element) {
    if (element->component.userid == 0) {
        return 1;
    }
    // none elements are skipped
    if ((element->component.type & (~BAGL_FLAG_TOUCHABLE)) == BAGL_NONE) {
        return 0;
    } else {
        switch (element->component.userid & 0xF0) {
        // icon
        case 0x40:
            return 1;
            break;

        // TITLE
        case 0x60:
            os_memmove(&tmp_element, element, sizeof(bagl_element_t));
            tmp_element.text =
                ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                [3];
            return &tmp_element;
            break;

        // SUBLINE
        case 0x50:
            os_memmove(&tmp_element, element, sizeof(bagl_element_t));
            tmp_element.text =
                ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                [4];
            return &tmp_element;
            break;

        // details label
        case 0x70:
            if (!ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                 [element->component.userid &
                                                  0xF]) {
                return NULL;
            }
            os_memmove(&tmp_element, element, sizeof(bagl_element_t));
            tmp_element.text =
                ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                [element->component.userid &
                                                 0xF];
            return &tmp_element;

        // detail value
        case 0x10:
            // won't display
            if (!ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                 [element->component.userid &
                                                  0xF]) {
                return NULL;
            }
            // always display the value
            os_memmove(&tmp_element, element, sizeof(bagl_element_t));
            tmp_element.text =
                ui_transaction_blue_values[(element->component.userid & 0xF)];

            // x -= 18 when overflow is detected
            if (strlen(ui_transaction_blue_values[(element->component.userid &
                                                   0xF)]) *
                    BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH >=
                160) {
                tmp_element.component.x -= 18;
            }
            return &tmp_element;
            break;

        // right arrow and left selection rectangle
        case 0x20:
            if (!ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                 [element->component.userid &
                                                  0xF]) {
                return NULL;
            }
            if (strlen(ui_transaction_blue_values[(element->component.userid &
                                                   0xF)]) *
                    BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH <
                160) {
                return NULL;
            }

        // horizontal delimiter
        case 0x30:
            return ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                   [element->component.userid &
                                                    0xF] != NULL
                       ? element
                       : NULL;
        }
    }
    return element;
}
unsigned int ui_transaction_blue_button(unsigned int button_mask,
                                        unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_display_address_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "CONFIRM ACCOUNT",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264,  19,  56,  44, 0, 0,
    //BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
    //BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,
    //0 }, BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_APP, 0xFFFFFF,
    //io_seproxyhal_touch_exit, NULL, NULL},

    {{BAGL_LABELINE, 0x00, 30, 106, 320, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "ACCOUNT",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x10, 30, 126, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x11, 30, 139, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     vars.tmp.addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x02, 320 / 2 - 0x1D * 8 / 2, 150, 8, 8, 0, 0, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 40, 414, 115, 36, 0, 18,
      BAGL_FILL, 0xCCCCCC, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "REJECT",
     0,
     0xB7B7B7,
     COLOR_BG_1,
     io_seproxyhal_touch_display_cancel,
     NULL,
     NULL},
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 165, 414, 115, 36, 0, 18,
      BAGL_FILL, 0x41ccb4, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x3ab7a2,
     COLOR_BG_1,
     io_seproxyhal_touch_display_ok,
     NULL,
     NULL},
};

unsigned int ui_display_address_blue_prepro(const bagl_element_t *element) {
    bagl_icon_details_t *icon_details = &vars.tmpqr.icon_details;
    bagl_element_t *icon_component = element;
    if (element->component.userid > 0) {
        unsigned int length = strlen(G_io_apdu_buffer + 200);
        switch (element->component.userid) {
        // qrcode, need magnifying
        case 0x02: {
            unsigned int x, y, x_off, y_off, bit;
#define PIXEL_SIZE 5
            os_memmove(&tmp_element, element, sizeof(bagl_element_t));
            tmp_element.component.width = PIXEL_SIZE;
            tmp_element.component.height = PIXEL_SIZE;
            x_off = 320 / 2 - vars.tmpqr.qrcode[0] * PIXEL_SIZE / 2;
            y_off =
                139 + (414 - 139) / 2 - vars.tmpqr.qrcode[0] * PIXEL_SIZE / 2;
            bit = 0;

            y = 0;
            x = 0;
            tmp_element.component.fgcolor =
                vars.tmpqr.qrcode[1 + (bit >> 3)] & (1 << (bit & 0x7))
                    ? 0x00000000
                    : 0xFFFFFFFF;
            tmp_element.component.x = x_off + x * PIXEL_SIZE;
            tmp_element.component.y = y_off + y * PIXEL_SIZE;
            bit++;
            x = 1;
            goto send_and_next;

            for (y = 0; y < vars.tmpqr.qrcode[0]; y++) {
                for (x = 0; x < vars.tmpqr.qrcode[0]; x++) {
                send_and_next:
                    io_seproxyhal_display(&tmp_element);
                    // tmp_element.component.fgcolor =
                    // vars.tmpqr.qrcode[1+((y*0x1D+x)>>3)]&(1<<((y*0x1D+x)&0x7))
                    // ? 0x00000000: 0xFFFFFFFF;
                    tmp_element.component.fgcolor =
                        vars.tmpqr.qrcode[1 + (bit >> 3)] & (1 << (bit & 0x7))
                            ? 0x00000000
                            : 0xFFFFFFFF;
                    tmp_element.component.x = x_off + x * PIXEL_SIZE;
                    tmp_element.component.y = y_off + y * PIXEL_SIZE;
                    bit++;
                    io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                           sizeof(G_io_seproxyhal_spi_buffer),
                                           0);
                }
            }
            // don't use the common draw method, we've already drawn the
            // component
            return 0;
        }

        // address lines
        case 0x10:
        case 0x11:
        default:
            if (length >=
                (element->component.userid & 0xF) * MAX_CHAR_PER_LINE) {
                os_memset(vars.tmpqr.addressSummary, 0, MAX_CHAR_PER_LINE + 1);
                os_memmove(vars.tmpqr.addressSummary,
                           G_io_apdu_buffer + 200 +
                               (element->component.userid & 0xF) *
                                   MAX_CHAR_PER_LINE,
                           MIN(length -
                                   (element->component.userid & 0xF) *
                                       MAX_CHAR_PER_LINE,
                               MAX_CHAR_PER_LINE));
                return 1;
            }
            break;
        }
        // nothing to draw for this line
        return 0;
    }
    return 1;
}
unsigned int ui_display_address_blue_button(unsigned int button_mask,
                                            unsigned int button_mask_counter) {
    return 0;
}
#endif // #if defined(TARGET_BLUE)

#if defined(TARGET_NANOS)

const bagl_element_t ui_display_address_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // Hax, avoid wasting space
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     G_io_apdu_buffer + 199,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x00,   1,  1,   32,  32, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, 0 }, &vars.tmpqr.icon_details, 0, 0, 0, NULL,
    //NULL, NULL },
};

unsigned int ui_display_address_nanos_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_display_address_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter);

const bagl_element_t ui_verify_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "transaction",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Amount",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     vars.tmp.fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x03, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x03, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     vars.tmp.fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x04, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Fees",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x04, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     vars.tmp.feesAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_verify_nanos_button(unsigned int button_mask,
                                    unsigned int button_mask_counter);

const bagl_element_t ui_verify_output_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     vars.tmp.feesAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Amount",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     vars.tmp.fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x03, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x03, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     vars.tmp.fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL}};
unsigned int ui_verify_output_nanos_button(unsigned int button_mask,
                                           unsigned int button_mask_counter);

const bagl_element_t ui_finalize_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "transaction",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Fees",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     vars.tmp.feesAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /* TODO
    {{BAGL_LABELINE                       , 0x02,   0,  12, 128,  12, 0, 0, 0
    , 0xFFFFFF, 0x000000,
    BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Amount",
    0, 0, 0, NULL, NULL, NULL },
    {{BAGL_LABELINE                       , 0x02,  23,  26,  82,  12, 0x80|10,
    0, 0        , 0xFFFFFF, 0x000000,
    BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 26  },
    vars.tmp.fullAmount, 0, 0, 0, NULL, NULL, NULL },
    */
};
unsigned int ui_finalize_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter);

// display or not according to step, and adjust delay
unsigned int ui_verify_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
            case 3:
            case 4:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_verify_output_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
            case 3:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_finalize_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

const bagl_element_t ui_verify_message_signature_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  28,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Sign the",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "message",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Message hash",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     vars.tmp.fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};
unsigned int
ui_verify_message_signature_nanos_button(unsigned int button_mask,
                                         unsigned int button_mask_counter);

unsigned int ui_verify_message_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

#endif // #if defined(TARGET_NANOS)

void ui_idle(void) {
    ux_step_count = 0;

#if defined(TARGET_BLUE)
    UX_DISPLAY(ui_idle_blue, NULL);
#elif defined(TARGET_NANOS)
    UX_MENU_DISPLAY(0, menu_main, NULL);
#endif // #if TARGET_ID
}

#ifdef TARGET_BLUE
unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e) {
    UX_DISPLAY(ui_settings_blue, ui_settings_blue_prepro);
    return 0; // do not redraw button, screen has switched
}

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // go back to the home screen
    os_sched_exit(0);
    return 0; // DO NOT REDRAW THE BUTTON
}
#endif // TARGET_BLUE

unsigned int io_seproxyhal_touch_verify_cancel(const bagl_element_t *e) {
    // user denied the transaction, tell the USB side
    if (!btchip_bagl_user_action(0)) {
        // redraw ui
        ui_idle();
    }
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_verify_ok(const bagl_element_t *e) {
    // user accepted the transaction, tell the USB side
    if (!btchip_bagl_user_action(1)) {
        // redraw ui
        ui_idle();
    }
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int
io_seproxyhal_touch_message_signature_verify_cancel(const bagl_element_t *e) {
    // user denied the transaction, tell the USB side
    btchip_bagl_user_action_message_signing(0);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int
io_seproxyhal_touch_message_signature_verify_ok(const bagl_element_t *e) {
    // user accepted the transaction, tell the USB side
    btchip_bagl_user_action_message_signing(1);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_display_cancel(const bagl_element_t *e) {
    // user denied the transaction, tell the USB side
    btchip_bagl_user_action_display(0);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_display_ok(const bagl_element_t *e) {
    // user accepted the transaction, tell the USB side
    btchip_bagl_user_action_display(1);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

#if defined(TARGET_NANOS)
unsigned int ui_verify_nanos_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_verify_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_verify_ok(NULL);
        break;
    }
    return 0;
}

unsigned int ui_verify_output_nanos_button(unsigned int button_mask,
                                           unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_verify_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_verify_ok(NULL);
        break;
    }
    return 0;
}

unsigned int ui_finalize_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_verify_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_verify_ok(NULL);
        break;
    }
    return 0;
}

unsigned int
ui_verify_message_signature_nanos_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_message_signature_verify_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_message_signature_verify_ok(NULL);
        break;
    }
    return 0;
}

unsigned int ui_display_address_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_display_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_display_ok(NULL);
        break;
    }
    return 0;
}

#endif // #if defined(TARGET_NANOS)

#if defined(TARGET_BLUE)
void ui_transaction_blue_init(void) {
    UX_DISPLAY(ui_transaction_blue, ui_transaction_blue_prepro);
}

void ui_transaction_full_blue_init(void) {
    ui_transaction_blue_ok =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_ok;
    ui_transaction_blue_cancel =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_cancel;
    G_ui_transaction_blue_state = TRANSACTION_FULL;
    ui_transaction_blue_values[0] = vars.tmp.fullAmount;
    ui_transaction_blue_values[1] = vars.tmp.fullAddress;
    ui_transaction_blue_values[2] = vars.tmp.feesAmount;
    ui_transaction_blue_init();
}

void ui_transaction_output_blue_init(void) {
    ui_transaction_blue_ok =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_ok;
    ui_transaction_blue_cancel =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_cancel;
    G_ui_transaction_blue_state = TRANSACTION_OUTPUT;
    snprintf(
        vars.tmp.addressSummary, sizeof(vars.tmp.addressSummary), "%d / %d",
        btchip_context_D.totalOutputs - btchip_context_D.remainingOutputs + 1,
        btchip_context_D.totalOutputs);
    ui_transaction_blue_values[0] = vars.tmp.addressSummary;
    ui_transaction_blue_values[1] = vars.tmp.fullAddress;
    ui_transaction_blue_values[2] = vars.tmp.fullAmount;
    ui_transaction_blue_init();
}

void ui_transaction_finalize_blue_init(void) {
    ui_transaction_blue_ok =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_ok;
    ui_transaction_blue_cancel =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_cancel;
    G_ui_transaction_blue_state = TRANSACTION_FINALIZE;
    ui_transaction_blue_values[0] = vars.tmp.fullAmount;
    ui_transaction_blue_values[1] = vars.tmp.feesAmount;
    ui_transaction_blue_values[2] = NULL;
    ui_transaction_blue_init();
}

void ui_message_signature_blue_init(void) {
    ui_transaction_blue_ok = (bagl_element_callback_t)
        io_seproxyhal_touch_message_signature_verify_ok;
    ui_transaction_blue_cancel = (bagl_element_callback_t)
        io_seproxyhal_touch_message_signature_verify_cancel;
    snprintf(vars.tmp.fullAmount, 65, "%.*H", 32, vars.tmp.fullAmount);
    G_ui_transaction_blue_state = TRANSACTION_MESSAGE;
    ui_transaction_blue_values[0] = vars.tmp.fullAmount;
    ui_transaction_blue_values[1] = NULL;
    ui_transaction_blue_values[2] = NULL;
    ui_transaction_blue_init();
}

void ui_transaction_p2sh_blue_init(void) {
    ui_transaction_blue_ok =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_ok;
    ui_transaction_blue_cancel =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_cancel;
    G_ui_transaction_blue_state = TRANSACTION_P2SH;
    ui_transaction_blue_values[0] = NULL;
    ui_transaction_blue_values[1] = NULL;
    ui_transaction_blue_values[2] = NULL;
    ui_transaction_blue_init();
}
#endif // #if defined(TARGET_BLUE)

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    if ((element->component.type & (~BAGL_TYPE_FLAGS_MASK)) != BAGL_NONE) {
        io_seproxyhal_display_default((bagl_element_t *)element);
    }
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
    // no break is intentional
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            // don't redisplay if UX not allowed (pin locked in the common bolos
            // ux ?)
            if (ux_step_count && UX_ALLOWED) {
                // prepare next screen
                ux_step = (ux_step + 1) % ux_step_count;
                // redisplay screen
                UX_REDISPLAY();
            }
        });
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

uint8_t prepare_fees() {
    if (btchip_context_D.transactionContext.relaxed) {
        os_memmove(vars.tmp.feesAmount, "UNKNOWN", 7);
        vars.tmp.feesAmount[7] = '\0';
    } else {
        unsigned char fees[8];
        unsigned short textSize;
        if (transaction_amount_sub_be(
                fees, btchip_context_D.transactionContext.transactionAmount,
                btchip_context_D.totalOutputAmount)) {
            PRINTF("Error : Fees not consistent");
            goto error;
        }
        os_memmove(vars.tmp.feesAmount, btchip_context_D.shortCoinId,
                   btchip_context_D.shortCoinIdLength);
        vars.tmp.feesAmount[btchip_context_D.shortCoinIdLength] = ' ';
        btchip_context_D.tmp =
            (unsigned char *)(vars.tmp.feesAmount +
                              btchip_context_D.shortCoinIdLength + 1);
        textSize = btchip_convert_hex_amount_to_displayable(fees);
        vars.tmp.feesAmount[textSize + btchip_context_D.shortCoinIdLength + 1] =
            '\0';
    }
    return 1;
error:
    return 0;
}

uint8_t prepare_single_output() {
    // TODO : special display for OP_RETURN
    unsigned char amount[8];
    char tmp[80];
    unsigned int offset = 0;
    unsigned char versionSize;
    int addressOffset;
    unsigned char address[34];
    unsigned short version;
    unsigned short textSize;
    unsigned char nativeSegwit;

    vars.tmp.fullAddress[0] = '\0';
    btchip_swap_bytes(amount, btchip_context_D.currentOutput + offset, 8);
    offset += 8;
    nativeSegwit = btchip_output_script_is_native_witness(
        btchip_context_D.currentOutput + offset);
#ifdef HAVE_PART_SUPPORT
    bool amountZero = true;
    for (size_t k = 0; k < 8; ++k) {
        if (amount[k] == 0)
            continue;
        amountZero = false;
        break;
    };
    if (amountZero)
    {
        snprintf(vars.tmp.fullAddress, 65, "DATA %dB", btchip_context_D.currentOutput[offset]);
    } else
    if (btchip_output_script_is_coldstake(btchip_context_D.currentOutput +
                                          offset))
    {
        version = btchip_context_D.payToAddressVersion;
        versionSize = 1;
        addressOffset = offset + 6;
        address[0] = version;
        os_memmove(address + versionSize,
                   btchip_context_D.currentOutput + addressOffset, 20);

        // Prepare address
        textSize = btchip_public_key_to_encoded_base58(
            address, 20 + versionSize, (unsigned char *)tmp, sizeof(tmp),
            version, 1);
        tmp[textSize] = '\0';
        strcpy(vars.tmp.fullAddress, "STK ");
        strncat(vars.tmp.fullAddress, tmp, 8);
        strcat(vars.tmp.fullAddress, "~ / SPD ");

        addressOffset += 26;
        version = PART_PKADDR256_V;
        address[0] = version;
        os_memmove(address + versionSize,
                   btchip_context_D.currentOutput + addressOffset, 32);

        // Prepare address
        textSize = btchip_pk256_to_encoded_base58(
            address, 32 + versionSize, (unsigned char *)tmp, sizeof(tmp),
            version, 1);
        tmp[textSize] = '\0';

        strncat(vars.tmp.fullAddress, tmp, 8);
        strcat(vars.tmp.fullAddress, "~");
    } else
#endif
    if (btchip_output_script_is_op_return(btchip_context_D.currentOutput +
                                          offset)) {
        strcpy(vars.tmp.fullAddress, "OP_RETURN");
    } else if ((G_coin_config->kind == COIN_KIND_QTUM) &&
               btchip_output_script_is_op_create(
                   btchip_context_D.currentOutput + offset)) {
        strcpy(vars.tmp.fullAddress, "OP_CREATE");
    } else if ((G_coin_config->kind == COIN_KIND_QTUM) &&
               btchip_output_script_is_op_call(btchip_context_D.currentOutput +
                                               offset)) {
        strcpy(vars.tmp.fullAddress, "OP_CALL");
    } else if (nativeSegwit) {
        addressOffset = offset + OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET;
    } else if (btchip_output_script_is_regular(btchip_context_D.currentOutput +
                                               offset)) {
        addressOffset = offset + 4;
        version = btchip_context_D.payToAddressVersion;
    } else {
        addressOffset = offset + 3;
        version = btchip_context_D.payToScriptHashVersion;
    }
    if (vars.tmp.fullAddress[0] == 0) {
        if (!nativeSegwit) {
            if (version > 255) {
                versionSize = 2;
                address[0] = (version >> 8);
                address[1] = version;
            } else {
                versionSize = 1;
                address[0] = version;
            }
            os_memmove(address + versionSize,
                       btchip_context_D.currentOutput + addressOffset, 20);

            // Prepare address
            if (btchip_context_D.usingCashAddr) {
                cashaddr_encode(
                    address + versionSize, 20, tmp, sizeof(tmp),
                    (version == btchip_context_D.payToScriptHashVersion
                         ? CASHADDR_P2SH
                         : CASHADDR_P2PKH));
            } else {
                textSize = btchip_public_key_to_encoded_base58(
                    address, 20 + versionSize, (unsigned char *)tmp,
                    sizeof(tmp), version, 1);
                tmp[textSize] = '\0';
            }
        } else if (G_coin_config->native_segwit_prefix) {
            textSize = segwit_addr_encode(
                tmp, PIC(G_coin_config->native_segwit_prefix), 0,
                btchip_context_D.currentOutput + addressOffset,
                btchip_context_D.currentOutput[addressOffset - 1]);
        }

        strcpy(vars.tmp.fullAddress, tmp);
    }

    // Prepare amount

    os_memmove(vars.tmp.fullAmount, btchip_context_D.shortCoinId,
               btchip_context_D.shortCoinIdLength);
    vars.tmp.fullAmount[btchip_context_D.shortCoinIdLength] = ' ';
    btchip_context_D.tmp =
        (unsigned char *)(vars.tmp.fullAmount +
                          btchip_context_D.shortCoinIdLength + 1);
    textSize = btchip_convert_hex_amount_to_displayable(amount);
    vars.tmp.fullAmount[textSize + btchip_context_D.shortCoinIdLength + 1] =
        '\0';

    return 1;
}

uint8_t prepare_full_output(uint8_t checkOnly) {
    unsigned int offset = 0;
    int numberOutputs;
    int i;
    unsigned int currentPos = 0;
    unsigned char amount[8], totalOutputAmount[8], fees[8];
    char tmp[80];
    unsigned char outputPos = 0, changeFound = 0;
    if (btchip_context_D.transactionContext.relaxed &&
        !btchip_context_D.transactionContext.consumeP2SH) {
        if (!checkOnly) {
            PRINTF("Error : Mixed inputs");
        }
        goto error;
    }
    if (btchip_context_D.transactionContext.consumeP2SH) {
        if (checkOnly) {
            goto error;
        }
        vars.tmp.fullAmount[0] = '\0';
        vars.tmp.feesAmount[0] = '\0';
        strcpy(vars.tmp.fullAddress, "P2SH");
        return 1;
    }
    // Parse output, locate the change output location
    os_memset(totalOutputAmount, 0, sizeof(totalOutputAmount));
    numberOutputs = btchip_context_D.currentOutput[offset++];
    if (numberOutputs > 3) {
        if (!checkOnly) {
            PRINTF("Error : Too many outputs");
        }
        goto error;
    }
    for (i = 0; i < numberOutputs; i++) {
        unsigned char nullAmount = 1;
        unsigned int j;
        unsigned char isOpReturn, isP2sh, isNativeSegwit;
        unsigned char isOpCreate, isOpCall;

        for (j = 0; j < 8; j++) {
            if (btchip_context_D.currentOutput[offset + j] != 0) {
                nullAmount = 0;
                break;
            }
        }
        btchip_swap_bytes(amount, btchip_context_D.currentOutput + offset, 8);
        transaction_amount_add_be(totalOutputAmount, totalOutputAmount, amount);
        offset += 8; // skip amount
        isOpReturn = btchip_output_script_is_op_return(
            btchip_context_D.currentOutput + offset);
        isP2sh = btchip_output_script_is_p2sh(btchip_context_D.currentOutput +
                                              offset);
        isNativeSegwit = btchip_output_script_is_native_witness(
            btchip_context_D.currentOutput + offset);
        isOpCreate = btchip_output_script_is_op_create(
            btchip_context_D.currentOutput + offset);
        isOpCall = btchip_output_script_is_op_call(
            btchip_context_D.currentOutput + offset);
        if (!btchip_output_script_is_regular(btchip_context_D.currentOutput +
                                             offset) &&
            !isP2sh && !(nullAmount && isOpReturn) &&
            (!(G_coin_config->kind == COIN_KIND_QTUM) ||
             (!isOpCreate && !isOpCall))) {
            if (!checkOnly) {
                PRINTF("Error : Unrecognized input script");
            }
            goto error;
        } else if (!btchip_output_script_is_regular(
                       btchip_context_D.currentOutput + offset) &&
                   !isP2sh && !(nullAmount && isOpReturn)) {
            if (!checkOnly) {
                PRINTF("Error : Unrecognized input script");
            }
            goto error;
        }
        if (((G_coin_config->kind == COIN_KIND_QTUM) &&
             btchip_context_D.tmpCtx.output.changeInitialized && !isOpReturn &&
             !isOpCreate && !isOpCall) ||
            (!(G_coin_config->kind == COIN_KIND_QTUM) &&
             btchip_context_D.tmpCtx.output.changeInitialized && !isOpReturn)) {
            unsigned char addressOffset =
                (isNativeSegwit ? OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET
                                : isP2sh ? OUTPUT_SCRIPT_P2SH_PRE_LENGTH
                                         : OUTPUT_SCRIPT_REGULAR_PRE_LENGTH);
            if (os_memcmp(btchip_context_D.currentOutput + offset +
                              addressOffset,
                          btchip_context_D.tmpCtx.output.changeAddress + 1,
                          20) == 0) {
                if (changeFound) {
                    if (!checkOnly) {
                        PRINTF("Error : Multiple change output found");
                    }
                    goto error;
                }
                changeFound = 1;
            } else {
                outputPos = currentPos;
            }
        }
        offset += 1 + btchip_context_D.currentOutput[offset];
        currentPos++;
    }
    if (btchip_context_D.tmpCtx.output.changeInitialized && !changeFound) {
        if (!checkOnly) {
            PRINTF("Error : change output not found");
        }
        goto error;
    }
    if (transaction_amount_sub_be(
            fees, btchip_context_D.transactionContext.transactionAmount,
            totalOutputAmount)) {
        if (!checkOnly) {
            PRINTF("Error : Fees not consistent");
        }
        goto error;
    }
    if (!checkOnly) {
        // Format validation message
        currentPos = 0;
        offset = 1;
        btchip_context_D.tmp = (unsigned char *)tmp;
        for (i = 0; i < numberOutputs; i++) {
            if (((G_coin_config->kind == COIN_KIND_QTUM) &&
                 !btchip_output_script_is_op_return(
                     btchip_context_D.currentOutput + offset + 8) &&
                 !btchip_output_script_is_op_create(
                     btchip_context_D.currentOutput + offset + 8) &&
                 !btchip_output_script_is_op_call(
                     btchip_context_D.currentOutput + offset + 8)) ||
                (!(G_coin_config->kind == COIN_KIND_QTUM) &&
                 !btchip_output_script_is_op_return(
                     btchip_context_D.currentOutput + offset + 8))) {
                unsigned char versionSize;
                int addressOffset;
                unsigned char address[22];
                unsigned short version;
                unsigned char isNativeSegwit;
                btchip_swap_bytes(amount,
                                  btchip_context_D.currentOutput + offset, 8);
                offset += 8;
                isNativeSegwit = btchip_output_script_is_native_witness(
                    btchip_context_D.currentOutput + offset);
                if (!isNativeSegwit) {
                    if (btchip_output_script_is_regular(
                            btchip_context_D.currentOutput + offset)) {
                        addressOffset = offset + 4;
                        version = btchip_context_D.payToAddressVersion;
                    } else {
                        addressOffset = offset + 3;
                        version = btchip_context_D.payToScriptHashVersion;
                    }
                    if (version > 255) {
                        versionSize = 2;
                        address[0] = (version >> 8);
                        address[1] = version;
                    } else {
                        versionSize = 1;
                        address[0] = version;
                    }
                    os_memmove(address + versionSize,
                               btchip_context_D.currentOutput + addressOffset,
                               20);
                }
                if (currentPos == outputPos) {
                    unsigned short textSize = 0;
                    if (!isNativeSegwit) {
                        // Prepare address
                        if (btchip_context_D.usingCashAddr) {
                            cashaddr_encode(
                                address + versionSize, 20, tmp, sizeof(tmp),
                                (version ==
                                         btchip_context_D.payToScriptHashVersion
                                     ? CASHADDR_P2SH
                                     : CASHADDR_P2PKH));
                        } else {
                            textSize = btchip_public_key_to_encoded_base58(
                                address, 20 + versionSize, (unsigned char *)tmp,
                                sizeof(tmp), version, 1);
                            tmp[textSize] = '\0';
                        }
                    } else if (G_coin_config->native_segwit_prefix) {
                        textSize = segwit_addr_encode(
                            tmp, PIC(G_coin_config->native_segwit_prefix), 0,
                            btchip_context_D.currentOutput + offset +
                                OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET,
                            btchip_context_D.currentOutput
                                [offset +
                                 OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET -
                                 1]);
                    }

                    strcpy(vars.tmp.fullAddress, tmp);

                    // Prepare amount

                    os_memmove(vars.tmp.fullAmount,
                               btchip_context_D.shortCoinId,
                               btchip_context_D.shortCoinIdLength);
                    vars.tmp.fullAmount[btchip_context_D.shortCoinIdLength] =
                        ' ';
                    btchip_context_D.tmp =
                        (unsigned char *)(vars.tmp.fullAmount +
                                          btchip_context_D.shortCoinIdLength +
                                          1);
                    textSize = btchip_convert_hex_amount_to_displayable(amount);
                    vars.tmp
                        .fullAmount[textSize +
                                    btchip_context_D.shortCoinIdLength + 1] =
                        '\0';

                    // prepare fee display
                    os_memmove(vars.tmp.feesAmount,
                               btchip_context_D.shortCoinId,
                               btchip_context_D.shortCoinIdLength);
                    vars.tmp.feesAmount[btchip_context_D.shortCoinIdLength] =
                        ' ';
                    btchip_context_D.tmp =
                        (unsigned char *)(vars.tmp.feesAmount +
                                          btchip_context_D.shortCoinIdLength +
                                          1);
                    textSize = btchip_convert_hex_amount_to_displayable(fees);
                    vars.tmp
                        .feesAmount[textSize +
                                    btchip_context_D.shortCoinIdLength + 1] =
                        '\0';
                    break;
                }
            } else {
                offset += 8;
            }
            offset += 1 + btchip_context_D.currentOutput[offset];
            currentPos++;
        }
    }
    return 1;
error:
    return 0;
}

#define HASH_LENGTH 4
uint8_t prepare_message_signature() {
    cx_hash(&btchip_context_D.transactionHashAuthorization.header, CX_LAST,
            vars.tmp.fullAmount, 0, vars.tmp.fullAmount);
    snprintf(vars.tmp.fullAddress, sizeof(vars.tmp.fullAddress), "%.*H...%.*H",
             8, vars.tmp.fullAmount, 8, vars.tmp.fullAmount + 32 - 8);
    return 1;
}

unsigned int btchip_bagl_confirm_full_output() {
    if (!prepare_full_output(0)) {
        return 0;
    }

#if defined(TARGET_BLUE)
    ui_transaction_full_blue_init();
#elif defined(TARGET_NANOS)
    ux_step = 0;
    ux_step_count = 4;
    UX_DISPLAY(ui_verify_nanos, ui_verify_prepro);
#endif // #if TARGET_ID
    return 1;
}

unsigned int btchip_bagl_confirm_single_output() {
// TODO : remove when supporting multi output
#if defined(TARGET_BLUE)
    if (btchip_context_D.transactionContext.consumeP2SH) {
        ui_transaction_p2sh_blue_init();
        return 1;
    }
#endif

    if (!prepare_single_output()) {
        return 0;
    }

    snprintf(vars.tmp.feesAmount, sizeof(vars.tmp.feesAmount), "output #%d",
             btchip_context_D.totalOutputs - btchip_context_D.remainingOutputs +
                 1);

#if defined(TARGET_BLUE)
    ui_transaction_output_blue_init();
#elif defined(TARGET_NANOS)
    ux_step = 0;
    ux_step_count = 3;
    UX_DISPLAY(ui_verify_output_nanos, ui_verify_output_prepro);
#endif // #if TARGET_ID
    return 1;
}

unsigned int btchip_bagl_finalize_tx() {
    if (!prepare_fees()) {
        return 0;
    }

#if defined(TARGET_BLUE)
    ui_transaction_finalize_blue_init();
#elif defined(TARGET_NANOS)
    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_finalize_nanos, ui_finalize_prepro);
#endif // #if TARGET_ID
    return 1;
}

void btchip_bagl_confirm_message_signature() {
    if (!prepare_message_signature()) {
        return;
    }

#if defined(TARGET_BLUE)
    ui_message_signature_blue_init();
#elif defined(TARGET_NANOS)
    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_verify_message_signature_nanos, ui_verify_message_prepro);
#endif // #if TARGET_ID
}

unsigned int btchip_bagl_display_public_key() {
    // setup qrcode of the address in the apdu buffer
    strcat(G_io_apdu_buffer + 200, " ");

#if defined(TARGET_BLUE)
    // must assert spi buffer is longer than the requested qrcode len.
    // sizeof(data and temp buffer) >=
    // qrcodegen_BUFFER_LEN_FOR_VERSION(guessed_qrcode_version)

    // encode the address as a QRcode
    os_memset(&vars.tmpqr, 0, sizeof(vars.tmpqr));
    // use G_io_seproxyhal_spi_buffer as
    if (qrcodegen_encodeBinary(
            G_io_apdu_buffer + 200, strlen(G_io_apdu_buffer + 200),
            G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer),
            // the edge qrcode size will be discarded when drawing
            &vars.tmpqr.qrcode, sizeof(vars.tmpqr.qrcode), qrcodegen_Ecc_LOW,
            qrcodegen_VERSION_MIN,
            3, // buffer is not designed to handle more than version 3
            qrcodegen_Mask_AUTO, 0)) {
        vars.tmpqr.icon_details.width = vars.tmpqr.qrcode[0];
        vars.tmpqr.icon_details.height = vars.tmpqr.qrcode[0];
        vars.tmpqr.icon_details.bpp = 1;
#if defined(TARGET_BLUE)
        // mgnify on the fly without consuming RAM
        vars.tmpqr.colors[0] = -1;
#else
        vars.tmpqr.colors[1] = -1;
#endif
        vars.tmpqr.icon_details.colors = &vars.tmpqr.colors[0];
        vars.tmpqr.icon_details.bitmap = &vars.tmpqr.qrcode[1];
        // os_memmove(&vars.tmpqr.icon, &C_qrcode_icon_initializer,
        // sizeof(C_qrcode_icon_initializer));
    }

    UX_DISPLAY(ui_display_address_blue, ui_display_address_blue_prepro);
#elif defined(TARGET_NANOS)
    // append and prepend a white space to the address
    G_io_apdu_buffer[199] = ' ';
    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_display_address_nanos, ui_display_address_nanos_prepro);
#endif // #if TARGET_ID
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

// used when application is compiled statically (no lib dependency)
btchip_altcoin_config_t const C_coin_config = {
    .p2pkh_version = COIN_P2PKH_VERSION,
    .p2sh_version = COIN_P2SH_VERSION,
    .family = COIN_FAMILY,
// unsigned char* iconsuffix;// will use the icon provided on the stack (maybe)
#ifdef TARGET_BLUE
    .header_text = COIN_COINID_HEADER,
    .color_header = COIN_COLOR_HDR,
    .color_dashboard = COIN_COLOR_DB,
#endif // TARGET_BLUE
    .coinid = COIN_COINID,
    .name = COIN_COINID_NAME,
    .name_short = COIN_COINID_SHORT,
#ifdef COIN_NATIVE_SEGWIT_PREFIX
    .native_segwit_prefix = COIN_NATIVE_SEGWIT_PREFIX,
#endif // COIN_NATIVE_SEGWIT_PREFIX
#ifdef COIN_FORKID
    .forkid = COIN_FORKID,
#endif // COIN_FORKID
#ifdef COIN_FLAGS
    .flags = COIN_FLAGS,
#endif // COIN_FLAGS
    .kind = COIN_KIND,
};

__attribute__((section(".boot"))) int main(int arg0) {
#ifdef USE_LIB_BITCOIN
    // in RAM allocation (on stack), to allow simple simple traversal into the
    // bitcoin app (separate NVRAM zone)
    unsigned int libcall_params[3];
    unsigned char coinid[sizeof(COIN_COINID)];
    strcpy(coinid, COIN_COINID);
    unsigned char name[sizeof(COIN_COINID_NAME)];
    strcpy(name, COIN_COINID_NAME);
    unsigned char name_short[sizeof(COIN_COINID_SHORT)];
    strcpy(name_short, COIN_COINID_SHORT);
#ifdef COIN_NATIVE_SEGWIT_PREFIX
    unsigned char native_segwit_prefix[sizeof(COIN_NATIVE_SEGWIT_PREFIX)];
    strcpy(native_segwit_prefix, COIN_NATIVE_SEGWIT_PREFIX);
#endif
    btchip_altcoin_config_t coin_config;
    os_memmove(&coin_config, &C_coin_config, sizeof(coin_config));
    coin_config.coinid = coinid;
    coin_config.name = name;
    coin_config.name_short = name_short;
#ifdef COIN_NATIVE_SEGWIT_PREFIX
    coin_config.native_segwit_prefix = native_segwit_prefix;
#endif // #ifdef COIN_NATIVE_SEGWIT_PREFIX
    BEGIN_TRY {
        TRY {
            // ensure syscall will accept us
            check_api_level(CX_COMPAT_APILEVEL);
            // delegate to bitcoin app/lib
            libcall_params[0] = "Bitcoin";
            libcall_params[1] = 0x100; // use the Init call, as we won't exit
            libcall_params[2] = &coin_config;
            os_lib_call(&libcall_params);
        }
        FINALLY {
            app_exit();
        }
    }
    END_TRY;
// no return
#else
    // exit critical section
    __asm volatile("cpsie i");

    if (arg0) {
        // is ID 1 ?
        if (((unsigned int *)arg0)[0] != 0x100) {
            os_lib_throw(INVALID_PARAMETER);
        }
        // grab the coin config structure from the first parameter
        G_coin_config = (btchip_altcoin_config_t *)((unsigned int *)arg0)[1];
    } else {
        G_coin_config = (btchip_altcoin_config_t *)PIC(&C_coin_config);
    }

    // ensure exception will work as planned
    os_boot();

    for (;;) {
        UX_INIT();
        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

                btchip_context_init();

                USB_power(0);
                USB_power(1);

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Ledger Wallet");
#endif // HAVE_BLE

#if defined(TARGET_BLUE)
                // setup the status bar colors (remembered after wards, even
                // more if another app does not resetup after app switch)
                UX_SET_STATUS_BAR_COLOR(0xFFFFFF, COLOR_APP);
#endif // TARGET_ID

                ui_idle();

                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                continue;
            }
            CATCH_ALL {
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
#endif // USE_LIB_BITCOIN
    return 0;
}
