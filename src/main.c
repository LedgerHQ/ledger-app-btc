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

#include "os.h"
#include "cx.h"

#include "os_io_seproxyhal.h"
#include "string.h"

#include "btchip_internal.h"

#include "btchip_bagl_extensions.h"

#include "segwit_addr.h"
#include "cashaddr.h"
#include "multichainaddr.h"

#include "glyphs.h"

#define __NAME3(a, b, c) a##b##c
#define NAME3(a, b, c) __NAME3(a, b, c)

bagl_element_t tmp_element;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#define BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH 10
#define BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH 8
#define MAX_CHAR_PER_LINE 25

#define COLOR_BG_1 0xF9F9F9
#define COLOR_APP COIN_COLOR_HDR      // bitcoin 0xFCB653
#define COLOR_APP_LIGHT COIN_COLOR_DB // bitcoin 0xFEDBA9
#define COLOR_BLACK 0x000000
#define COLOR_WHITE 0xFFFFFF
#define COLOR_GRAY 0x999999
#define COLOR_LIGHT_GRAY 0xEEEEEE

#define UI_NANOS_BACKGROUND() {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,COLOR_WHITE,0,0},NULL,0,0,0,NULL,NULL,NULL}
#define UI_NANOS_ICON_LEFT(userid, glyph) {{BAGL_ICON,userid,3,12,7,7,0,0,0,COLOR_WHITE,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_NANOS_ICON_RIGHT(userid, glyph) {{BAGL_ICON,userid,117,13,8,6,0,0,0,COLOR_WHITE,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_NANOS_TEXT(userid, x, y, w, text, font) {{BAGL_LABELINE,userid,x,y,w,12,0,0,0,COLOR_WHITE,0,font|BAGL_FONT_ALIGNMENT_CENTER,0},(char *)text,0,0,0,NULL,NULL,NULL}
// Only one scrolling text per screen can be displayed
#define UI_NANOS_SCROLLING_TEXT(userid, x, y, w, text, font) {{BAGL_LABELINE,userid,x,y,w,12,0x80|10,0,0,COLOR_WHITE,0,font|BAGL_FONT_ALIGNMENT_CENTER,26},(char *)text,0,0,0,NULL,NULL,NULL}

#define UI_BLUE_BACKGROUND(title) {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,COLOR_BLACK, 0, 0},NULL,0,0,0,NULL,NULL,NULL}, \
{{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP, COLOR_APP, 0, 0},NULL,0,0,0,NULL,NULL,NULL}, \
{{BAGL_LABELINE, 0x01, 0, 45, 320, 30, 0, 0, BAGL_FILL, COLOR_WHITE, COLOR_APP, BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},title,0,0,0,NULL,NULL,NULL}
#define UI_BLUE_BUTTON_SETTINGS(setting_cb) {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 56, 44, 0, 0, BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT, BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE, 0 }, BAGL_FONT_SYMBOLS_0_SETTINGS, 0, COLOR_APP, COLOR_WHITE, setting_cb, NULL, NULL}
#define UI_BLUE_BUTTON_GO_BACK(back_cb) {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 50, 44, 0, 0, BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT, BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE, 0 }, BAGL_FONT_SYMBOLS_0_LEFT, 0, COLOR_APP, COLOR_WHITE, back_cb, NULL, NULL}
#define UI_BLUE_ICON(userid, x, y, width, height, icon, bg_color){{BAGL_ICON, userid, x, y, width, height, 0, 0, BAGL_FILL, 0, bg_color, 0, 0},icon,0,0,0,NULL,NULL,NULL}
// Toggle icon should be set/updated within a preprocessor
#define UI_BLUE_TOGGLE(x, y, bg_color) {{BAGL_ICON, 0x01, x, y, 320, 18, 0, 0, BAGL_FILL, COLOR_BLACK, bg_color, 0, 0 }, NULL, 0, 0, 0, NULL, NULL, NULL}
#define UI_BLUE_TOUCHZONE(x, y, x_max, y_max, tap_cb, out_cb, over_cb) {{BAGL_NONE|BAGL_FLAG_TOUCHABLE, 0x00, x, y, x_max, y_max, 0, 0, BAGL_FILL, COLOR_WHITE, COLOR_BLACK, 0 , 0}, NULL, 0, COLOR_LIGHT_GRAY, COLOR_BLACK, tap_cb, out_cb, over_cb}
#define UI_BLUE_BUTTON_EXIT(exit_cb) {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0, BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0}, BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_APP, COLOR_WHITE, exit_cb, NULL, NULL}
// Displays standard interface for approval: 2 buttons at the bottom of the screen, one to cancel and one to proceed
#define UI_BLUE_BUTTONS_REJECT_OR_CONFIRM(reject_text, confirm_text, reject_cb, confirm_cb) {{BAGL_RECTANGLE|BAGL_FLAG_TOUCHABLE,0x00,40,414,115,36,0,18,BAGL_FILL,0xCCCCCC,COLOR_BG_1,BAGL_FONT_OPEN_SANS_REGULAR_11_14PX|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,0},reject_text,0,0xB7B7B7,COLOR_BG_1,reject_cb,NULL,NULL},{{BAGL_RECTANGLE|BAGL_FLAG_TOUCHABLE,0x00,165,414,115,36,0,18,BAGL_FILL,0x41ccb4,COLOR_BG_1,BAGL_FONT_OPEN_SANS_REGULAR_11_14PX|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,0},confirm_text,0,0x3ab7a2,COLOR_BG_1,confirm_cb,NULL,NULL}
#define UI_BLUE_TEXT(userid, x, y, w, text, font, flags, text_color, bg_color) {{BAGL_LABELINE,userid,x,y,w,30,0,0,BAGL_FILL,text_color,bg_color,font|flags,0},(char *)text,0,0,0,NULL,NULL,NULL}


#if defined(TARGET_BLUE)
#include "qrcodegen.h"

union {
    struct {
        char addressSummary[40]; // beginning of the output address ... end of
        char fullAmount[65];     // full amount
        char fullAddress[65];
        // the address
        char feesAmount[40]; // fees
        char output_numbering[10];
    } tmp;

    struct {
        char addressSummary[MAX_CHAR_PER_LINE + 1];
        bagl_icon_details_t icon_details;
        unsigned int colors[2];
        unsigned char qrcode[qrcodegen_BUFFER_LEN_FOR_VERSION(3)];
    } tmpqr;

    struct {
        // A bip44 path contains 5 elements, which max length in ascii is 10 char + optional quote "'" + "/" + \0"
        char derivation_path [MAX_DERIV_PATH_ASCII_LENGTH];
    } tmp_warning;

    unsigned int dummy; // ensure the whole vars is aligned for the CM0 to
                        // operate correctly
} vars;

void load_qr_code(unsigned char *data){
    // must assert spi buffer is longer than the requested qrcode len.
    // sizeof(data and temp buffer) >=
    // qrcodegen_BUFFER_LEN_FOR_VERSION(guessed_qrcode_version)

    // encode the address as a QRcode
    os_memset(&vars.tmpqr, 0, sizeof(vars.tmpqr));
    // use G_io_seproxyhal_spi_buffer as
    if (qrcodegen_encodeBinary(
            data, strlen(data),
            G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer),
            // the edge qrcode size will be discarded when drawing
            &vars.tmpqr.qrcode, sizeof(vars.tmpqr.qrcode), qrcodegen_Ecc_LOW,
            qrcodegen_VERSION_MIN,
            3, // buffer is not designed to handle more than version 3
            qrcodegen_Mask_AUTO, 0)) {
        vars.tmpqr.icon_details.width = vars.tmpqr.qrcode[0];
        vars.tmpqr.icon_details.height = vars.tmpqr.qrcode[0];
        vars.tmpqr.icon_details.bpp = 1;

        // magnify on the fly without consuming RAM
        vars.tmpqr.colors[0] = -1;

        vars.tmpqr.icon_details.colors = &vars.tmpqr.colors[0];
        vars.tmpqr.icon_details.bitmap = &vars.tmpqr.qrcode[1];
        // os_memmove(&vars.tmpqr.icon, &C_qrcode_icon_initializer,
        // sizeof(C_qrcode_icon_initializer));
    }
}

unsigned int map_color(unsigned int color) {
    switch (color) {
    case COLOR_APP:
        return G_coin_config->color_header;

    case COLOR_APP_LIGHT:
        return G_coin_config->color_dashboard;
    }
    return color;
}
void copy_element_and_map_coin_colors(const bagl_element_t *element) {
    os_memmove(&tmp_element, element, sizeof(bagl_element_t));
    tmp_element.component.fgcolor = map_color(tmp_element.component.fgcolor);
    tmp_element.component.bgcolor = map_color(tmp_element.component.bgcolor);
    tmp_element.overfgcolor = map_color(tmp_element.overfgcolor);
    tmp_element.overbgcolor = map_color(tmp_element.overbgcolor);
}

#else

union {
    struct {
        // char addressSummary[40]; // beginning of the output address ... end
        // of

        char fullAddress[65]; // the address
        char fullAmount[20];  // full amount
        char feesAmount[20];  // fees
    } tmp;

    struct {
        char derivation_path [MAX_DERIV_PATH_ASCII_LENGTH];
    } tmp_warning;

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
unsigned int io_seproxyhal_touch_display_address_blue(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_display_token_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_display_token_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
void ui_idle(void);

#ifdef TARGET_NANOX
#include "ux.h"
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
#else // TARGET_NANOX
ux_state_t ux;
#endif // TARGET_NANOX

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;
uint8_t ux_loop_over_curr_element; // Nano S only

const bagl_element_t *ui_menu_item_out_over(const bagl_element_t *e) {
    // the selection rectangle is after the none|touchable
    e = (const bagl_element_t *)(((unsigned int)e) + sizeof(bagl_element_t));
    return e;
}

#if defined(TARGET_BLUE)

const bagl_element_t *ui_idle_blue_prepro(const bagl_element_t *element) {
    copy_element_and_map_coin_colors(element);
    if (element->component.userid == 0x01) {
        tmp_element.text = G_coin_config->header_text;
    }
    return &tmp_element;
}

const bagl_element_t ui_idle_blue[] = {

    UI_BLUE_BACKGROUND(NULL),
    UI_BLUE_BUTTON_SETTINGS(io_seproxyhal_touch_settings),
    UI_BLUE_BUTTON_EXIT(io_seproxyhal_touch_exit),
    UI_BLUE_TEXT(0, 0, 270, 320, "Open your wallet", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX, BAGL_FONT_ALIGNMENT_CENTER,  COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 308, 320, "Connect your Ledger Blue and open your", BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 331, 320, "preferred wallet to view your accounts.", BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 450, 320, "Validation requests will show automatically.", BAGL_FONT_OPEN_SANS_REGULAR_8_11PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_GRAY, COLOR_BG_1)

};

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t * ui_settings_blue_toggle_pubKeyRequestRestriction(const bagl_element_t * e) {
    // swap setting and request redraw of settings elements
    uint8_t setting = N_btchip.pubKeyRequestRestriction?0:1;
    nvm_write(&N_btchip.pubKeyRequestRestriction, (void*)&setting, sizeof(uint8_t));
     // only refresh settings mutable drawn elements
    UX_REDISPLAY_IDX(7);
     // won't redisplay the bagl_none
    return 0;
}
 // don't perform any draw/color change upon finger event over settings
const bagl_element_t* ui_settings_out_over(const bagl_element_t* e) {
  return NULL;
}
 unsigned int ui_settings_back_callback(const bagl_element_t* e) {
  // go back to idle
  ui_idle();
  return 0;
}
 const bagl_element_t ui_settings_blue[] = {
    UI_BLUE_BACKGROUND("SETTINGS"),
    UI_BLUE_BUTTON_GO_BACK(ui_settings_back_callback),
    UI_BLUE_TEXT(0, 30, 105, 160, "Public key export", BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 30, 126, 260, "Enable to approve export requests manually", BAGL_FONT_OPEN_SANS_REGULAR_8_11PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_GRAY, COLOR_BG_1),
    UI_BLUE_TOUCHZONE(0, 78, 320, 68, ui_settings_blue_toggle_pubKeyRequestRestriction, ui_settings_out_over, ui_settings_out_over),
    UI_BLUE_TOGGLE(258, 98, COLOR_BG_1)
};
 const bagl_element_t * ui_settings_blue_prepro(const bagl_element_t * e) {
  copy_element_and_map_coin_colors(e);
  // none elements are skipped
  if ((e->component.type&(~BAGL_FLAG_TOUCHABLE)) == BAGL_NONE) {
    return 0;
  }
  // swap icon buffer to be displayed depending on if corresponding setting is enabled or not.
  if (e->component.userid) {
    switch(e->component.userid) {
      case 0x01:
        // swap icon content
        if (N_btchip.pubKeyRequestRestriction) {
          tmp_element.text = &C_blue_icon_toggle_set;
        }
        else {
          tmp_element.text = &C_blue_icon_toggle_reset;
        }
        break;
    }
  }
  return &tmp_element;
}

unsigned int ui_settings_blue_button(unsigned int button_mask, unsigned int button_mask_counter) {
  return 0;
}

#endif // #if defined(TARGET_BLUE)

#if defined(TARGET_NANOS)

const ux_menu_entry_t menu_main[];
const ux_menu_entry_t menu_settings[];

// change the setting
void menu_settings_pubKeyRequestRestriction_change(unsigned int enabled) {
    nvm_write((void *)&N_btchip.pubKeyRequestRestriction, &enabled, 1);
    // go back to the menu entry
    UX_MENU_DISPLAY(0, menu_main, NULL);
}
 const ux_menu_entry_t menu_settings_pubKeyRequestRestriction[] = {
  {NULL, menu_settings_pubKeyRequestRestriction_change, 1, NULL, "Manual approval", NULL, 0, 0},
  {NULL, menu_settings_pubKeyRequestRestriction_change, 0, NULL, "Auto approval", NULL, 0, 0},
  UX_MENU_END
};
 const ux_menu_entry_t menu_settings[] = {
    {menu_settings_pubKeyRequestRestriction, NULL, 0, NULL, "Public keys", "export approval", 0, 0},
    {menu_main, NULL, 1, &C_nanos_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {menu_main, NULL, 1, &C_nanos_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    //{NULL, NULL, 0, &NAME3(C_nanos_badge_, COINID, ), "Use wallet to", "view
    // accounts", 33, 12},
    {NULL, NULL, 0, NULL, "Use wallet to", "view accounts", 0, 0},
    {menu_settings, NULL, 0, NULL, "Settings", NULL, 0, 0},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_nanos_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

#endif // #if defined(TARGET_NANOS)

#if defined(TARGET_BLUE)
// reuse vars.tmp.addressSummary for each line content
typedef void (*callback_t)(void);
callback_t ui_details_back_callback;

const char *ui_details_title;
const char *ui_details_content;

const bagl_element_t *
ui_details_blue_back_callback(const bagl_element_t *element) {
    ui_details_back_callback();
    return 0;
}

const bagl_element_t ui_details_blue[] = {
    UI_BLUE_BACKGROUND(NULL),
    UI_BLUE_BUTTON_GO_BACK(ui_details_blue_back_callback),
    UI_BLUE_TEXT(0, 30, 106, 320, "VALUE", BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_GRAY, COLOR_BG_1),
    UI_BLUE_TEXT(0x10, 30, 136, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x11, 30, 159, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x12, 30, 182, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x13, 30, 205, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x14, 30, 228, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x15, 30, 251, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x16, 30, 274, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x17, 30, 297, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x18, 30, 320, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_BLACK, COLOR_BG_1),
    //"..." at the end if too much
    UI_BLUE_TEXT(0x19, 30, 343, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_GRAY, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 450, 320, "Review the whole value before continuing.", BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_GRAY, COLOR_BG_1)
};

const bagl_element_t *ui_details_blue_prepro(const bagl_element_t *element) {
    copy_element_and_map_coin_colors(element);
    if (element->component.userid == 1) {
        tmp_element.text = ui_details_title;
        return &tmp_element;
    } else if (element->component.userid > 0) {
        unsigned int length = strlen(ui_details_content);
        if (length >= (element->component.userid & 0xF) * MAX_CHAR_PER_LINE) {
            os_memset(vars.tmp.addressSummary, 0, MAX_CHAR_PER_LINE + 1);
            os_memmove(vars.tmp.addressSummary,
                       ui_details_content + (element->component.userid & 0xF) *
                                                MAX_CHAR_PER_LINE,
                       MIN(length - (element->component.userid & 0xF) *
                                        MAX_CHAR_PER_LINE,
                           MAX_CHAR_PER_LINE));
            return 1;
        }
        // nothing to draw for this line
        return 0;
    }
    return &tmp_element;
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
        "AMOUNT",
        "ADDRESS",
        "FEES",
        "CONFIRM TRANSACTION",
        "Transaction details",
    },

    /*TRANSACTION_OUTPUT*/
    {
        "OUTPUT#",
        "ADDRESS",
        "AMOUNT",
        "CONFIRM OUTPUT",
        "Transaction output",
    },

    /*TRANSACTION_FINALIZE*/
    {"AMOUNT", "FEES", NULL, "CONFIRM TRANSACTION", "Transaction details"},

    /*TRANSACTION_P2SH*/
    {
        NULL,
        NULL,
        NULL,
        "CONFIRM P2SH",
        "P2SH Transaction",
    },

    /*TRANSACTION_MESSAGE*/
    {
        "HASH",
        NULL,
        NULL,
        "SIGN MESSAGE",
        "Message signature",
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
    UI_BLUE_BACKGROUND(NULL),
    UI_BLUE_TEXT(0, 30, 106, 320, "VALUE", BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, BAGL_FONT_ALIGNMENT_LEFT, COLOR_GRAY, COLOR_BG_1),
    UI_BLUE_ICON(0x40, 30, 98, 50, 50, &C_blue_badge_transaction, COLOR_BG_1),
    // becomes a line in preprocessor
    UI_BLUE_TEXT(0x50, 100, 117, 320, NULL, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 100, 138, 320, "Check and confirm values", BAGL_FONT_OPEN_SANS_REGULAR_8_11PX, 0, COLOR_GRAY, COLOR_BG_1),

    // First detail zone
    UI_BLUE_TEXT(0x70, 30, 196, 100, NULL, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0, COLOR_BLACK, COLOR_BG_1),
    // x-18 when ...
    UI_BLUE_TEXT(0x10, 130, 200, 160, NULL, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_RIGHT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x20, 284, 196, 6, BAGL_FONT_SYMBOLS_0_MINIRIGHT, BAGL_FONT_SYMBOLS_0, BAGL_FONT_ALIGNMENT_RIGHT, COLOR_GRAY, COLOR_BG_1),
    UI_BLUE_TOUCHZONE(0, 168, 320, 48, ui_transaction_blue_1_details, ui_menu_item_out_over, ui_menu_item_out_over),
    {{BAGL_RECTANGLE, 0x20, 0, 168, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1, COLOR_BG_1, 0, 0},
    NULL, 0, 0x41CCB4, 0, NULL, NULL, NULL},

    // separator when second details is to be displayed
    {{BAGL_RECTANGLE, 0x31, 30, 216, 260, 1, 1, 0, 0, COLOR_LIGHT_GRAY, COLOR_BG_1, 0, 0},
     NULL, 0, 0, 0, NULL, NULL, NULL},
    UI_BLUE_TEXT(0x71, 30, 245, 100, NULL, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0, COLOR_BLACK, COLOR_BG_1),
    // x-18 when ...
    UI_BLUE_TEXT(0x11, 130, 245, 160, NULL, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_RIGHT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x21, 284, 245, 6, BAGL_FONT_SYMBOLS_0_MINIRIGHT, BAGL_FONT_SYMBOLS_0, BAGL_FONT_ALIGNMENT_RIGHT, COLOR_GRAY, COLOR_BG_1),
    UI_BLUE_TOUCHZONE(0, 217, 320, 48, ui_transaction_blue_2_details, ui_menu_item_out_over, ui_menu_item_out_over),
    {{BAGL_RECTANGLE, 0x21, 0, 217, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1, COLOR_BG_1, 0, 0},
    NULL, 0, 0x41CCB4, 0, NULL, NULL, NULL},

    // separator when second details is to be displayed
    {{BAGL_RECTANGLE, 0x32, 30, 265, 260, 1, 1, 0, 0, COLOR_LIGHT_GRAY, COLOR_BG_1, 0, 0},
     NULL, 0, 0, 0, NULL, NULL, NULL},
    UI_BLUE_TEXT(0x72, 30, 294, 100, NULL, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0, COLOR_BLACK, COLOR_BG_1),
    // x-18 when ...
    UI_BLUE_TEXT(0x12, 130, 294, 160, NULL, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, BAGL_FONT_ALIGNMENT_RIGHT, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x22, 284, 294, 6, BAGL_FONT_SYMBOLS_0_MINIRIGHT, BAGL_FONT_SYMBOLS_0, BAGL_FONT_ALIGNMENT_RIGHT, COLOR_GRAY, COLOR_BG_1),
    UI_BLUE_TOUCHZONE(0, 266, 320, 48, ui_transaction_blue_3_details, ui_menu_item_out_over, ui_menu_item_out_over),
    {{BAGL_RECTANGLE, 0x22, 0, 266, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1, COLOR_BG_1, 0, 0}, // WHY OVER ACTIVATE WHE TOUCING OUT OF RECTANGLE ? ASK OTO
    NULL, 0, 0x41CCB4, 0, NULL, NULL, NULL},

    UI_BLUE_BUTTONS_REJECT_OR_CONFIRM("REJECT", "CONFIRM", ui_transaction_blue_cancel_callback, ui_transaction_blue_ok_callback)

};

const bagl_element_t *
ui_transaction_blue_prepro(const bagl_element_t *element) {
    copy_element_and_map_coin_colors(element);
    if (element->component.userid == 0) {
        return &tmp_element;
    }
    // none elements are skipped
    if ((element->component.type & (~BAGL_FLAG_TOUCHABLE)) == BAGL_NONE) {
        return 0;
    } else {
        switch (element->component.userid & 0xF0) {
        // icon
        case 0x40:
            return &tmp_element;
            break;

        // TITLE
        case 0x60:
            tmp_element.text =
                ui_transaction_blue_details_name[G_ui_transaction_blue_state]
                                                [3];
            return &tmp_element;
            break;

        // SUBLINE
        case 0x50:
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
                       ? &tmp_element
                       : NULL;
        }
    }
    return &tmp_element;
}
unsigned int ui_transaction_blue_button(unsigned int button_mask,
                                        unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_display_derivation_warning[] = {
    UI_BLUE_BACKGROUND("WARNING"),

    UI_BLUE_ICON(0x40, 135, 95, 50, 50, &C_blue_badge_warning, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 185, 320, "The derivation path is unusual.", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 203, 320, "Reject if you're not sure.", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 220, 320, "Contact Ledger support for help.", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 271, 320, "Derivation path:", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 297, 320, vars.tmp_warning.derivation_path, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 314, 320, vars.tmp_warning.derivation_path+30, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 331, 320, vars.tmp_warning.derivation_path+60, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 348, 320, vars.tmp_warning.derivation_path+90, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),


    UI_BLUE_BUTTONS_REJECT_OR_CONFIRM("REJECT", "CONFIRM", io_seproxyhal_touch_display_cancel, io_seproxyhal_touch_display_address_blue)
};

const bagl_element_t ui_display_address_blue[] = {
    UI_BLUE_BACKGROUND("CONFIRM ACCOUNT"),
    UI_BLUE_TEXT(0, 30, 106, 320, "ACCOUNT", BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0, COLOR_GRAY, COLOR_BG_1),

    UI_BLUE_TEXT(0x10, 30, 126, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x11, 30, 139, 260, vars.tmp.addressSummary, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0, COLOR_BLACK, COLOR_BG_1),

    {{BAGL_RECTANGLE, 0x02, 320 / 2 - 0x1D * 8 / 2, 150, 8, 8, 0, 0, BAGL_FILL,COLOR_WHITE, COLOR_BLACK, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},

    UI_BLUE_BUTTONS_REJECT_OR_CONFIRM("REJECT", "CONFIRM", io_seproxyhal_touch_display_cancel, io_seproxyhal_touch_display_ok)
};


const bagl_element_t ui_display_token_blue[] = {
    UI_BLUE_BACKGROUND("PUBLIC KEY EXPORT"),

    UI_BLUE_TEXT(0, 30, 185, 260, "Check if the following token is", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 30, 201, 260, "identical on both devices:", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0x10, 30, 240, 260, G_io_apdu_buffer+200, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),

    UI_BLUE_BUTTONS_REJECT_OR_CONFIRM("REJECT", "CONFIRM", io_seproxyhal_touch_display_token_cancel, io_seproxyhal_touch_display_token_ok)
};

 const bagl_element_t ui_request_pubkey_approval_blue[] = {
    UI_BLUE_BACKGROUND("PUBLIC KEY EXPORT"),

    UI_BLUE_TEXT(0, 0, 160, 320, "Approve to export your public keys", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),

    UI_BLUE_BUTTONS_REJECT_OR_CONFIRM("REJECT", "CONFIRM", io_seproxyhal_touch_display_cancel, io_seproxyhal_touch_display_ok)
};

const bagl_element_t ui_request_change_path_approval_blue[] = {
    UI_BLUE_BACKGROUND("WARNING"),

    UI_BLUE_ICON(0x40, 135, 95, 50, 50, &C_blue_badge_warning, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 185, 320, "The change path is unusual.", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 203, 320, "Reject if you're not sure.", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 220, 320, "Contact Ledger support for help.", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 271, 320, "Change path:", BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 297, 320, vars.tmp_warning.derivation_path, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 314, 320, vars.tmp_warning.derivation_path+30, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 331, 320, vars.tmp_warning.derivation_path+60, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),
    UI_BLUE_TEXT(0, 0, 348, 320, vars.tmp_warning.derivation_path+90, BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX, BAGL_FONT_ALIGNMENT_CENTER, COLOR_BLACK, COLOR_BG_1),


    UI_BLUE_BUTTONS_REJECT_OR_CONFIRM("REJECT", "CONFIRM", io_seproxyhal_touch_display_cancel, io_seproxyhal_touch_display_ok)
};

unsigned int ui_display_address_blue_prepro(const bagl_element_t *element) {
    bagl_icon_details_t *icon_details = &vars.tmpqr.icon_details;
    bagl_element_t *icon_component = element;
    copy_element_and_map_coin_colors(element);
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
                    ? COLOR_BLACK
                    : COLOR_WHITE;
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
                    // ? COLOR_BLACK: COLOR_WHITE;
                    tmp_element.component.fgcolor =
                        vars.tmpqr.qrcode[1 + (bit >> 3)] & (1 << (bit & 0x7))
                            ? COLOR_BLACK
                            : COLOR_WHITE;
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
                           MIN(length - (element->component.userid & 0xF) *
                                            MAX_CHAR_PER_LINE,
                               MAX_CHAR_PER_LINE));
                return &tmp_element;
            }
            break;
        }
        // nothing to draw for this line
        return 0;
    }
    return &tmp_element;
}

unsigned int ui_display_token_blue_prepro(const bagl_element_t *element) {
    copy_element_and_map_coin_colors(element);
    return element;
}

unsigned int ui_request_pubkey_approval_blue_prepro(const bagl_element_t *element) {
    copy_element_and_map_coin_colors(element);
    return element;
}

unsigned int ui_request_change_path_approval_blue_prepro(const bagl_element_t *element) {
    copy_element_and_map_coin_colors(element);
    return element;
}

unsigned int ui_display_derivation_warning_button(unsigned int button_mask,
                                            unsigned int button_mask_counter) {
    return 0;
}

unsigned int ui_display_address_blue_button(unsigned int button_mask,
                                            unsigned int button_mask_counter) {
    return 0;
}

unsigned int ui_display_token_blue_button(unsigned int button_mask,
                                            unsigned int button_mask_counter)
{
    return 0;
}
unsigned int ui_request_pubkey_approval_blue_button(unsigned int button_mask,
                                            unsigned int button_mask_counter)
{
    return 0;
}

unsigned int ui_request_change_path_approval_blue_button(unsigned int button_mask,
                                            unsigned int button_mask_counter)
{
    return 0;
}

#endif // #if defined(TARGET_BLUE)

#if defined(TARGET_NANOS)

const bagl_element_t ui_display_address_nanos[] = {

    UI_NANOS_BACKGROUND(),

    /* Displayed when derivation path is unusual */

    UI_NANOS_TEXT(1, 0, 22, 128, "Warning !", BAGL_FONT_OPEN_SANS_LIGHT_16px),

    UI_NANOS_TEXT(2, 0, 12, 128, "The derivation", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(2, 0, 26, 128, "path is unusual", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(3, 0, 12, 128, "Derivation path", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(0x83, 15, 26, 98, vars.tmp_warning.derivation_path, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_ICON_LEFT(4, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(4, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(4, 0, 12, 128, "Reject if you're", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(4, 0, 26, 128, "not sure", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    /* Always displayed */

    UI_NANOS_ICON_LEFT(5, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(5, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(5, 0, 12, 128, "Confirm", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(5, 0, 26, 128, "address", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(6, 0, 12, 128, "Address", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    // Hax, avoid wasting space
    UI_NANOS_SCROLLING_TEXT(0x86, 15, 26, 98, G_io_apdu_buffer + 199, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)
};

const bagl_element_t ui_display_token_nanos[] = {

    UI_NANOS_BACKGROUND(),
    UI_NANOS_ICON_LEFT(0, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(0, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(1, 0, 12, 128, "Confirm token", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    // Hax, avoid wasting space
    UI_NANOS_TEXT(1, 0, 26, 128, G_io_apdu_buffer + 200, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)
};
 const bagl_element_t ui_request_pubkey_approval_nanos[] = {
    UI_NANOS_BACKGROUND(),
    UI_NANOS_ICON_LEFT(0, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(0, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(1, 0, 12, 128, "Export", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    // Hax, avoid wasting space
    UI_NANOS_TEXT(1, 0, 26, 128, "public key?", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)
};

const bagl_element_t ui_request_change_path_approval_nanos[] = {
    UI_NANOS_BACKGROUND(),

    UI_NANOS_TEXT(1, 0, 22, 128, "Warning !", BAGL_FONT_OPEN_SANS_LIGHT_16px),

    UI_NANOS_TEXT(2, 0, 12, 128, "The change path", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(2, 0, 26, 128, "is unusual", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(3, 0, 12, 128, "Change path", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(0x83, 15, 26, 98, vars.tmp_warning.derivation_path, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_ICON_LEFT(4, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(4, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(4, 0, 12, 128, "Reject if you're", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(4, 0, 26, 128, "not sure", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)
};

unsigned int ui_display_address_nanos_prepro(const bagl_element_t *element) {

    if (element->component.userid > 0) {
        unsigned int display = (ux_step == (0x7F & element->component.userid) - 1);
        if (display) {
            switch (element->component.userid) {
            case 0x83:
                ux_loop_over_curr_element = 1;
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            case 5:
                UX_CALLBACK_SET_INTERVAL(2000);
                ux_loop_over_curr_element = 0; // allow next timer to increment ux_step when triggered
                break;
            case 0x86:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                // ugly ux tricks, loops around last 2 screens
                ux_step -= 1; // loops back to previous element on next redraw
                ux_loop_over_curr_element = 1; // when the timer will trigger, ux_step won't be incremented, only redraw
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_request_change_path_approval_nanos_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == (0x7F & element->component.userid) - 1);
        if (display) {
            if (element->component.userid & 0x80) {
                ux_loop_over_curr_element = 1;
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_display_address_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter);
unsigned int ui_display_token_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter);
unsigned int ui_request_pubkey_approval_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter);
unsigned int ui_request_change_path_approval_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter);

const bagl_element_t ui_verify_nanos[] = {
    UI_NANOS_BACKGROUND(),
    UI_NANOS_ICON_LEFT(0, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(0, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(1, 0, 12, 128, "Confirm", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(1, 0, 26, 128, "transaction", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(2, 0, 12, 128, "Amount", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(2, 23, 26, 82, vars.tmp.fullAmount, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(3, 0, 12, 128, "Address", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(3, 23, 26, 82, vars.tmp.fullAddress, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(4, 0, 12, 128, "Fees", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(4, 23, 26, 82, vars.tmp.feesAmount, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)

};
unsigned int ui_verify_nanos_button(unsigned int button_mask,
                                    unsigned int button_mask_counter);

const bagl_element_t ui_verify_output_nanos[] = {

    UI_NANOS_BACKGROUND(),
    UI_NANOS_ICON_LEFT(0, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(0, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(1, 0, 12, 128, "Confirm", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(1, 0, 26, 128, vars.tmp.feesAmount, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(2, 0, 12, 128, "Amount", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(2, 23, 26, 82, vars.tmp.fullAmount, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(3, 0, 12, 128, "Address", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(3, 23, 26, 82, vars.tmp.fullAddress, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)
};

unsigned int ui_verify_output_nanos_button(unsigned int button_mask,
                                           unsigned int button_mask_counter);

const bagl_element_t ui_finalize_nanos[] = {
    UI_NANOS_BACKGROUND(),
    UI_NANOS_ICON_LEFT(0, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(0, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(1, 0, 12, 128, "Confirm", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(1, 0, 26, 128, "transaction", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(2, 0, 12, 128, "Fees", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_SCROLLING_TEXT(2, 23, 26, 82, vars.tmp.feesAmount, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)


    /* TODO
    {{BAGL_LABELINE                       , 0x02,   0,  12, 128,  12, 0, 0, 0 ,
    COLOR_WHITE, COLOR_BLACK,
    BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Amount",
    0, 0, 0, NULL, NULL, NULL },
    {{BAGL_LABELINE                       , 0x02,  23,  26,  82,  12, 0x80|10,
    0, 0        , COLOR_WHITE, COLOR_BLACK,
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
    UI_NANOS_BACKGROUND(),
    UI_NANOS_ICON_LEFT(0, BAGL_GLYPH_ICON_CROSS),
    UI_NANOS_ICON_RIGHT(0, BAGL_GLYPH_ICON_CHECK),
    UI_NANOS_TEXT(1, 0, 12, 128, "Sign the", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),
    UI_NANOS_TEXT(1, 0, 26, 128, "message", BAGL_FONT_OPEN_SANS_EXTRABOLD_11px),

    UI_NANOS_TEXT(2, 0, 12, 128, "Message hash", BAGL_FONT_OPEN_SANS_REGULAR_11px),
    UI_NANOS_SCROLLING_TEXT(2, 23, 26, 82, vars.tmp.fullAddress, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px)
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

unsigned int io_seproxyhal_touch_display_address_blue(const bagl_element_t *e) {
    load_qr_code(G_io_apdu_buffer + 200);
    UX_DISPLAY(ui_display_address_blue, ui_display_address_blue_prepro);
    return 0;
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

unsigned int io_seproxyhal_touch_display_token_cancel(const bagl_element_t *e) {
    // revoke previous valid token if there was one
    btchip_context_D.has_valid_token = false;
    // user denied the token, tell the USB side
    btchip_bagl_user_action_display(0);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_display_token_ok(const bagl_element_t *e) {
    // Set the valid token flag
    btchip_context_D.has_valid_token = true;
    // user approved the token, tell the USB side
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
    if (ux_step == 3)
    {
        switch (button_mask)
        {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            io_seproxyhal_touch_display_cancel(NULL);
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            // prepare next screen
            ux_step = (ux_step + 1) % ux_step_count;
            // redisplay screen
            UX_REDISPLAY();
            break;
        }
    }
    else if (ux_step >= 4)
    {
        switch (button_mask)
        {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            io_seproxyhal_touch_display_cancel(NULL);
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            io_seproxyhal_touch_display_ok(NULL);
            break;
        }
    }
    else
    {
        if(button_mask == (BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT))
        {
                // if we were looping over a single element, disable this loop and diffuse the redisplay timeout (used by scrolling text)
                if(ux_loop_over_curr_element) {
                    ux_loop_over_curr_element = 0;
                    ux.callback_interval_ms = 0;
                }
                // prepare next screen
                ux_step = (ux_step + 1) % ux_step_count;
                // redisplay screen
                UX_REDISPLAY();
        }
    }
    return 0;
}

unsigned int ui_display_token_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter)
{
    switch (button_mask)
    {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_display_token_cancel(NULL);
        break;
     case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_display_token_ok(NULL);
        break;
    }
    return 0;
}
 unsigned int ui_request_pubkey_approval_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter)
{
    switch (button_mask)
    {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_display_cancel(NULL);
        break;
     case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_display_ok(NULL);
        break;
    }
    return 0;
}


 unsigned int ui_request_change_path_approval_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter)
{
    if (ux_step == 3)
    {
        switch (button_mask)
        {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            io_seproxyhal_touch_display_cancel(NULL);
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            io_seproxyhal_touch_display_ok(NULL);
            break;
        }
    }
    else
    {
        if(button_mask == (BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT))
        {
                // if we were looping over a single element, disable this loop and diffuse the redisplay timeout (used by scrolling text)
                if(ux_loop_over_curr_element) {
                    ux_loop_over_curr_element = 0;
                    ux.callback_interval_ms = 0;
                }
                // prepare next screen
                ux_step = (ux_step + 1) % ux_step_count;
                // redisplay screen
                UX_REDISPLAY();
        }
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
        vars.tmp.output_numbering, sizeof(vars.tmp.output_numbering), "%d / %d",
        btchip_context_D.totalOutputs - btchip_context_D.remainingOutputs + 1,
        btchip_context_D.totalOutputs);
    ui_transaction_blue_values[0] = vars.tmp.output_numbering;
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
    G_ui_transaction_blue_state = TRANSACTION_MESSAGE;
    ui_transaction_blue_values[0] = vars.tmp.fullAddress;
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


#if defined(TARGET_NANOX)

const char* settings_submenu_getter(unsigned int idx);
void settings_submenu_selector(unsigned int idx);


void settings_pubkey_export_change(unsigned int enabled) {
    nvm_write((void *)&N_btchip.pubKeyRequestRestriction, &enabled, 1);
    ui_idle();
}
//////////////////////////////////////////////////////////////////////////////////////
// Public keys export submenu:

const char* const settings_pubkey_export_getter_values[] = {
  "Auto Approval",
  "Manual Approval",
  "Back"
};

const char* settings_pubkey_export_getter(unsigned int idx) {
  if (idx < ARRAYLEN(settings_pubkey_export_getter_values)) {
    return settings_pubkey_export_getter_values[idx];
  }
  return NULL;
}

void settings_pubkey_export_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      settings_pubkey_export_change(0);
      break;
    case 1:
      settings_pubkey_export_change(1);
      break;
    default:
      ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector);
  }
}

//////////////////////////////////////////////////////////////////////////////////////
// Settings menu:

const char* const settings_submenu_getter_values[] = {
  "Public keys export",
  "Back",
};

const char* settings_submenu_getter(unsigned int idx) {
  if (idx < ARRAYLEN(settings_submenu_getter_values)) {
    return settings_submenu_getter_values[idx];
  }
  return NULL;
}

void settings_submenu_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      ux_menulist_init_select(0, settings_pubkey_export_getter, settings_pubkey_export_selector, N_btchip.pubKeyRequestRestriction);
      break;
    default:
      ui_idle();
  }
}

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_idle_flow_1_step, 
    nn, 
    {
      "Application",
      "is ready",
    });
UX_STEP_VALID(
    ux_idle_flow_2_step,
    pb,
    ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector),
    {
      &C_icon_coggle,
      "Settings",
    });
UX_STEP_NOCB(
    ux_idle_flow_3_step, 
    bn, 
    {
      "Version",
      APPVERSION,
    });
UX_STEP_VALID(
    ux_idle_flow_4_step,
    pb,
    os_sched_exit(-1),
    {
      &C_icon_dashboard_x,
      "Quit",
    });
UX_FLOW(ux_idle_flow,
  &ux_idle_flow_1_step,
  &ux_idle_flow_2_step,
  &ux_idle_flow_3_step,
  &ux_idle_flow_4_step,
  FLOW_LOOP
);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_sign_flow_1_step, 
    pnn, 
    {
      &C_icon_certificate,
      "Sign",
      "message",
    });
UX_STEP_NOCB(
    ux_sign_flow_2_step, 
    bnnn_paging, 
    {
      .title = "Message hash",
      .text = vars.tmp.fullAddress,
    });
UX_STEP_VALID(
    ux_sign_flow_3_step,
    pbb,
    io_seproxyhal_touch_message_signature_verify_ok(NULL),
    {
      &C_icon_validate_14,
      "Sign",
      "message",
    });
UX_STEP_VALID(
    ux_sign_flow_4_step,
    pbb,
    io_seproxyhal_touch_message_signature_verify_cancel(NULL),
    {
      &C_icon_crossmark,
      "Cancel",
      "signature",
    });

UX_FLOW(ux_sign_flow,
  &ux_sign_flow_1_step,
  &ux_sign_flow_2_step,
  &ux_sign_flow_3_step,
  &ux_sign_flow_4_step
);

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(ux_confirm_full_flow_1_step, 
    pnn, 
    {
      &C_icon_eye,
      "Review",
      "transaction",
    });
UX_STEP_NOCB(
    ux_confirm_full_flow_2_step, 
    bnnn_paging, 
    {
      .title = "Amount",
      .text = vars.tmp.fullAmount
    });
UX_STEP_NOCB(
    ux_confirm_full_flow_3_step, 
    bnnn_paging, 
    {
      .title = "Address",
      .text = vars.tmp.fullAddress,
    });
UX_STEP_NOCB(
    ux_confirm_full_flow_4_step, 
    bnnn_paging, 
    {
      .title = "Fees",
      .text = vars.tmp.feesAmount,
    });
UX_STEP_VALID(
    ux_confirm_full_flow_5_step, 
    pbb, 
    io_seproxyhal_touch_verify_ok(NULL),
    {
      &C_icon_validate_14,
      "Accept",
      "and send",
    });
UX_STEP_VALID(
    ux_confirm_full_flow_6_step, 
    pb, 
    io_seproxyhal_touch_verify_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });
// confirm_full: confirm transaction / Amount: fullAmount / Address: fullAddress / Fees: feesAmount
UX_FLOW(ux_confirm_full_flow,
  &ux_confirm_full_flow_1_step,
  &ux_confirm_full_flow_2_step,
  &ux_confirm_full_flow_3_step,
  &ux_confirm_full_flow_4_step,
  &ux_confirm_full_flow_5_step,
  &ux_confirm_full_flow_6_step
);

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(
    ux_confirm_single_flow_1_step, 
    pnn, 
    {
      &C_icon_eye,
      "Review",
      vars.tmp.feesAmount, // output #
    });
UX_STEP_NOCB(
    ux_confirm_single_flow_2_step, 
    bnnn_paging, 
    {
      .title = "Amount",
      .text = vars.tmp.fullAmount,
    });
UX_STEP_NOCB(
    ux_confirm_single_flow_3_step, 
    bnnn_paging, 
    {
      .title = "Address",
      .text = vars.tmp.fullAddress,
    });
UX_STEP_VALID(
    ux_confirm_single_flow_5_step, 
    pb,
    io_seproxyhal_touch_verify_ok(NULL), 
    {
      &C_icon_validate_14,
      "Accept",
    });
UX_STEP_VALID(
    ux_confirm_single_flow_6_step, 
    pb, 
    io_seproxyhal_touch_verify_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });
// confirm_single: confirm output #x(feesAmount) / Amount: fullAmount / Address: fullAddress
UX_FLOW(ux_confirm_single_flow,
  &ux_confirm_single_flow_1_step,
  &ux_confirm_single_flow_2_step,
  &ux_confirm_single_flow_3_step,
  &ux_confirm_single_flow_5_step,
  &ux_confirm_single_flow_6_step
);

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(
    ux_finalize_flow_1_step, 
    pnn, 
    {
      &C_icon_eye,
      "Confirm",
      "transaction"
    });
UX_STEP_NOCB(
    ux_finalize_flow_4_step, 
    bnnn_paging, 
    {
      .title = "Fees",
      .text = vars.tmp.feesAmount,
    });
UX_STEP_VALID(
    ux_finalize_flow_5_step, 
    pbb, 
    io_seproxyhal_touch_verify_ok(NULL),
    {
      &C_icon_validate_14,
      "Accept",
      "and send"
    });
UX_STEP_VALID(
    ux_finalize_flow_6_step, 
    pb, 
    io_seproxyhal_touch_verify_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });
// finalize: confirm transaction / Fees: feesAmount
UX_FLOW(ux_finalize_flow,
  &ux_finalize_flow_1_step,
  &ux_finalize_flow_4_step,
  &ux_finalize_flow_5_step,
  &ux_finalize_flow_6_step
);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_display_public_flow_1_step, 
    pnn, 
    {
      &C_icon_warning,
      "The derivation",
      "path is unusual!",
    });
UX_STEP_NOCB(
    ux_display_public_flow_2_step, 
    bnnn_paging, 
    {
      .title = "Derivation path",
      .text = vars.tmp_warning.derivation_path,
    });
UX_STEP_VALID(
    ux_display_public_flow_3_step, 
    pnn,
    io_seproxyhal_touch_display_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject if you're",
      "not sure",
    });
UX_STEP_NOCB(
    ux_display_public_flow_4_step, 
    pnn, 
    {
      &C_icon_validate_14,
      "Approve derivation",
      "path",
    });
UX_STEP_NOCB(
    ux_display_public_flow_5_step, 
    bnnn_paging, 
    {
      .title = "Address",
      .text = G_io_apdu_buffer+200,
    });
UX_STEP_VALID(
    ux_display_public_flow_6_step, 
    pb, 
    io_seproxyhal_touch_display_ok(NULL),
    {
      &C_icon_validate_14,
      "Approve",
    });
UX_STEP_VALID(
    ux_display_public_flow_7_step, 
    pb, 
    io_seproxyhal_touch_display_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });

UX_FLOW(ux_display_public_with_warning_flow,
  &ux_display_public_flow_1_step,
  &ux_display_public_flow_2_step,
  &ux_display_public_flow_3_step,
  &ux_display_public_flow_4_step,
  FLOW_BARRIER,
  &ux_display_public_flow_5_step,
  &ux_display_public_flow_6_step,
  &ux_display_public_flow_7_step
);

UX_FLOW(ux_display_public_flow,
  &ux_display_public_flow_5_step,
  &ux_display_public_flow_6_step,
  &ux_display_public_flow_7_step
);


//////////////////////////////////////////////////////////////////////
UX_STEP_VALID(
    ux_display_token_flow_1_step, 
    pbb, 
    io_seproxyhal_touch_display_ok(NULL),
    {
      &C_icon_validate_14,
      "Confirm token",
      G_io_apdu_buffer+200,
    });
UX_STEP_VALID(
    ux_display_token_flow_2_step, 
    pb, 
    io_seproxyhal_touch_display_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });

UX_FLOW(ux_display_token_flow,
  &ux_display_token_flow_1_step,
  &ux_display_token_flow_2_step
);

//////////////////////////////////////////////////////////////////////
UX_STEP_VALID(
    ux_request_pubkey_approval_flow_1_step, 
    pbb, 
    io_seproxyhal_touch_display_ok(NULL),
    {
      &C_icon_validate_14,
      "Export",
      "public key?",
    });
UX_STEP_VALID(
    ux_request_pubkey_approval_flow_2_step, 
    pb, 
    io_seproxyhal_touch_display_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });

UX_FLOW(ux_request_pubkey_approval_flow,
  &ux_request_pubkey_approval_flow_1_step,
  &ux_request_pubkey_approval_flow_2_step
);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_request_change_path_approval_flow_1_step, 
    pbb, 
    {
      &C_icon_eye,
      "The change path",
      "is unusual",
    });
UX_STEP_NOCB(
    ux_request_change_path_approval_flow_2_step, 
    bnnn_paging, 
    {
      .title = "Change path",
      .text = vars.tmp_warning.derivation_path,
    });
UX_STEP_VALID(
    ux_request_change_path_approval_flow_3_step, 
    pbb, 
    io_seproxyhal_touch_display_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject if you're",
      "not sure",
    });
UX_STEP_VALID(
    ux_request_change_path_approval_flow_4_step, 
    pb, 
    io_seproxyhal_touch_display_ok(NULL),
    {
      &C_icon_validate_14,
      "Approve",
    });

UX_FLOW(ux_request_change_path_approval_flow,
  &ux_request_change_path_approval_flow_1_step,
  &ux_request_change_path_approval_flow_2_step,
  &ux_request_change_path_approval_flow_3_step,
  &ux_request_change_path_approval_flow_4_step
);

#endif // #if defined(TARGET_NANOX)

void ui_idle(void) {
    ux_step_count = 0;
    ux_loop_over_curr_element = 0;

#if defined(TARGET_BLUE)
    UX_DISPLAY(ui_idle_blue, ui_idle_blue_prepro);
#elif defined(TARGET_NANOS)
    UX_MENU_DISPLAY(0, menu_main, NULL);
#elif defined(TARGET_NANOX)
    // reserve a display stack slot if none yet
    if(G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
#endif // #if TARGET_ID
}

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
                if(!ux_loop_over_curr_element) {
                    ux_step = (ux_step + 1) % ux_step_count;
                }
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
        unsigned char borrow;

        borrow = transaction_amount_sub_be(
                fees, btchip_context_D.transactionContext.transactionAmount,
                btchip_context_D.totalOutputAmount);
        if (borrow && G_coin_config->kind == COIN_KIND_KOMODO) {
            os_memmove(vars.tmp.feesAmount, "REWARD", 6);
            vars.tmp.feesAmount[6] = '\0';
        }
        else {
            if (borrow) {
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
    }
    return 1;
error:
    return 0;
}

#define OMNI_ASSETID 1
#define MAIDSAFE_ASSETID 3
#define USDT_ASSETID 31

uint8_t prepare_single_output() {
    // TODO : special display for OP_RETURN
    unsigned char amount[8];
    char tmp[80];
    unsigned int offset = 0;
    unsigned char versionSize;
    int addressOffset;
    unsigned char address[22];
    unsigned short version;
    unsigned short textSize;
    unsigned char nativeSegwit;

    vars.tmp.fullAddress[0] = '\0';
    btchip_swap_bytes(amount, btchip_context_D.currentOutput + offset, 8);
    offset += 8;
    nativeSegwit = btchip_output_script_is_native_witness(
        btchip_context_D.currentOutput + offset);
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
            } else if (G_coin_config->flags & FLAG_MULTICHAIN) {
                textSize = multichainaddr_encode(
                    address + versionSize, 20, (unsigned char *)tmp,
                    sizeof(tmp), (version == btchip_context_D.payToScriptHashVersion
                    ? G_coin_config->mc_p2sh_version
                    : G_coin_config->mc_p2pkh_version), G_coin_config->mc_addr_checksum, 1);
                tmp[textSize] = '\0';
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

        strncpy(vars.tmp.fullAddress, tmp, sizeof(vars.tmp.fullAddress));
        vars.tmp.fullAddress[sizeof(vars.tmp.fullAddress) - 1] = '\0';
    }

    // Prepare amount

    // Handle Omni simple send
    if ((btchip_context_D.currentOutput[offset + 2] == 0x14) &&
        (os_memcmp(btchip_context_D.currentOutput + offset + 3, "omni", 4) == 0) &&
        (os_memcmp(btchip_context_D.currentOutput + offset + 3 + 4, "\0\0\0\0", 4) == 0)) {
            uint8_t headerLength;
            uint32_t omniAssetId = btchip_read_u32(btchip_context_D.currentOutput + offset + 3 + 4 + 4, 1, 0);
            switch(omniAssetId) {
                case OMNI_ASSETID:
                    strcpy(vars.tmp.fullAmount, "OMNI ");
                    break;
                case USDT_ASSETID:
                    strcpy(vars.tmp.fullAmount, "USDT ");
                    break;
                case MAIDSAFE_ASSETID:
                    strcpy(vars.tmp.fullAmount, "MAID ");
                    break;
                default:
                    snprintf(vars.tmp.fullAmount, sizeof(vars.tmp.fullAmount), "OMNI asset %d ", omniAssetId);
                    break;
            }
            headerLength = strlen(vars.tmp.fullAmount);
            btchip_context_D.tmp = vars.tmp.fullAmount + headerLength;
            textSize = btchip_convert_hex_amount_to_displayable(btchip_context_D.currentOutput + offset + 3 + 4 + 4 + 4);
            vars.tmp.fullAmount[textSize + headerLength] = '\0';
    }
    else {
        os_memmove(vars.tmp.fullAmount, btchip_context_D.shortCoinId,
               btchip_context_D.shortCoinIdLength);
        vars.tmp.fullAmount[btchip_context_D.shortCoinIdLength] = ' ';
        btchip_context_D.tmp =
            (unsigned char *)(vars.tmp.fullAmount +
                          btchip_context_D.shortCoinIdLength + 1);
        textSize = btchip_convert_hex_amount_to_displayable(amount);
        vars.tmp.fullAmount[textSize + btchip_context_D.shortCoinIdLength + 1] =
            '\0';
    }

    return 1;
}

uint8_t prepare_full_output(uint8_t checkOnly) {
    unsigned int offset = 0;
    int numberOutputs;
    int i;
    unsigned int currentPos = 0;
    unsigned char amount[8], totalOutputAmount[8], fees[8];
    char tmp[80];
    unsigned char outputPos = 0, changeFound = 0, specialOpFound = 0;
    unsigned char borrow;
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
        // Always notify OP_RETURN to the user
        if (nullAmount && isOpReturn) {
            if (!checkOnly) {
                PRINTF("Error : Unexpected OP_RETURN");
            }
            goto error;
        }
        if ((nullAmount && isOpReturn) ||
             ((G_coin_config->kind == COIN_KIND_QTUM) && (isOpCall || isOpCreate))) {
            specialOpFound = 1;
        }
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
    if ((numberOutputs > 1) && (!changeFound || !specialOpFound)) {
        if (!checkOnly) {
            PRINTF("Error : too many inputs");
        }
        goto error;
    }
    borrow = transaction_amount_sub_be(
            fees, btchip_context_D.transactionContext.transactionAmount,
            totalOutputAmount);
    if (borrow && G_coin_config->kind != COIN_KIND_KOMODO) {
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
                        } else if (G_coin_config->flags & FLAG_MULTICHAIN) {
                            textSize = multichainaddr_encode(
                                address + versionSize, 20, (unsigned char *)tmp,
                                sizeof(tmp), (version == btchip_context_D.payToScriptHashVersion
                                ? G_coin_config->mc_p2sh_version
                                : G_coin_config->mc_p2pkh_version), G_coin_config->mc_addr_checksum, 1);
                            tmp[textSize] = '\0';
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

                    strncpy(vars.tmp.fullAddress, tmp, sizeof(vars.tmp.fullAddress));
                    vars.tmp.fullAddress[sizeof(vars.tmp.fullAddress) - 1] = '\0';

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
                    if (borrow) {
                        os_memmove(vars.tmp.feesAmount, "REWARD", 6);
                        vars.tmp.feesAmount[6] = '\0';
                    }
                    else {
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
                    }
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
    uint8_t buffer[32];

    cx_hash(&btchip_context_D.transactionHashAuthorization.header, CX_LAST,
            vars.tmp.fullAmount, 0, buffer, 32);

    snprintf(vars.tmp.fullAddress, sizeof(vars.tmp.fullAddress), "%.*H...%.*H",
             8, buffer, 8, buffer + 32 - 8);
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
#elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_confirm_full_flow, NULL);
#endif // TARGET_NANOX
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
#elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_confirm_single_flow, NULL);
#endif // TARGET_NANOX 
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
#elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_finalize_flow, NULL);
#endif // TARGET_NANOX 
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
#elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_sign_flow, NULL);
#endif // TARGET_NANOX 
}

void btchip_bagl_display_public_key(unsigned char* derivation_path) {
    // append a white space at the end of the address to avoid glitch on nano S
    strcat(G_io_apdu_buffer + 200, " ");

    bip32_print_path(derivation_path, vars.tmp_warning.derivation_path, MAX_DERIV_PATH_ASCII_LENGTH);
    uint8_t is_derivation_path_unusual = bip44_derivation_guard(derivation_path, false);

#if defined(TARGET_BLUE)

    if(is_derivation_path_unusual){
        UX_DISPLAY(ui_display_derivation_warning, ui_request_change_path_approval_blue_prepro);
    }
    else{
        load_qr_code(G_io_apdu_buffer + 200);
        UX_DISPLAY(ui_display_address_blue, ui_display_address_blue_prepro);
    }

#elif defined(TARGET_NANOS)
    // prepend a white space to the address
    G_io_apdu_buffer[199] = ' ';
    ux_step = is_derivation_path_unusual?0:4;
    ux_step_count = 6;
    UX_DISPLAY(ui_display_address_nanos, ui_display_address_nanos_prepro);
    
#elif defined(TARGET_NANOX)
    ux_flow_init(0, is_derivation_path_unusual?ux_display_public_with_warning_flow:ux_display_public_flow, NULL);
#endif // TARGET_NANOX
}

void btchip_bagl_display_token()
{
 #if defined(TARGET_BLUE)
    UX_DISPLAY(ui_display_token_blue, ui_display_token_blue_prepro);
#elif defined(TARGET_NANOS)
    ux_step = 0;
    ux_step_count = 1;
    UX_DISPLAY(ui_display_token_nanos, NULL);
#elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_display_token_flow, NULL);
#endif // #if TARGET_ID
}

void btchip_bagl_request_pubkey_approval()
{
 #if defined(TARGET_BLUE)
     UX_DISPLAY(ui_request_pubkey_approval_blue, ui_request_pubkey_approval_blue_prepro);
#elif defined(TARGET_NANOS)
    // append and prepend a white space to the address
    ux_step = 0;
    ux_step_count = 1;
    UX_DISPLAY(ui_request_pubkey_approval_nanos, NULL);
#elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_request_pubkey_approval_flow, NULL);
#endif // #if TARGET_ID
}

void btchip_bagl_request_change_path_approval(unsigned char* change_path)
{
    bip32_print_path(change_path, vars.tmp_warning.derivation_path, MAX_DERIV_PATH_ASCII_LENGTH);
 #if defined(TARGET_BLUE)
    UX_DISPLAY(ui_request_change_path_approval_blue, ui_request_change_path_approval_blue_prepro);
#elif defined(TARGET_NANOS)
    // append and prepend a white space to the address
    ux_step = 0;
    ux_step_count = 4;
    UX_DISPLAY(ui_request_change_path_approval_nanos, ui_request_change_path_approval_nanos_prepro);
#elif defined(TARGET_NANOX)
    ux_flow_init(0, ux_request_change_path_approval_flow, NULL);
#endif // #if TARGET_ID
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
#ifdef MC_COIN_ADDR_CHECKSUM
    .mc_addr_checksum = MC_COIN_ADDR_CHECKSUM,
    .mc_p2pkh_version = MC_COIN_P2PKH_VERSION,
    .mc_p2sh_version = MC_COIN_P2SH_VERSION,
#endif // COIN_ADDR_CHECKSUM
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
#ifdef TARGET_BLUE
    unsigned char header[sizeof(COIN_COINID_HEADER)];
    strcpy(header, COIN_COINID_HEADER);
#endif // TARGET_BLUE
#ifdef COIN_NATIVE_SEGWIT_PREFIX
    unsigned char native_segwit_prefix[sizeof(COIN_NATIVE_SEGWIT_PREFIX)];
    strcpy(native_segwit_prefix, COIN_NATIVE_SEGWIT_PREFIX);
#endif
    btchip_altcoin_config_t coin_config;
    os_memmove(&coin_config, &C_coin_config, sizeof(coin_config));
#ifdef TARGET_BLUE
    coin_config.header_text = header;
    coin_config.color_header = COIN_COLOR_HDR;
    coin_config.color_dashboard = COIN_COLOR_DB;
#endif // TARGET_BLUE
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

#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif // TARGET_NANOX

                btchip_context_init();

                USB_power(0);
                USB_power(1);

                ui_idle();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif // HAVE_BLE

#if defined(TARGET_BLUE)
                // setup the status bar colors (remembered after wards, even
                // more if another app does not resetup after app switch)
                UX_SET_STATUS_BAR_COLOR(COLOR_WHITE, G_coin_config->color_header);
#endif // TARGET_ID

                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                CLOSE_TRY;
                continue;
            }
            CATCH_ALL {
                CLOSE_TRY;
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
