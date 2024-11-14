//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Common functionality for low/high-frequency GALLAGHER tag encoding & decoding.
//-----------------------------------------------------------------------------
#include "gallaghercore.h"
#include "aes.h"
#include "common.h"
#include "ui.h"

static void scramble(uint8_t *arr, uint8_t len) {
    const uint8_t lut[] = {
        0xa3, 0xb0, 0x80, 0xc6, 0xb2, 0xf4, 0x5c, 0x6c, 0x81, 0xf1, 0xbb, 0xeb, 0x55, 0x67, 0x3c, 0x05,
        0x1a, 0x0e, 0x61, 0xf6, 0x22, 0xce, 0xaa, 0x8f, 0xbd, 0x3b, 0x1f, 0x5e, 0x44, 0x04, 0x51, 0x2e,
        0x4d, 0x9a, 0x84, 0xea, 0xf8, 0x66, 0x74, 0x29, 0x7f, 0x70, 0xd8, 0x31, 0x7a, 0x6d, 0xa4, 0x00,
        0x82, 0xb9, 0x5f, 0xb4, 0x16, 0xab, 0xff, 0xc2, 0x39, 0xdc, 0x19, 0x65, 0x57, 0x7c, 0x20, 0xfa,
        0x5a, 0x49, 0x13, 0xd0, 0xfb, 0xa8, 0x91, 0x73, 0xb1, 0x33, 0x18, 0xbe, 0x21, 0x72, 0x48, 0xb6,
        0xdb, 0xa0, 0x5d, 0xcc, 0xe6, 0x17, 0x27, 0xe5, 0xd4, 0x53, 0x42, 0xf3, 0xdd, 0x7b, 0x24, 0xac,
        0x2b, 0x58, 0x1e, 0xa7, 0xe7, 0x86, 0x40, 0xd3, 0x98, 0x97, 0x71, 0xcb, 0x3a, 0x0f, 0x01, 0x9b,
        0x6e, 0x1b, 0xfc, 0x34, 0xa6, 0xda, 0x07, 0x0c, 0xae, 0x37, 0xca, 0x54, 0xfd, 0x26, 0xfe, 0x0a,
        0x45, 0xa2, 0x2a, 0xc4, 0x12, 0x0d, 0xf5, 0x4f, 0x69, 0xe0, 0x8a, 0x77, 0x60, 0x3f, 0x99, 0x95,
        0xd2, 0x38, 0x36, 0x62, 0xb7, 0x32, 0x7e, 0x79, 0xc0, 0x46, 0x93, 0x2f, 0xa5, 0xba, 0x5b, 0xaf,
        0x52, 0x1d, 0xc3, 0x75, 0xcf, 0xd6, 0x4c, 0x83, 0xe8, 0x3d, 0x30, 0x4e, 0xbc, 0x08, 0x2d, 0x09,
        0x06, 0xd9, 0x25, 0x9e, 0x89, 0xf2, 0x96, 0x88, 0xc1, 0x8c, 0x94, 0x0b, 0x28, 0xf0, 0x47, 0x63,
        0xd5, 0xb3, 0x68, 0x56, 0x9c, 0xf9, 0x6f, 0x41, 0x50, 0x85, 0x8b, 0x9d, 0x59, 0xbf, 0x9f, 0xe2,
        0x8e, 0x6a, 0x11, 0x23, 0xa1, 0xcd, 0xb5, 0x7d, 0xc7, 0xa9, 0xc8, 0xef, 0xdf, 0x02, 0xb8, 0x03,
        0x6b, 0x35, 0x3e, 0x2c, 0x76, 0xc9, 0xde, 0x1c, 0x4b, 0xd1, 0xed, 0x14, 0xc5, 0xad, 0xe9, 0x64,
        0x4a, 0xec, 0x8d, 0xf7, 0x10, 0x43, 0x78, 0x15, 0x87, 0xe4, 0xd7, 0x92, 0xe1, 0xee, 0xe3, 0x90
    };

    for (int i = 0; i < len;  i++) {
        arr[i] = lut[arr[i]];
    }
}

static void descramble(uint8_t *arr, uint8_t len) {
    const uint8_t lut[] = {
        0x2f, 0x6e, 0xdd, 0xdf, 0x1d, 0x0f, 0xb0, 0x76, 0xad, 0xaf, 0x7f, 0xbb, 0x77, 0x85, 0x11, 0x6d,
        0xf4, 0xd2, 0x84, 0x42, 0xeb, 0xf7, 0x34, 0x55, 0x4a, 0x3a, 0x10, 0x71, 0xe7, 0xa1, 0x62, 0x1a,
        0x3e, 0x4c, 0x14, 0xd3, 0x5e, 0xb2, 0x7d, 0x56, 0xbc, 0x27, 0x82, 0x60, 0xe3, 0xae, 0x1f, 0x9b,
        0xaa, 0x2b, 0x95, 0x49, 0x73, 0xe1, 0x92, 0x79, 0x91, 0x38, 0x6c, 0x19, 0x0e, 0xa9, 0xe2, 0x8d,
        0x66, 0xc7, 0x5a, 0xf5, 0x1c, 0x80, 0x99, 0xbe, 0x4e, 0x41, 0xf0, 0xe8, 0xa6, 0x20, 0xab, 0x87,
        0xc8, 0x1e, 0xa0, 0x59, 0x7b, 0x0c, 0xc3, 0x3c, 0x61, 0xcc, 0x40, 0x9e, 0x06, 0x52, 0x1b, 0x32,
        0x8c, 0x12, 0x93, 0xbf, 0xef, 0x3b, 0x25, 0x0d, 0xc2, 0x88, 0xd1, 0xe0, 0x07, 0x2d, 0x70, 0xc6,
        0x29, 0x6a, 0x4d, 0x47, 0x26, 0xa3, 0xe4, 0x8b, 0xf6, 0x97, 0x2c, 0x5d, 0x3d, 0xd7, 0x96, 0x28,
        0x02, 0x08, 0x30, 0xa7, 0x22, 0xc9, 0x65, 0xf8, 0xb7, 0xb4, 0x8a, 0xca, 0xb9, 0xf2, 0xd0, 0x17,
        0xff, 0x46, 0xfb, 0x9a, 0xba, 0x8f, 0xb6, 0x69, 0x68, 0x8e, 0x21, 0x6f, 0xc4, 0xcb, 0xb3, 0xce,
        0x51, 0xd4, 0x81, 0x00, 0x2e, 0x9c, 0x74, 0x63, 0x45, 0xd9, 0x16, 0x35, 0x5f, 0xed, 0x78, 0x9f,
        0x01, 0x48, 0x04, 0xc1, 0x33, 0xd6, 0x4f, 0x94, 0xde, 0x31, 0x9d, 0x0a, 0xac, 0x18, 0x4b, 0xcd,
        0x98, 0xb8, 0x37, 0xa2, 0x83, 0xec, 0x03, 0xd8, 0xda, 0xe5, 0x7a, 0x6b, 0x53, 0xd5, 0x15, 0xa4,
        0x43, 0xe9, 0x90, 0x67, 0x58, 0xc0, 0xa5, 0xfa, 0x2a, 0xb1, 0x75, 0x50, 0x39, 0x5c, 0xe6, 0xdc,
        0x89, 0xfc, 0xcf, 0xfe, 0xf9, 0x57, 0x54, 0x64, 0xa8, 0xee, 0x23, 0x0b, 0xf1, 0xea, 0xfd, 0xdb,
        0xbd, 0x09, 0xb5, 0x5b, 0x05, 0x86, 0x13, 0xf3, 0x24, 0xc5, 0x3f, 0x44, 0x72, 0x7c, 0x7e, 0x36
    };

    for (int i = 0; i < len;  i++) {
        arr[i] = lut[arr[i]];
    }
}

int gallagher_deversify_classic_key(uint8_t *site_key, uint8_t *csn, size_t csn_len, uint8_t *key_output) {
    memcpy(key_output, site_key, 16);
    for (int i = 0; i < csn_len; i++) {
        key_output[i] = site_key[i] ^ csn[i];
    }
    return PM3_SUCCESS;
}

int gallagher_construct_credentail(GallagherCredentials_t *creds, uint8_t region, uint16_t facility, uint32_t card, uint8_t issue, bool mes, uint8_t *csn, uint8_t csn_len, uint8_t *site_key) {
    creds->region_code = region;
    creds->facility_code = facility;
    creds->card_number = card;
    creds->issue_level = issue;
    creds->mes = mes;
    memcpy(creds->csn, csn, csn_len);
    memcpy(creds->site_key, site_key, 16);
    return PM3_SUCCESS;
}

void gallagher_decode_creds(uint8_t *eight_bytes, GallagherCredentials_t *creds) {
    uint8_t *arr = eight_bytes;

    descramble(arr, 8);

    // 4bit region code
    creds->region_code = (arr[3] & 0x1E) >> 1;

    // 16bit facility code
    creds->facility_code = (arr[5] & 0x0F) << 12 | arr[1] << 4 | ((arr[7] >> 4) & 0x0F);

    // 24bit card number
    creds->card_number = arr[0] << 16 | (arr[4] & 0x1F) << 11 | arr[2] << 3 | (arr[3] & 0xE0) >> 5;

    // 4bit issue level
    creds->issue_level = arr[7] & 0x0F;
}

void gallagher_encode_creds(uint8_t *eight_bytes, GallagherCredentials_t *creds) {
    uint8_t rc = creds->region_code;
    uint16_t fc = creds->facility_code;
    uint32_t cn = creds->card_number;
    uint8_t il = creds->issue_level;

    // put data into the correct places (Gallagher obfuscation)
    eight_bytes[0] = (cn & 0xffffff) >> 16;
    eight_bytes[1] = (fc & 0xfff) >> 4;
    eight_bytes[2] = (cn & 0x7ff) >> 3;
    eight_bytes[3] = (cn & 0x7) << 5 | (rc & 0xf) << 1;
    eight_bytes[4] = (cn & 0xffff) >> 11;
    eight_bytes[5] = (fc & 0xffff) >> 12;
    eight_bytes[6] = 0;
    eight_bytes[7] = (fc & 0xf) << 4 | (il & 0xf);

    // more obfuscation
    scramble(eight_bytes, 8);
}

int gallagher_encode_mes(uint8_t *sixteen_bytes, GallagherCredentials_t *creds) {
    // unknown parramters from the research these might be for UUID's longer than 4 bytes?
    uint8_t UB = 0x00;
    uint8_t UC = 0x00;
    uint8_t UD = 0x00;
    uint8_t UE = 0x00;
    uint8_t PO = 0x00; // Pin offset
    uint8_t UX = 0x00;
    uint16_t R = 0x0748;

    uint8_t mes[16];
    uint8_t deversified_site_key[16];

    if (creds->csn_len > 4){
        PrintAndLogEx(ERR, "Credential could not be encoded into a Mifare Enhanced Encription block. only 4 byte UUID's are supported");
        return PM3_ENOTIMPL;
    }

    mes[0] = 0x01;
    mes[1] = (creds->card_number & 0xFF0000) >> 16;
    mes[2] = (creds->card_number & 0x00FF00) >> 8;
    mes[3] = creds->card_number & 0x0000FF;
    mes[4] = (creds->facility_code & 0xFF00) >> 8;
    mes[5] = creds->facility_code & 0x00FF;
    mes[6] = ((creds->region_code & 0x0F) << 4) | (creds->issue_level & 0x0F);
    mes[7] = (PO & 0x0F) | ((UX & 0x0F) << 4);
    mes[8] = (UB & 0x0F) | ((UC & 0x0F) << 4);
    mes[9] = (UD & 0x0F) | ((UE & 0x0F) << 4);
    mes[10] = creds->csn[0];
    mes[11] = creds->csn[1];
    mes[12] = creds->csn[2];
    mes[13] = creds->csn[3];
    mes[14] = (R & 0xFF00) >> 8;
    mes[15] = R & 0x00FF;

    PrintAndLogEx(DEBUG, "MES before encryption %s", sprint_hex_ascii(mes, 16));

    gallagher_deversify_classic_key(creds->site_key, creds->csn, creds->csn_len, deversified_site_key);

    mbedtls_aes_context actx;
    mbedtls_aes_init(&actx);
    if (mbedtls_aes_setkey_enc(&actx, deversified_site_key, 128) != 0) return PM3_ENOKEY;
    if (mbedtls_aes_crypt_ecb(&actx, MBEDTLS_AES_ENCRYPT, mes, sixteen_bytes) != 0) return PM3_ENOKEY;;
    mbedtls_aes_free(&actx);

    PrintAndLogEx(DEBUG, "MES after encryption %s", sprint_hex_ascii(sixteen_bytes, 16));
    return PM3_SUCCESS;
}

int gallagher_decode_mes(uint8_t *block, GallagherCredentials_t *creds) {
    // unknown parramters from the research these might be for UUID's longer than 4 bytes?
    // uint8_t UB = 0x00; 
    // uint8_t UC = 0x00;
    // uint8_t UD = 0x00;
    // uint8_t UE = 0x00;
    // uint8_t PO = 0x00;
    // uint8_t UX = 0x00;
    uint16_t R = 0x0748;
    uint8_t mes[16];

    uint8_t deversified_site_key[16];
    gallagher_deversify_classic_key(creds->site_key, creds->csn, creds->csn_len, deversified_site_key);
    if (creds->csn_len>4){
        PrintAndLogEx(WARNING, "UUID length is > 4, this may not be a valid gallagher credential?");
    }
    
    // AES decrypt 16 bytes
    mbedtls_aes_context actx;
    mbedtls_aes_init(&actx);
    if (mbedtls_aes_setkey_dec(&actx, deversified_site_key, 128) != 0) return PM3_ENOKEY;
    if (mbedtls_aes_crypt_ecb(&actx, MBEDTLS_AES_DECRYPT, block, mes) != 0) return PM3_ENOKEY;;
    mbedtls_aes_free(&actx);

    PrintAndLogEx(DEBUG, "MES after decryption %s", sprint_hex_ascii(mes, 16));

    if (mes[0] != 0x01){
        PrintAndLogEx(ERR, "MES block is not valid");
        return PM3_EWRONGANSWER;
    }
    creds->card_number = mes[1] << 16 | mes[2] << 8 | mes[3];
    creds->facility_code = mes[4] << 8 | mes[5];
    creds->region_code = (mes[6] & 0xF0) >> 4;
    creds->issue_level = mes[6] & 0x0F;
    // PO = mes[7] & 0x0F;
    // UX = (mes[7] & 0xF0) >> 4;
    // UB = mes[8] & 0x0F;
    // UC = (mes[8] & 0xF0) >> 4;
    // UD = mes[9] & 0x0F;
    // UE = (mes[9] & 0xF0) >> 4;
    // csn is already varified by key deversification
    // csn[0] = mes[10];
    // csn[1] = mes[11];
    // csn[2] = mes[12];
    // csn[3] = mes[13];
    R = mes[14] << 8 | mes[15];
    if (R != 0x0748) {
        PrintAndLogEx(WARNING, "R value is different from 0x0748, this hasn' seen in the wild \n https://github.com/megabug/gallagher-research/blob/master/formats/mes.md");
    }

    return PM3_SUCCESS;
}

bool gallagher_is_valid_creds_struct(GallagherCredentials_t *creds) {
    return gallagher_is_valid_creds(creds->region_code, creds->facility_code, creds->card_number, creds->issue_level);
}

bool gallagher_is_valid_creds(uint64_t region_code, uint64_t facility_code, uint64_t card_number, uint64_t issue_level) {
    bool is_valid = true;

    // validate input
    if (region_code > 0x0f) {
        PrintAndLogEx(ERR, "Region code must be 0 <= rc <= 15 (4 bits), received: %"PRIu64, region_code);
        is_valid = false;
    }
    if (facility_code > 0xffff) {
        PrintAndLogEx(ERR, "Facility code must be 0 <= fc <= 65535 (2 bytes), received: %"PRIu64, facility_code);
        is_valid = false;
    }
    if (card_number > 0xffffff) {
        PrintAndLogEx(ERR, "Card number must be 0 <= cn <= 16777215 (3 bytes), received: %"PRIu64, card_number);
        is_valid = false;
    }
    if (issue_level > 0x0f) {
        PrintAndLogEx(ERR, "Issue level must be 0 <= il <= 15 (4 bits), received: %"PRIu64, issue_level);
        is_valid = false;
    }
    return is_valid;
}

void print_gallagher_creds(GallagherCredentials_t *creds) {

    if (!gallagher_is_valid_creds_struct(creds)) {
        PrintAndLogEx(ERR, "Invalid Gallagher credential");
        return;
    }
    PrintAndLogEx(SUCCESS, "Gallagher - region: " _GREEN_("%c") " ( " _GREEN_("%u") " )"
                           ", facility: " _GREEN_("%u")
                           ", card number: " _GREEN_("%u")
                           ", issue level: " _GREEN_("%u"),
    'A' + creds->region_code,
                  creds->region_code,
                  creds->facility_code,
                  creds->card_number,
                  creds->issue_level
                 );
}
