#include "gallaghertest.h"

#include <unistd.h>
#include <string.h>      // memcpy memset
#include "ui.h"

#include "mifare/gallaghercore.h"


static bool TestCreds() {
    GallagherCredentials_t creds1 = {
        .region_code = 0x0,
        .facility_code = 0x0,
        .card_number = 0x0,
        .issue_level = 0x0,
    };

    GallagherCredentials_t creds2 = {
        .region_code = 0x1,
        .facility_code = 0x2,
        .card_number = 0x20,
        .issue_level = 0x1,
    };

    GallagherCredentials_t cred_result = {0};
    uint8_t bytes_result[8] = {0};

    gallagher_encode_creds(bytes_result, &creds1);
    gallagher_decode_creds(bytes_result, &cred_result);
    if (cred_result.region_code != creds1.region_code || cred_result.facility_code != creds1.facility_code || cred_result.card_number != creds1.card_number || cred_result.issue_level != creds1.issue_level) {
        PrintAndLogEx(INFO, "Gallagher encode/decode test failed");
        return false;
    }

    gallagher_encode_creds(bytes_result, &creds2);
    gallagher_decode_creds(bytes_result, &cred_result);
    if (cred_result.region_code != creds2.region_code || cred_result.facility_code != creds2.facility_code || cred_result.card_number != creds2.card_number || cred_result.issue_level != creds2.issue_level) {
        PrintAndLogEx(INFO, "Gallagher encode/decode test failed");
        return false;
    }

    return false;
}

static bool creds_match(GallagherCredentials_t *creds1, GallagherCredentials_t *creds2) {
    return creds1->region_code == creds2->region_code && creds1->facility_code == creds2->facility_code && creds1->card_number == creds2->card_number && creds1->issue_level == creds2->issue_level;
}

static bool TestMES() {

    uint8_t csn[] = {0x3C, 0x54, 0x51, 0xE3};
    uint8_t csn_len = 4;
    uint8_t site_key[] = {0x13, 0x37, 0xD0, 0x0D, 0x13, 0x37, 0xD0, 0x0D, 0x13, 0x37, 0xD0, 0x0D, 0x13, 0x37, 0xD0, 0x0D};
    uint8_t site_key_len = 16;
 
    GallagherCredentials_t known_cred;
    gallagher_construct_credentail(&known_cred, 12, 0x1337, 0xF00D, 1, true, csn, csn_len, site_key);

    GallagherCredentials_t result_creds = {0};
    gallagher_construct_credentail(&result_creds, 0, 0, 0, 0, true, csn, csn_len, site_key);
    PrintAndLogEx(DEBUG, "Diversified Site Key: %s", sprint_hex_ascii(site_key, 16));

    uint8_t sector_result[16] = {0};
    uint8_t known_sector[16] = {0x4F, 0x36, 0xB7, 0x4E, 0xFF, 0xCD, 0x76, 0xEF, 0xED, 0xA5, 0x74, 0x58, 0xC8, 0xB4, 0xE3, 0x04};

    gallagher_encode_mes(sector_result, &known_cred);
    for (int i = 0; i < 16; i++) {
        if (sector_result[i] != known_sector[i]) {
            PrintAndLogEx(INFO, "Gallagher MES encode test failed");
            PrintAndLogEx(INFO, "Expected: %s", sprint_hex_ascii(known_sector, 16));
            PrintAndLogEx(INFO,  "Got:     %s", sprint_hex_ascii(sector_result, 16));
            break;
        }
    }

    PrintAndLogEx(DEBUG, "Finished encoding");

    if (gallagher_decode_mes(known_sector, &result_creds, site_key) != PM3_SUCCESS) {
        if (creds_match(&known_cred, &result_creds)) {
            PrintAndLogEx(INFO, "Gallagher MES decoded different creds than expected");
            return false;
        }
        PrintAndLogEx(INFO, "Gallagher MES decode test failed");
    } else {
        print_gallagher_creds(&result_creds);
    }
    return false;
}

bool GallagherTest(bool verbose) {
    bool result = true;
    result &= TestMES();
    result &= TestCreds();
    return result;
}
