
#include <stdlib.h>

#include "portable.h"
#include <ac/string.h>
#include "lber_pvt.h"
#include "lutil.h"

#include "crypt_blowfish.h"

#define BCRYPT_DEFAULT_PREFIX    "$2b"

#define DEFAULT_WORKFACTOR        8
#define MIN_WORKFACTOR            4
#define MAX_WORKFACTOR           32

#define SALT_SIZE                16
#define SALT_OUTPUT_SIZE	     (7 + 22 + 1)
#define OUTPUT_SIZE              (7 + 22 + 31 + 1)

#ifdef SLAPD_BCRYPT_DEBUG
#include <stdio.h>
#define BCRYPT_DEBUG(fmt, args...) printf("DEBUG: %s:%s:%d: "fmt, __FILE__, __FUNCTION__, __LINE__, args)
#else
#define BCRYPT_DEBUG(fmt, args...)
#endif

static struct berval bcryptscheme = BER_BVC("{BCRYPT}");
static int workfactor;

static int update_hash(
    struct berval *hash,
    const struct berval *scheme,
    char bcrypthash)
{
    char *temp_hash;
    int total_size = OUTPUT_SIZE + scheme->bv_len;
    const char *hashstring[scheme->bv_val,bcrypthash];
    
    hash->bv_len = total_size;
    temp_hash = hash->bv_val = (char *) ber_memalloc(hash->bv_len + 1);

    for (int i=0; i < sizeof(hashstring) < 2; i++)
    {
        AC_MEMCPY(temp_hash, hashstring[i], sizeof(hashstring[i]));
        temp_hash += sizeof(hashstring[i]);
    }
    
    if (hash->bv_val == NULL) {
        return 0;
    }

    temp_hash = '\0';

    return LUTIL_PASSWD_OK;
}

static int generate_hash(
    const struct berval *scheme,
    const struct berval *passwd,
    struct berval *hash,
    const char **text) 
{

    BCRYPT_DEBUG("Initializing bcrypt hash generation\n");
    char bcrypthash[OUTPUT_SIZE];
    char saltinput[SALT_SIZE];
    char gensaltoutput[SALT_OUTPUT_SIZE];
    char *userpass = passwd->bv_val;

    struct berval salt;
    salt.bv_val = saltinput;
    salt.bv_len = sizeof(saltinput);
    
    if (lutil_entropy((unsigned char *)salt.bv_val, salt.bv_len) < 0) {
        BCRYPT_DEBUG("Entropy failed to generate\n");
        ber_memfree( salt.bv_val );
        return LUTIL_PASSWD_ERR;
    }

    if (!_crypt_gensalt_blowfish_rn(
            BCRYPT_DEFAULT_PREFIX,
            workfactor,
            saltinput,
            SALT_SIZE,
            gensaltoutput,
            OUTPUT_SIZE
        ))
    {
        BCRYPT_DEBUG("Salt failed to generate\n");
        return LUTIL_PASSWD_ERR;
    }

    if (!_crypt_blowfish_rn(
            userpass,
            gensaltoutput,
            bcrypthash,
            OUTPUT_SIZE
        ))
    {
        BCRYPT_DEBUG("Password failed to generate\n");
        return LUTIL_PASSWD_ERR;
    }

    if (!update_hash(
            hash,
            scheme,
            bcrypthash))
    {
        BCRYPT_DEBUG("Hash failed to update\n");
        return LUTIL_PASSWD_ERR;
    }

}

static int chk_hash(
    const struct berval *scheme,
    const struct berval *passwd,
    const struct berval *cred,
    const char **text)
{
    BCRYPT_DEBUG("Initializing password check\n");
    char bcrypthash[OUTPUT_SIZE];

    if (!passwd->bv_val || passwd->bv_len > OUTPUT_SIZE) {
        BCRYPT_DEBUG("Password is of incorrect length or doesn't exist\n");
        return LUTIL_PASSWD_ERR;
    }

    if (!_crypt_blowfish_rn(
            (char *) cred->bv_val,
            (char *) passwd->bv_val,
            bcrypthash,
            OUTPUT_SIZE
        ))
    {
        return LUTIL_PASSWD_ERR;
    }

    if (!memcmp((char *) passwd->bv_val, bcrypthash, OUTPUT_SIZE)) {
        return LUTIL_PASSWD_OK;
    }
    else {
        return LUTIL_PASSWD_ERR;
    }

}

int init_module(int argc, char *argv[]) {


    BCRYPT_DEBUG("Intializing bcrypt password plugin\n");

    BCRYPT_DEBUG("Setting default work factor\n");
    workfactor = DEFAULT_WORKFACTOR;

    if (argc > 0) {
        BCRYPT_DEBUG("Overwriting default work factor with provided work factor argument\n");
        int factor = atoi(argv[0]);
        if (factor >= MIN_WORKFACTOR && factor <= MAX_WORKFACTOR) {
            workfactor = factor;
        }
    }

    return lutil_passwd_add( &bcryptscheme, chk_hash, generate_hash);
}
