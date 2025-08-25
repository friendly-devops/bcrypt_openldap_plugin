
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
#define _DEBUG(args...) printf(args)
#else
#define _DEBUG(args...)
#endif

static struct berval bcryptscheme = BER_BVC("{BCRYPT}");
static int workfactor;

static int generate_hash(
    const struct berval *scheme,
    const struct berval *passwd,
    struct berval *hash,
    const char **text) 
{

    char bcrypthash[OUTPUT_SIZE];
    int total_size = OUTPUT_SIZE + scheme->bv_len;
    char *temp_hash;
    char saltinput[SALT_SIZE];
    char gensaltoutput[SALT_OUTPUT_SIZE];
    char *userpass = passwd->bv_val;

    struct berval salt;
    salt.bv_val = saltinput;
    salt.bv_len = sizeof(saltinput);
    
    if (lutil_entropy((unsigned char *)salt.bv_val, salt.bv_len) < 0) {
        _DEBUG("Error: Salt failed to generate");
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
        return LUTIL_PASSWD_ERR;
    }

    if (!_crypt_blowfish_rn(
            userpass,
            gensaltoutput,
            bcrypthash,
            OUTPUT_SIZE
        ))
    {
        return LUTIL_PASSWD_ERR;
    }

    hash->bv_len = total_size;
    temp_hash = hash->bv_val = (char *) ber_memalloc(hash->bv_len + 1);

    AC_MEMCPY(temp_hash, scheme->bv_val, scheme->bv_len);
    temp_hash += scheme->bv_len;

    AC_MEMCPY(temp_hash, bcrypthash, OUTPUT_SIZE);

    hash->bv_val[hash->bv_len] = '\0';

    return LUTIL_PASSWD_OK;

}

static int chk_hash(
    const struct berval *scheme,
    const struct berval *passwd,
    const struct berval *cred,
    const char **text)
{
    char bcrypthash[OUTPUT_SIZE];

    if (!passwd->bv_val || passwd->bv_len > OUTPUT_SIZE) {
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


    _DEBUG("Loading bcrypt password plugin\n")

    _DEBUG("Setting default work factor\n");
    workfactor = DEFAULT_WORKFACTOR;

    if (argc > 0) {
        _DEBUG("Overwriting default work factor with provided work factor argument\n")
        int factor = atoi(argv[0]);
        if (factor >= MIN_WORKFACTOR && factor <= MAX_WORKFACTOR) {
            workfactor = factor;
        }
    }

    return lutil_passwd_add( &bcryptscheme, chk_hash, generate_hash);
}
