
/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto.c
 * \brief Wrapper functions to present a consistent interface to
 * public-key and symmetric cryptography operations from OpenSSL.
 **/

#include "orconfig.h"

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
/* Windows defines this; so does OpenSSL 0.9.8h and later. We don't actually
 * use either definition. */
#undef OCSP_RESPONSE
#endif

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/conf.h>
#include <openssl/hmac.h>

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

#define CRYPTO_PRIVATE
#include "crypto.h"
#include "torlog.h"
#include "aes.h"
#include "tor_util.h"
#include "container.h"
#include "tor_compat.h"
#include "sandbox.h"

#if OPENSSL_VERSION_NUMBER < OPENSSL_V_SERIES(0,9,8)
#error "We require OpenSSL >= 0.9.8"
#endif

#ifdef ANDROID
/* Android's OpenSSL seems to have removed all of its Engine support. */
#define DISABLE_ENGINES
#endif

/** Longest recognized */
#define MAX_DNS_LABEL_SIZE 63

/** Macro: is k a valid RSA public or private key? */
#define PUBLIC_KEY_OK(k) ((k) && (k)->key && (k)->key->n)
/** Macro: is k a valid RSA private key? */
#define PRIVATE_KEY_OK(k) ((k) && (k)->key && (k)->key->p)

#ifdef TOR_IS_MULTITHREADED
/** A number of preallocated mutexes for use by OpenSSL. */
static tor_mutex_t **openssl_mutexes_ = NULL;
/** How many mutexes have we allocated for use by OpenSSL? */
static int n_openssl_mutexes_ = 0;
#endif

/** A public key, or a public/private key-pair. */
struct crypto_pk_t
{
  int refs; /**< reference count, so we don't have to copy keys */
  RSA *key; /**< The key itself */
};

/** Key and stream information for a stream cipher. */
struct crypto_cipher_t
{
  char key[CIPHER_KEY_LEN]; /**< The raw key. */
  char iv[CIPHER_IV_LEN]; /**< The initial IV. */
  aes_cnt_cipher_t *cipher; /**< The key in format usable for counter-mode AES
                             * encryption */
};

/** A structure to hold the first half (x, g^x) of a Diffie-Hellman handshake
 * while we're waiting for the second.*/
struct crypto_dh_t {
  DH *dh; /**< The openssl DH object */
};

static int setup_openssl_threading(void);
static int tor_check_dh_key(int severity, BIGNUM *bn);

/** Return the number of bytes added by padding method <b>padding</b>.
 */
static INLINE int
crypto_get_rsa_padding_overhead(int padding)
{
  switch (padding)
    {
    case RSA_PKCS1_OAEP_PADDING: return PKCS1_OAEP_PADDING_OVERHEAD;
    default: tor_assert(0); return -1;
    }
}

/** Given a padding method <b>padding</b>, return the correct OpenSSL constant.
 */
static INLINE int
crypto_get_rsa_padding(int padding)
{
  switch (padding)
    {
    case PK_PKCS1_OAEP_PADDING: return RSA_PKCS1_OAEP_PADDING;
    default: tor_assert(0); return -1;
    }
}

/** Boolean: has OpenSSL's crypto been initialized? */
static int crypto_global_initialized_ = 0;

/** Log all pending crypto errors at level <b>severity</b>.  Use
 * <b>doing</b> to describe our current activities.
 */
static void
crypto_log_errors(int severity, const char *doing)
{
  unsigned long err;
  const char *msg, *lib, *func;
  while ((err = ERR_get_error()) != 0) {
    msg = (const char*)ERR_reason_error_string(err);
    lib = (const char*)ERR_lib_error_string(err);
    func = (const char*)ERR_func_error_string(err);
    if (!msg) msg = "(null)";
    if (!lib) lib = "(null)";
    if (!func) func = "(null)";
    if (doing) {
      tor_log(severity, LD_CRYPTO, "crypto error while %s: %s (in %s:%s)",
              doing, msg, lib, func);
    } else {
      tor_log(severity, LD_CRYPTO, "crypto error: %s (in %s:%s)",
              msg, lib, func);
    }
  }
}

#ifndef DISABLE_ENGINES
/** Log any OpenSSL engines we're using at NOTICE. */
static void
log_engine(const char *fn, ENGINE *e)
{
  if (e) {
    const char *name, *id;
    name = ENGINE_get_name(e);
    id = ENGINE_get_id(e);
    log_notice(LD_CRYPTO, "Default OpenSSL engine for %s is %s [%s]",
               fn, name?name:"?", id?id:"?");
  } else {
    log_info(LD_CRYPTO, "Using default implementation for %s", fn);
  }
}
#endif

#ifndef DISABLE_ENGINES
/** Try to load an engine in a shared library via fully qualified path.
 */
static ENGINE *
try_load_engine(const char *path, const char *engine)
{
  ENGINE *e = ENGINE_by_id("dynamic");
  if (e) {
    if (!ENGINE_ctrl_cmd_string(e, "ID", engine, 0) ||
        !ENGINE_ctrl_cmd_string(e, "DIR_LOAD", "2", 0) ||
        !ENGINE_ctrl_cmd_string(e, "DIR_ADD", path, 0) ||
        !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
      ENGINE_free(e);
      e = NULL;
    }
  }
  return e;
}
#endif

/* Returns a trimmed and human-readable version of an openssl version string
* <b>raw_version</b>. They are usually in the form of 'OpenSSL 1.0.0b 10
* May 2012' and this will parse them into a form similar to '1.0.0b' */
static char *
parse_openssl_version_str(const char *raw_version)
{
  const char *end_of_version = NULL;
  /* The output should be something like "OpenSSL 1.0.0b 10 May 2012. Let's
     trim that down. */
  if (!strcmpstart(raw_version, "OpenSSL ")) {
    raw_version += strlen("OpenSSL ");
    end_of_version = strchr(raw_version, ' ');
  }

  if (end_of_version)
    return tor_strndup(raw_version,
                      end_of_version-raw_version);
  else
    return tor_strdup(raw_version);
}

static char *crypto_openssl_version_str = NULL;
/* Return a human-readable version of the run-time openssl version number. */
const char *
crypto_openssl_get_version_str(void)
{
  if (crypto_openssl_version_str == NULL) {
    const char *raw_version = SSLeay_version(SSLEAY_VERSION);
    crypto_openssl_version_str = parse_openssl_version_str(raw_version);
  }
  return crypto_openssl_version_str;
}

static char *crypto_openssl_header_version_str = NULL;
/* Return a human-readable version of the compile-time openssl version
* number. */
const char *
crypto_openssl_get_header_version_str(void)
{
  if (crypto_openssl_header_version_str == NULL) {
    crypto_openssl_header_version_str =
                        parse_openssl_version_str(OPENSSL_VERSION_TEXT);
  }
  return crypto_openssl_header_version_str;
}

/** Initialize the crypto library.  Return 0 on success, -1 on failure.
 */
int
crypto_global_init(int useAccel, const char *accelName, const char *accelDir)
{
  if (!crypto_global_initialized_) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    crypto_global_initialized_ = 1;
    setup_openssl_threading();

    if (SSLeay() == OPENSSL_VERSION_NUMBER &&
        !strcmp(SSLeay_version(SSLEAY_VERSION), OPENSSL_VERSION_TEXT)) {
      log_info(LD_CRYPTO, "OpenSSL version matches version from headers "
                 "(%lx: %s).", SSLeay(), SSLeay_version(SSLEAY_VERSION));
    } else {
      log_warn(LD_CRYPTO, "OpenSSL version from headers does not match the "
               "version we're running with. If you get weird crashes, that "
               "might be why. (Compiled with %lx: %s; running with %lx: %s).",
               (unsigned long)OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT,
               SSLeay(), SSLeay_version(SSLEAY_VERSION));
    }

    if (SSLeay() < OPENSSL_V_SERIES(1,0,0)) {
      log_notice(LD_CRYPTO,
                 "Your OpenSSL version seems to be %s. We recommend 1.0.0 "
                 "or later.",
                 crypto_openssl_get_version_str());
    }

    if (useAccel > 0) {
#ifdef DISABLE_ENGINES
      (void)accelName;
      (void)accelDir;
      log_warn(LD_CRYPTO, "No OpenSSL hardware acceleration support enabled.");
#else
      ENGINE *e = NULL;

      log_info(LD_CRYPTO, "Initializing OpenSSL engine support.");
      ENGINE_load_builtin_engines();
      ENGINE_register_all_complete();

      if (accelName) {
        if (accelDir) {
          log_info(LD_CRYPTO, "Trying to load dynamic OpenSSL engine \"%s\""
                   " via path \"%s\".", accelName, accelDir);
          e = try_load_engine(accelName, accelDir);
        } else {
          log_info(LD_CRYPTO, "Initializing dynamic OpenSSL engine \"%s\""
                   " acceleration support.", accelName);
          e = ENGINE_by_id(accelName);
        }
        if (!e) {
          log_warn(LD_CRYPTO, "Unable to load dynamic OpenSSL engine \"%s\".",
                   accelName);
        } else {
          log_info(LD_CRYPTO, "Loaded dynamic OpenSSL engine \"%s\".",
                   accelName);
        }
      }
      if (e) {
        log_info(LD_CRYPTO, "Loaded OpenSSL hardware acceleration engine,"
                 " setting default ciphers.");
        ENGINE_set_default(e, ENGINE_METHOD_ALL);
      }
      /* Log, if available, the intersection of the set of algorithms
         used by Tor and the set of algorithms available in the engine */
      log_engine("RSA", ENGINE_get_default_RSA());
      log_engine("DH", ENGINE_get_default_DH());
      log_engine("ECDH", ENGINE_get_default_ECDH());
      log_engine("ECDSA", ENGINE_get_default_ECDSA());
      log_engine("RAND", ENGINE_get_default_RAND());
      log_engine("RAND (which we will not use)", ENGINE_get_default_RAND());
      log_engine("SHA1", ENGINE_get_digest_engine(NID_sha1));
      log_engine("3DES-CBC", ENGINE_get_cipher_engine(NID_des_ede3_cbc));
      log_engine("AES-128-ECB", ENGINE_get_cipher_engine(NID_aes_128_ecb));
      log_engine("AES-128-CBC", ENGINE_get_cipher_engine(NID_aes_128_cbc));
#ifdef NID_aes_128_ctr
      log_engine("AES-128-CTR", ENGINE_get_cipher_engine(NID_aes_128_ctr));
#endif
#ifdef NID_aes_128_gcm
      log_engine("AES-128-GCM", ENGINE_get_cipher_engine(NID_aes_128_gcm));
#endif
      log_engine("AES-256-CBC", ENGINE_get_cipher_engine(NID_aes_256_cbc));
#ifdef NID_aes_256_gcm
      log_engine("AES-256-GCM", ENGINE_get_cipher_engine(NID_aes_256_gcm));
#endif

#endif
    } else {
      log_info(LD_CRYPTO, "NOT using OpenSSL engine support.");
    }

    if (RAND_get_rand_method() != RAND_SSLeay()) {
      log_notice(LD_CRYPTO, "It appears that one of our engines has provided "
                 "a replacement the OpenSSL RNG. Resetting it to the default "
                 "implementation.");
      RAND_set_rand_method(RAND_SSLeay());
    }

    evaluate_evp_for_aes(-1);
    evaluate_ctr_for_aes();

    return crypto_seed_rng(1);
  }
  return 0;
}

/** Free crypto resources held by this thread. */
void
crypto_thread_cleanup(void)
{
  ERR_remove_state(0);
}

/** used by tortls.c: wrap an RSA* in a crypto_pk_t. */
crypto_pk_t *
crypto_new_pk_from_rsa_(RSA *rsa)
{
  crypto_pk_t *env;
  tor_assert(rsa);
  env = tor_malloc(sizeof(crypto_pk_t));
  env->refs = 1;
  env->key = rsa;
  return env;
}

/** Helper, used by tor-checkkey.c and tor-gencert.c.  Return the RSA from a
 * crypto_pk_t. */
RSA *
crypto_pk_get_rsa_(crypto_pk_t *env)
{
  return env->key;
}

/** used by tortls.c: get an equivalent EVP_PKEY* for a crypto_pk_t.  Iff
 * private is set, include the private-key portion of the key. */
EVP_PKEY *
crypto_pk_get_evp_pkey_(crypto_pk_t *env, int private)
{
  RSA *key = NULL;
  EVP_PKEY *pkey = NULL;
  tor_assert(env->key);
  if (private) {
    if (!(key = RSAPrivateKey_dup(env->key)))
      goto error;
  } else {
    if (!(key = RSAPublicKey_dup(env->key)))
      goto error;
  }
  if (!(pkey = EVP_PKEY_new()))
    goto error;
  if (!(EVP_PKEY_assign_RSA(pkey, key)))
    goto error;
  return pkey;
 error:
  if (pkey)
    EVP_PKEY_free(pkey);
  if (key)
    RSA_free(key);
  return NULL;
}

/** Used by tortls.c: Get the DH* from a crypto_dh_t.
 */
DH *
crypto_dh_get_dh_(crypto_dh_t *dh)
{
  return dh->dh;
}

/** Allocate and return storage for a public key.  The key itself will not yet
 * be set.
 */
crypto_pk_t *
crypto_pk_new(void)
{
  RSA *rsa;

  rsa = RSA_new();
  tor_assert(rsa);
  return crypto_new_pk_from_rsa_(rsa);
}

/** Release a reference to an asymmetric key; when all the references
 * are released, free the key.
 */
void
crypto_pk_free(crypto_pk_t *env)
{
  if (!env)
    return;

  if (--env->refs > 0)
    return;
  tor_assert(env->refs == 0);

  if (env->key)
    RSA_free(env->key);

  tor_free(env);
}

/** Allocate and return a new symmetric cipher using the provided key and iv.
 * The key is CIPHER_KEY_LEN bytes; the IV is CIPHER_IV_LEN bytes.  If you
 * provide NULL in place of either one, it is generated at random.
 */
crypto_cipher_t *
crypto_cipher_new_with_iv(const char *key, const char *iv)
{
  crypto_cipher_t *env;

  env = tor_malloc_zero(sizeof(crypto_cipher_t));

  if (key == NULL)
    crypto_rand(env->key, CIPHER_KEY_LEN);
  else
    memcpy(env->key, key, CIPHER_KEY_LEN);
  if (iv == NULL)
    crypto_rand(env->iv, CIPHER_IV_LEN);
  else
    memcpy(env->iv, iv, CIPHER_IV_LEN);

  env->cipher = aes_new_cipher(env->key, env->iv);

  return env;
}

/** Return a new crypto_cipher_t with the provided <b>key</b> and an IV of all
 * zero bytes.  */
crypto_cipher_t *
crypto_cipher_new(const char *key)
{
  char zeroiv[CIPHER_IV_LEN];
  memset(zeroiv, 0, sizeof(zeroiv));
  return crypto_cipher_new_with_iv(key, zeroiv);
}

/** Free a symmetric cipher.
 */
void
crypto_cipher_free(crypto_cipher_t *env)
{
  if (!env)
    return;

  tor_assert(env->cipher);
  aes_cipher_free(env->cipher);
  memwipe(env, 0, sizeof(crypto_cipher_t));
  tor_free(env);
}

/* public key crypto */

/** Generate a <b>bits</b>-bit new public/private keypair in <b>env</b>.
 * Return 0 on success, -1 on failure.
 */
int
crypto_pk_generate_key_with_bits(crypto_pk_t *env, int bits)
{
  tor_assert(env);

  if (env->key)
    RSA_free(env->key);

  {
    BIGNUM *e = BN_new();
    RSA *r = NULL;
    if (!e)
      goto done;
    if (! BN_set_word(e, 65537))
      goto done;
    r = RSA_new();
    if (!r)
      goto done;
    if (RSA_generate_key_ex(r, bits, e, NULL) == -1)
      goto done;

    env->key = r;
    r = NULL;
  done:
    if (e)
      BN_clear_free(e);
    if (r)
      RSA_free(r);
  }

  if (!env->key) {
    crypto_log_errors(LOG_WARN, "generating RSA key");
    return -1;
  }

  return 0;
}

/** Read a PEM-encoded private key from the <b>len</b>-byte string <b>s</b>
 * into <b>env</b>.  Return 0 on success, -1 on failure.  If len is -1,
 * the string is nul-terminated.
 */
/* Used here, and used for testing. */
int
crypto_pk_read_private_key_from_string(crypto_pk_t *env,
                                       const char *s, ssize_t len)
{
  BIO *b;

  tor_assert(env);
  tor_assert(s);
  tor_assert(len < INT_MAX && len < SSIZE_T_CEILING);

  /* Create a read-only memory BIO, backed by the string 's' */
  b = BIO_new_mem_buf((char*)s, (int)len);
  if (!b)
    return -1;

  if (env->key)
    RSA_free(env->key);

  env->key = PEM_read_bio_RSAPrivateKey(b,NULL,NULL,NULL);

  BIO_free(b);

  if (!env->key) {
    crypto_log_errors(LOG_WARN, "Error parsing private key");
    return -1;
  }
  return 0;
}

/** Read a PEM-encoded private key from the file named by
 * <b>keyfile</b> into <b>env</b>.  Return 0 on success, -1 on failure.
 */
int
crypto_pk_read_private_key_from_filename(crypto_pk_t *env,
                                         const char *keyfile)
{
  char *contents;
  int r;

  /* Read the file into a string. */
  contents = read_file_to_str(keyfile, 0, NULL);
  if (!contents) {
    log_warn(LD_CRYPTO, "Error reading private key from \"%s\"", keyfile);
    return -1;
  }

  /* Try to parse it. */
  r = crypto_pk_read_private_key_from_string(env, contents, -1);
  memwipe(contents, 0, strlen(contents));
  tor_free(contents);
  if (r)
    return -1; /* read_private_key_from_string already warned, so we don't.*/

  /* Make sure it's valid. */
  if (crypto_pk_check_key(env) <= 0)
    return -1;

  return 0;
}

/** Helper function to implement crypto_pk_write_*_key_to_string. */
static int
crypto_pk_write_key_to_string_impl(crypto_pk_t *env, char **dest,
                                   size_t *len, int is_public)
{
  BUF_MEM *buf;
  BIO *b;
  int r;

  tor_assert(env);
  tor_assert(env->key);
  tor_assert(dest);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */
  if (!b)
    return -1;

  /* Now you can treat b as if it were a file.  Just use the
   * PEM_*_bio_* functions instead of the non-bio variants.
   */
  if (is_public)
    r = PEM_write_bio_RSAPublicKey(b, env->key);
  else
    r = PEM_write_bio_RSAPrivateKey(b, env->key, NULL,NULL,0,NULL,NULL);

  if (!r) {
    crypto_log_errors(LOG_WARN, "writing RSA key to string");
    BIO_free(b);
    return -1;
  }

  BIO_get_mem_ptr(b, &buf);
  (void)BIO_set_close(b, BIO_NOCLOSE); /* so BIO_free doesn't free buf */
  BIO_free(b);

  *dest = tor_malloc(buf->length+1);
  memcpy(*dest, buf->data, buf->length);
  (*dest)[buf->length] = 0; /* nul terminate it */
  *len = buf->length;
  BUF_MEM_free(buf);

  return 0;
}

/** PEM-encode the public key portion of <b>env</b> and write it to a
 * newly allocated string.  On success, set *<b>dest</b> to the new
 * string, *<b>len</b> to the string's length, and return 0.  On
 * failure, return -1.
 */
int
crypto_pk_write_public_key_to_string(crypto_pk_t *env, char **dest,
                                     size_t *len)
{
  return crypto_pk_write_key_to_string_impl(env, dest, len, 1);
}

/** PEM-encode the private key portion of <b>env</b> and write it to a
 * newly allocated string.  On success, set *<b>dest</b> to the new
 * string, *<b>len</b> to the string's length, and return 0.  On
 * failure, return -1.
 */
int
crypto_pk_write_private_key_to_string(crypto_pk_t *env, char **dest,
                                     size_t *len)
{
  return crypto_pk_write_key_to_string_impl(env, dest, len, 0);
}

/** Read a PEM-encoded public key from the first <b>len</b> characters of
 * <b>src</b>, and store the result in <b>env</b>.  Return 0 on success, -1 on
 * failure.
 */
int
crypto_pk_read_public_key_from_string(crypto_pk_t *env, const char *src,
                                      size_t len)
{
  BIO *b;

  tor_assert(env);
  tor_assert(src);
  tor_assert(len<INT_MAX);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */
  if (!b)
    return -1;

  BIO_write(b, src, (int)len);

  if (env->key)
    RSA_free(env->key);
  env->key = PEM_read_bio_RSAPublicKey(b, NULL, NULL, NULL);
  BIO_free(b);
  if (!env->key) {
    crypto_log_errors(LOG_WARN, "reading public key from string");
    return -1;
  }

  return 0;
}

/** Write the private key from <b>env</b> into the file named by <b>fname</b>,
 * PEM-encoded.  Return 0 on success, -1 on failure.
 */
int
crypto_pk_write_private_key_to_filename(crypto_pk_t *env,
                                        const char *fname)
{
  BIO *bio;
  char *cp;
  long len;
  char *s;
  int r;

  tor_assert(PRIVATE_KEY_OK(env));

  if (!(bio = BIO_new(BIO_s_mem())))
    return -1;
  if (PEM_write_bio_RSAPrivateKey(bio, env->key, NULL,NULL,0,NULL,NULL)
      == 0) {
    crypto_log_errors(LOG_WARN, "writing private key");
    BIO_free(bio);
    return -1;
  }
  len = BIO_get_mem_data(bio, &cp);
  tor_assert(len >= 0);
  s = tor_malloc(len+1);
  memcpy(s, cp, len);
  s[len]='\0';
  r = write_str_to_file(fname, s, 0);
  BIO_free(bio);
  memwipe(s, 0, strlen(s));
  tor_free(s);
  return r;
}

/** Return true iff <b>env</b> has a valid key.
 */
int
crypto_pk_check_key(crypto_pk_t *env)
{
  int r;
  tor_assert(env);

  r = RSA_check_key(env->key);
  if (r <= 0)
    crypto_log_errors(LOG_WARN,"checking RSA key");
  return r;
}

/** Return true iff <b>key</b> contains the private-key portion of the RSA
 * key. */
int
crypto_pk_key_is_private(const crypto_pk_t *key)
{
  tor_assert(key);
  return PRIVATE_KEY_OK(key);
}

/** Return true iff <b>env</b> contains a public key whose public exponent
 * equals 65537.
 */
int
crypto_pk_public_exponent_ok(crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  return BN_is_word(env->key->e, 65537);
}

/** Compare the public-key components of a and b.  Return less than 0
 * if a\<b, 0 if a==b, and greater than 0 if a\>b.  A NULL key is
 * considered to be less than all non-NULL keys, and equal to itself.
 *
 * Note that this may leak information about the keys through timing.
 */
int
crypto_pk_cmp_keys(crypto_pk_t *a, crypto_pk_t *b)
{
  int result;
  char a_is_non_null = (a != NULL) && (a->key != NULL);
  char b_is_non_null = (b != NULL) && (b->key != NULL);
  char an_argument_is_null = !a_is_non_null | !b_is_non_null;

  result = tor_memcmp(&a_is_non_null, &b_is_non_null, sizeof(a_is_non_null));
  if (an_argument_is_null)
    return result;

  tor_assert(PUBLIC_KEY_OK(a));
  tor_assert(PUBLIC_KEY_OK(b));
  result = BN_cmp((a->key)->n, (b->key)->n);
  if (result)
    return result;
  return BN_cmp((a->key)->e, (b->key)->e);
}

/** Compare the public-key components of a and b.  Return non-zero iff
 * a==b.  A NULL key is considered to be distinct from all non-NULL
 * keys, and equal to itself.
 *
 *  Note that this may leak information about the keys through timing.
 */
int
crypto_pk_eq_keys(crypto_pk_t *a, crypto_pk_t *b)
{
  return (crypto_pk_cmp_keys(a, b) == 0);
}

/** Return the size of the public key modulus in <b>env</b>, in bytes. */
size_t
crypto_pk_keysize(crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  return (size_t) RSA_size(env->key);
}

/** Return the size of the public key modulus of <b>env</b>, in bits. */
int
crypto_pk_num_bits(crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);
  tor_assert(env->key->n);

  return BN_num_bits(env->key->n);
}

/** Increase the reference count of <b>env</b>, and return it.
 */
crypto_pk_t *
crypto_pk_dup_key(crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  env->refs++;
  return env;
}

/** Make a real honest-to-goodness copy of <b>env</b>, and return it. */
crypto_pk_t *
crypto_pk_copy_full(crypto_pk_t *env)
{
  RSA *new_key;
  int privatekey = 0;
  tor_assert(env);
  tor_assert(env->key);

  if (PRIVATE_KEY_OK(env)) {
    new_key = RSAPrivateKey_dup(env->key);
    privatekey = 1;
  } else {
    new_key = RSAPublicKey_dup(env->key);
  }
  if (!new_key) {
    log_err(LD_CRYPTO, "Unable to duplicate a %s key: openssl failed.",
            privatekey?"private":"public");
    crypto_log_errors(LOG_ERR,
                      privatekey ? "Duplicating a private key" :
                      "Duplicating a public key");
    tor_fragile_assert();
    return NULL;
  }

  return crypto_new_pk_from_rsa_(new_key);
}

/** Encrypt <b>fromlen</b> bytes from <b>from</b> with the public key
 * in <b>env</b>, using the padding method <b>padding</b>.  On success,
 * write the result to <b>to</b>, and return the number of bytes
 * written.  On failure, return -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_public_encrypt(crypto_pk_t *env, char *to, size_t tolen,
                         const char *from, size_t fromlen, int padding)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen<INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));

  r = RSA_public_encrypt((int)fromlen,
                         (unsigned char*)from, (unsigned char*)to,
                         env->key, crypto_get_rsa_padding(padding));
  if (r<0) {
    crypto_log_errors(LOG_WARN, "performing RSA encryption");
    return -1;
  }
  return r;
}

/** Decrypt <b>fromlen</b> bytes from <b>from</b> with the private key
 * in <b>env</b>, using the padding method <b>padding</b>.  On success,
 * write the result to <b>to</b>, and return the number of bytes
 * written.  On failure, return -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_private_decrypt(crypto_pk_t *env, char *to,
                          size_t tolen,
                          const char *from, size_t fromlen,
                          int padding, int warnOnFailure)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(env->key);
  tor_assert(fromlen<INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));
  if (!env->key->p)
    /* Not a private key */
    return -1;

  r = RSA_private_decrypt((int)fromlen,
                          (unsigned char*)from, (unsigned char*)to,
                          env->key, crypto_get_rsa_padding(padding));

  if (r<0) {
    crypto_log_errors(warnOnFailure?LOG_WARN:LOG_DEBUG,
                      "performing RSA decryption");
    return -1;
  }
  return r;
}

/** Check the signature in <b>from</b> (<b>fromlen</b> bytes long) with the
 * public key in <b>env</b>, using PKCS1 padding.  On success, write the
 * signed data to <b>to</b>, and return the number of bytes written.
 * On failure, return -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_public_checksig(crypto_pk_t *env, char *to,
                          size_t tolen,
                          const char *from, size_t fromlen)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));
  r = RSA_public_decrypt((int)fromlen,
                         (unsigned char*)from, (unsigned char*)to,
                         env->key, RSA_PKCS1_PADDING);

  if (r<0) {
    crypto_log_errors(LOG_WARN, "checking RSA signature");
    return -1;
  }
  return r;
}

/** Check a siglen-byte long signature at <b>sig</b> against
 * <b>datalen</b> bytes of data at <b>data</b>, using the public key
 * in <b>env</b>. Return 0 if <b>sig</b> is a correct signature for
 * SHA1(data).  Else return -1.
 */
int
crypto_pk_public_checksig_digest(crypto_pk_t *env, const char *data,
                               size_t datalen, const char *sig, size_t siglen)
{
  char digest[DIGEST_LEN];
  char *buf;
  size_t buflen;
  int r;

  tor_assert(env);
  tor_assert(data);
  tor_assert(sig);
  tor_assert(datalen < SIZE_T_CEILING);
  tor_assert(siglen < SIZE_T_CEILING);

  if (crypto_digest(digest,data,datalen)<0) {
    log_warn(LD_BUG, "couldn't compute digest");
    return -1;
  }
  buflen = crypto_pk_keysize(env);
  buf = tor_malloc(buflen);
  r = crypto_pk_public_checksig(env,buf,buflen,sig,siglen);
  if (r != DIGEST_LEN) {
    log_warn(LD_CRYPTO, "Invalid signature");
    tor_free(buf);
    return -1;
  }
  if (tor_memneq(buf, digest, DIGEST_LEN)) {
    log_warn(LD_CRYPTO, "Signature mismatched with digest.");
    tor_free(buf);
    return -1;
  }
  tor_free(buf);

  return 0;
}

/** Sign <b>fromlen</b> bytes of data from <b>from</b> with the private key in
 * <b>env</b>, using PKCS1 padding.  On success, write the signature to
 * <b>to</b>, and return the number of bytes written.  On failure, return
 * -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_private_sign(crypto_pk_t *env, char *to, size_t tolen,
                       const char *from, size_t fromlen)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));
  if (!env->key->p)
    /* Not a private key */
    return -1;

  r = RSA_private_encrypt((int)fromlen,
                          (unsigned char*)from, (unsigned char*)to,
                          env->key, RSA_PKCS1_PADDING);
  if (r<0) {
    crypto_log_errors(LOG_WARN, "generating RSA signature");
    return -1;
  }
  return r;
}

/** Compute a SHA1 digest of <b>fromlen</b> bytes of data stored at
 * <b>from</b>; sign the data with the private key in <b>env</b>, and
 * store it in <b>to</b>.  Return the number of bytes written on
 * success, and -1 on failure.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_private_sign_digest(crypto_pk_t *env, char *to, size_t tolen,
                              const char *from, size_t fromlen)
{
  int r;
  char digest[DIGEST_LEN];
  if (crypto_digest(digest,from,fromlen)<0)
    return -1;
  r = crypto_pk_private_sign(env,to,tolen,digest,DIGEST_LEN);
  memwipe(digest, 0, sizeof(digest));
  return r;
}

/** Perform a hybrid (public/secret) encryption on <b>fromlen</b>
 * bytes of data from <b>from</b>, with padding type 'padding',
 * storing the results on <b>to</b>.
 *
 * Returns the number of bytes written on success, -1 on failure.
 *
 * The encrypted data consists of:
 *   - The source data, padded and encrypted with the public key, if the
 *     padded source data is no longer than the public key, and <b>force</b>
 *     is false, OR
 *   - The beginning of the source data prefixed with a 16-byte symmetric key,
 *     padded and encrypted with the public key; followed by the rest of
 *     the source data encrypted in AES-CTR mode with the symmetric key.
 */
int
crypto_pk_public_hybrid_encrypt(crypto_pk_t *env,
                                char *to, size_t tolen,
                                const char *from,
                                size_t fromlen,
                                int padding, int force)
{
  int overhead, outlen, r;
  size_t pkeylen, symlen;
  crypto_cipher_t *cipher = NULL;
  char *buf = NULL;

  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < SIZE_T_CEILING);

  overhead = crypto_get_rsa_padding_overhead(crypto_get_rsa_padding(padding));
  pkeylen = crypto_pk_keysize(env);

  if (!force && fromlen+overhead <= pkeylen) {
    /* It all fits in a single encrypt. */
    return crypto_pk_public_encrypt(env,to,
                                    tolen,
                                    from,fromlen,padding);
  }
  tor_assert(tolen >= fromlen + overhead + CIPHER_KEY_LEN);
  tor_assert(tolen >= pkeylen);

  cipher = crypto_cipher_new(NULL); /* generate a new key. */

  buf = tor_malloc(pkeylen+1);
  memcpy(buf, cipher->key, CIPHER_KEY_LEN);
  memcpy(buf+CIPHER_KEY_LEN, from, pkeylen-overhead-CIPHER_KEY_LEN);

  /* Length of symmetrically encrypted data. */
  symlen = fromlen-(pkeylen-overhead-CIPHER_KEY_LEN);

  outlen = crypto_pk_public_encrypt(env,to,tolen,buf,pkeylen-overhead,padding);
  if (outlen!=(int)pkeylen) {
    goto err;
  }
  r = crypto_cipher_encrypt(cipher, to+outlen,
                            from+pkeylen-overhead-CIPHER_KEY_LEN, symlen);

  if (r<0) goto err;
  memwipe(buf, 0, pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  tor_assert(outlen+symlen < INT_MAX);
  return (int)(outlen + symlen);
 err:

  memwipe(buf, 0, pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  return -1;
}

/** Invert crypto_pk_public_hybrid_encrypt. */
int
crypto_pk_private_hybrid_decrypt(crypto_pk_t *env,
                                 char *to,
                                 size_t tolen,
                                 const char *from,
                                 size_t fromlen,
                                 int padding, int warnOnFailure)
{
  int outlen, r;
  size_t pkeylen;
  crypto_cipher_t *cipher = NULL;
  char *buf = NULL;

  tor_assert(fromlen < SIZE_T_CEILING);
  pkeylen = crypto_pk_keysize(env);

  if (fromlen <= pkeylen) {
    return crypto_pk_private_decrypt(env,to,tolen,from,fromlen,padding,
                                     warnOnFailure);
  }

  buf = tor_malloc(pkeylen);
  outlen = crypto_pk_private_decrypt(env,buf,pkeylen,from,pkeylen,padding,
                                     warnOnFailure);
  if (outlen<0) {
    log_fn(warnOnFailure?LOG_WARN:LOG_DEBUG, LD_CRYPTO,
           "Error decrypting public-key data");
    goto err;
  }
  if (outlen < CIPHER_KEY_LEN) {
    log_fn(warnOnFailure?LOG_WARN:LOG_INFO, LD_CRYPTO,
           "No room for a symmetric key");
    goto err;
  }
  cipher = crypto_cipher_new(buf);
  if (!cipher) {
    goto err;
  }
  memcpy(to,buf+CIPHER_KEY_LEN,outlen-CIPHER_KEY_LEN);
  outlen -= CIPHER_KEY_LEN;
  tor_assert(tolen - outlen >= fromlen - pkeylen);
  r = crypto_cipher_decrypt(cipher, to+outlen, from+pkeylen, fromlen-pkeylen);
  if (r<0)
    goto err;
  memwipe(buf,0,pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  tor_assert(outlen + fromlen < INT_MAX);
  return (int)(outlen + (fromlen-pkeylen));
 err:
  memwipe(buf,0,pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  return -1;
}

/** ASN.1-encode the public portion of <b>pk</b> into <b>dest</b>.
 * Return -1 on error, or the number of characters used on success.
 */
int
crypto_pk_asn1_encode(crypto_pk_t *pk, char *dest, size_t dest_len)
{
  int len;
  unsigned char *buf = NULL;

  len = i2d_RSAPublicKey(pk->key, &buf);
  if (len < 0 || buf == NULL)
    return -1;

  if ((size_t)len > dest_len || dest_len > SIZE_T_CEILING) {
    OPENSSL_free(buf);
    return -1;
  }
  /* We don't encode directly into 'dest', because that would be illegal
   * type-punning.  (C99 is smarter than me, C99 is smarter than me...)
   */
  memcpy(dest,buf,len);
  OPENSSL_free(buf);
  return len;
}

/** Decode an ASN.1-encoded public key from <b>str</b>; return the result on
 * success and NULL on failure.
 */
crypto_pk_t *
crypto_pk_asn1_decode(const char *str, size_t len)
{
  RSA *rsa;
  unsigned char *buf;
  const unsigned char *cp;
  cp = buf = tor_malloc(len);
  memcpy(buf,str,len);
  rsa = d2i_RSAPublicKey(NULL, &cp, len);
  tor_free(buf);
  if (!rsa) {
    crypto_log_errors(LOG_WARN,"decoding public key");
    return NULL;
  }
  return crypto_new_pk_from_rsa_(rsa);
}

/** Given a private or public key <b>pk</b>, put a SHA1 hash of the
 * public key into <b>digest_out</b> (must have DIGEST_LEN bytes of space).
 * Return 0 on success, -1 on failure.
 */
int
crypto_pk_get_digest(crypto_pk_t *pk, char *digest_out)
{
  unsigned char *buf = NULL;
  int len;

  len = i2d_RSAPublicKey(pk->key, &buf);
  if (len < 0 || buf == NULL)
    return -1;
  if (crypto_digest(digest_out, (char*)buf, len) < 0) {
    OPENSSL_free(buf);
    return -1;
  }
  OPENSSL_free(buf);
  return 0;
}

/** Compute all digests of the DER encoding of <b>pk</b>, and store them
 * in <b>digests_out</b>.  Return 0 on success, -1 on failure. */
int
crypto_pk_get_all_digests(crypto_pk_t *pk, digests_t *digests_out)
{
  unsigned char *buf = NULL;
  int len;

  len = i2d_RSAPublicKey(pk->key, &buf);
  if (len < 0 || buf == NULL)
    return -1;
  if (crypto_digest_all(digests_out, (char*)buf, len) < 0) {
    OPENSSL_free(buf);
    return -1;
  }
  OPENSSL_free(buf);
  return 0;
}

/** Copy <b>in</b> to the <b>outlen</b>-byte buffer <b>out</b>, adding spaces
 * every four spaces. */
void
crypto_add_spaces_to_fp(char *out, size_t outlen, const char *in)
{
  int n = 0;
  char *end = out+outlen;
  tor_assert(outlen < SIZE_T_CEILING);

  while (*in && out<end) {
    *out++ = *in++;
    if (++n == 4 && *in && out<end) {
      n = 0;
      *out++ = ' ';
    }
  }
  tor_assert(out<end);
  *out = '\0';
}

/** Given a private or public key <b>pk</b>, put a fingerprint of the
 * public key into <b>fp_out</b> (must have at least FINGERPRINT_LEN+1 bytes of
 * space).  Return 0 on success, -1 on failure.
 *
 * Fingerprints are computed as the SHA1 digest of the ASN.1 encoding
 * of the public key, converted to hexadecimal, in upper case, with a
 * space after every four digits.
 *
 * If <b>add_space</b> is false, omit the spaces.
 */
int
crypto_pk_get_fingerprint(crypto_pk_t *pk, char *fp_out, int add_space)
{
  char digest[DIGEST_LEN];
  char hexdigest[HEX_DIGEST_LEN+1];
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  base16_encode(hexdigest,sizeof(hexdigest),digest,DIGEST_LEN);
  if (add_space) {
    crypto_add_spaces_to_fp(fp_out, FINGERPRINT_LEN+1, hexdigest);
  } else {
    strncpy(fp_out, hexdigest, HEX_DIGEST_LEN+1);
  }
  return 0;
}

/* symmetric crypto */

/** Return a pointer to the key set for the cipher in <b>env</b>.
 */
const char *
crypto_cipher_get_key(crypto_cipher_t *env)
{
  return env->key;
}

/** Encrypt <b>fromlen</b> bytes from <b>from</b> using the cipher
 * <b>env</b>; on success, store the result to <b>to</b> and return 0.
 * On failure, return -1.
 */
int
crypto_cipher_encrypt(crypto_cipher_t *env, char *to,
                      const char *from, size_t fromlen)
{
  tor_assert(env);
  tor_assert(env->cipher);
  tor_assert(from);
  tor_assert(fromlen);
  tor_assert(to);
  tor_assert(fromlen < SIZE_T_CEILING);

  aes_crypt(env->cipher, from, fromlen, to);
  return 0;
}

/** Decrypt <b>fromlen</b> bytes from <b>from</b> using the cipher
 * <b>env</b>; on success, store the result to <b>to</b> and return 0.
 * On failure, return -1.
 */
int
crypto_cipher_decrypt(crypto_cipher_t *env, char *to,
                      const char *from, size_t fromlen)
{
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < SIZE_T_CEILING);

  aes_crypt(env->cipher, from, fromlen, to);
  return 0;
}

/** Encrypt <b>len</b> bytes on <b>from</b> using the cipher in <b>env</b>;
 * on success, return 0.  On failure, return -1.
 */
int
crypto_cipher_crypt_inplace(crypto_cipher_t *env, char *buf, size_t len)
{
  tor_assert(len < SIZE_T_CEILING);
  aes_crypt_inplace(env->cipher, buf, len);
  return 0;
}

/** Encrypt <b>fromlen</b> bytes (at least 1) from <b>from</b> with the key in
 * <b>key</b> to the buffer in <b>to</b> of length
 * <b>tolen</b>. <b>tolen</b> must be at least <b>fromlen</b> plus
 * CIPHER_IV_LEN bytes for the initialization vector. On success, return the
 * number of bytes written, on failure, return -1.
 */
int
crypto_cipher_encrypt_with_iv(const char *key,
                              char *to, size_t tolen,
                              const char *from, size_t fromlen)
{
  crypto_cipher_t *cipher;
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);

  if (fromlen < 1)
    return -1;
  if (tolen < fromlen + CIPHER_IV_LEN)
    return -1;

  cipher = crypto_cipher_new_with_iv(key, NULL);

  memcpy(to, cipher->iv, CIPHER_IV_LEN);
  crypto_cipher_encrypt(cipher, to+CIPHER_IV_LEN, from, fromlen);
  crypto_cipher_free(cipher);
  return (int)(fromlen + CIPHER_IV_LEN);
}

/** Decrypt <b>fromlen</b> bytes (at least 1+CIPHER_IV_LEN) from <b>from</b>
 * with the key in <b>key</b> to the buffer in <b>to</b> of length
 * <b>tolen</b>. <b>tolen</b> must be at least <b>fromlen</b> minus
 * CIPHER_IV_LEN bytes for the initialization vector. On success, return the
 * number of bytes written, on failure, return -1.
 */
int
crypto_cipher_decrypt_with_iv(const char *key,
                              char *to, size_t tolen,
                              const char *from, size_t fromlen)
{
  crypto_cipher_t *cipher;
  tor_assert(key);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);

  if (fromlen <= CIPHER_IV_LEN)
    return -1;
  if (tolen < fromlen - CIPHER_IV_LEN)
    return -1;

  cipher = crypto_cipher_new_with_iv(key, from);

  crypto_cipher_encrypt(cipher, to, from+CIPHER_IV_LEN, fromlen-CIPHER_IV_LEN);
  crypto_cipher_free(cipher);
  return (int)(fromlen - CIPHER_IV_LEN);
}

/* SHA-1 */

/** Compute the SHA1 digest of the <b>len</b> bytes on data stored in
 * <b>m</b>.  Write the DIGEST_LEN byte result into <b>digest</b>.
 * Return 0 on success, -1 on failure.
 */
int
crypto_digest(char *digest, const char *m, size_t len)
{
  tor_assert(m);
  tor_assert(digest);
  return (SHA1((const unsigned char*)m,len,(unsigned char*)digest) == NULL);
}

/** Compute a 256-bit digest of <b>len</b> bytes in data stored in <b>m</b>,
 * using the algorithm <b>algorithm</b>.  Write the DIGEST_LEN256-byte result
 * into <b>digest</b>.  Return 0 on success, -1 on failure. */
int
crypto_digest256(char *digest, const char *m, size_t len,
                 digest_algorithm_t algorithm)
{
  tor_assert(m);
  tor_assert(digest);
  tor_assert(algorithm == DIGEST_SHA256);
  return (SHA256((const unsigned char*)m,len,(unsigned char*)digest) == NULL);
}

/** Set the digests_t in <b>ds_out</b> to contain every digest on the
 * <b>len</b> bytes in <b>m</b> that we know how to compute.  Return 0 on
 * success, -1 on failure. */
int
crypto_digest_all(digests_t *ds_out, const char *m, size_t len)
{
  int i;
  tor_assert(ds_out);
  memset(ds_out, 0, sizeof(*ds_out));
  if (crypto_digest(ds_out->d[DIGEST_SHA1], m, len) < 0)
    return -1;
  for (i = DIGEST_SHA256; i < N_DIGEST_ALGORITHMS; ++i) {
    if (crypto_digest256(ds_out->d[i], m, len, i) < 0)
      return -1;
  }
  return 0;
}

/** Return the name of an algorithm, as used in directory documents. */
const char *
crypto_digest_algorithm_get_name(digest_algorithm_t alg)
{
  switch (alg) {
    case DIGEST_SHA1:
      return "sha1";
    case DIGEST_SHA256:
      return "sha256";
    default:
      tor_fragile_assert();
      return "??unknown_digest??";
  }
}

/** Given the name of a digest algorithm, return its integer value, or -1 if
 * the name is not recognized. */
int
crypto_digest_algorithm_parse_name(const char *name)
{
  if (!strcmp(name, "sha1"))
    return DIGEST_SHA1;
  else if (!strcmp(name, "sha256"))