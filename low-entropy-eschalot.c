/* low-entropy-eschalot - generates .onion names with repeating characters  */
/* a fork of eschalot (https://github.com/ReclaimYourPrivacy/eschalot) */

/*
 * Copyright (c) 2017 Giedrius Jonikas
 * Copyright (c) 2013 Unperson Hiro <blacksunhq56imku.onion>
 * Copyright (c) 2007 Orum			<hangman5naigg7rr.onion>
 * Copyright (c) 2006 Cowboy Bebop	<torlandypjxiligx.onion>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */



#ifdef __APPLE__
  #include <libkern/OSByteOrder.h>

  #define htobe16(x) OSSwapHostToBigInt16(x)
  #define htole16(x) OSSwapHostToLittleInt16(x)
  #define be16toh(x) OSSwapBigToHostInt16(x)
  #define le16toh(x) OSSwapLittleToHostInt16(x)

  #define htobe32(x) OSSwapHostToBigInt32(x)
  #define htole32(x) OSSwapHostToLittleInt32(x)
  #define be32toh(x) OSSwapBigToHostInt32(x)
  #define le32toh(x) OSSwapLittleToHostInt32(x)

  #define htobe64(x) OSSwapHostToBigInt64(x)
  #define htole64(x) OSSwapHostToLittleInt64(x)
  #define be64toh(x) OSSwapBigToHostInt64(x)
  #define le64toh(x) OSSwapLittleToHostInt64(x)
#endif	/* __APPLE__ */

#if defined(__linux__) || defined(__CYGWIN__)
# define _GNU_SOURCE
# include <endian.h>
#endif

#ifdef __FreeBSD__
# include <sys/endian.h>
#endif

#include <sys/types.h>

#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
/* #include <regex.h> */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#define OPENSSL_VERSION_1_1 0x10100000L
#define OPENSSL_VERSION_0_9_0_8 0x0090800FL

/* Define NEED_HTOBE32 if htobe32() is not available on your platform. */
/* #define NEED_HTOBE32 */
#if BYTE_ORDER == LITTLE_ENDIAN
# ifdef NEED_HTOBE32
#  define HTOBE32(x)	(((uint32_t)(x) & 0xffu)	<< 24 |	\
			 ((uint32_t)(x) & 0xff00u)	<<	8 |	\
			 ((uint32_t)(x) & 0xff0000u)	>>	8 |	\
			 ((uint32_t)(x) & 0xff000000u)	>> 24)
# else
#  define HTOBE32(x)	htobe32(x)
# endif
#else
# define HTOBE32(x)	(x)
#endif

#define THREADS	1			/* number of threads */
#define SHA_REL_CTX_LEN	10 * sizeof(SHA_LONG)	/* 40 bytes */
#define RSA_KEYS_BITLEN	1024			/* RSA key length to use */
#define SIZE_OF_E	4			/* Limit public exponent to 4 bytes */
#define RSA_E_START	0xFFFFFFu + 2		/* Min e */
#define RSA_E_LIMIT	0x7FFFFFFFu		/* Max e */
#define ONION_LENP1	17			/* Onion name length plus 1 */
#define MAX_WORDS	0xFFFFFFFFu		/* Maximum words to read from file */
#define BASE32_ALPHABET	"abcdefghijklmnopqrstuvwxyz234567"

extern char	*__progname;

/* Error and debug functions */
static void		usage(void);
static void		error(char *, ...);
static void		normal(char *, ...);
/* User IO functions */
static void		printresult(RSA *, uint8_t *);

static _Bool		validkey(RSA *);
static void		base32_enc(uint8_t *, uint8_t *);
static void		onion_enc(uint8_t *, RSA *);
/* Main thread routine */
static void		*worker(void *);

static unsigned int repeating_chains(char* str);
static unsigned int unique_characters(char* str);

unsigned int min_unique_characters = 16;
unsigned int min_repeating_chains = 16;

pthread_mutex_t printresult_lock;

int
main(int argc, char *argv[])
{
	if(argc < 3) {
		usage();
	}
	min_unique_characters = strtol(argv[1], NULL, 10);
	min_repeating_chains = strtol(argv[2], NULL, 10);

	pthread_t	babies[THREADS];
	uint64_t	count[THREADS];
	unsigned int	i = 0;

	pthread_mutex_init(&printresult_lock, NULL);


	/* Start our threads */
	for (i = 1; i <= THREADS; i++) {
		count[i] = 0;
		if (pthread_create(&babies[i], NULL, worker, (void *)&count[i]) != 0)
			error("Failed to start thread!\n");
		normal("Thread #%d started.\n", i);
	}

	/* Wait for all the threads to exit */
	for (i = 1; i <= THREADS; i++)
		pthread_join(babies[i], NULL);
	exit(0);
}

/* Main hashing thread */
void *
worker(void *arg)
{
	SHA_CTX		hash, copy;
	RSA		*rsa = NULL;
	uint8_t		*tmp, *der,
			buf[SHA_DIGEST_LENGTH],
			onion[ONION_LENP1],
			onionfinal[ONION_LENP1];
	signed int	derlen;
	uint64_t	*counter;
	/* Public exponent and the "big-endian" version of it */
	unsigned int	e, e_be;
	BIGNUM *big_e = BN_new();
	BN_set_word(big_e, (unsigned long) RSA_E_START);

	counter = (uint64_t *)arg;

	while (1) {
		/* Generate a new RSA key every time e reaches RSA_E_LIMIT */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_0_9_0_8
		rsa = RSA_new();
		if (!RSA_generate_key_ex(rsa, RSA_KEYS_BITLEN, big_e, NULL))
			error("RSA Key Generation failed!\n");
#else
		rsa = RSA_generate_key(RSA_KEYS_BITLEN, RSA_E_START,
			NULL, NULL);
		if (!rsa)
			error("RSA Key Generation failed!\n");
#endif

		/* Encode RSA key in X.690 DER format */
		if((derlen = i2d_RSAPublicKey(rsa, NULL)) < 0)
			error("DER encoding failed!\n");
		if ((der = tmp = (uint8_t *)malloc(derlen)) == NULL)
			error("malloc(derlen) failed!\n");
		if (i2d_RSAPublicKey(rsa, &tmp) != derlen)
			error("DER encoding failed!\n");

		/* Prepare the hash context */
		SHA1_Init(&hash);
		SHA1_Update(&hash, der, derlen - SIZE_OF_E);
		free(der);
		e = RSA_E_START - 2; /* public exponent */
		BN_set_word(big_e, (unsigned long) e);

		/* Main loop */
		while  ((e < RSA_E_LIMIT)) {
			e += 2;
			/* Convert e to big-endian format. */
			e_be = HTOBE32(e);
			/* Copy the relevant parts of already set up context. */
			memcpy(&copy, &hash, SHA_REL_CTX_LEN); /* 40 bytes */
			copy.num = hash.num;
			/* Compute SHA1 digest (the real bottleneck) */
			SHA1_Update(&copy, &e_be, SIZE_OF_E);
			SHA1_Final(buf, &copy);
			(*counter)++;
			/* This is fairly fast, but can be faster if inlined. */
			base32_enc(onion, buf);

			if(repeating_chains((char*) onion) <= min_repeating_chains &&
			   unique_characters((char*) onion) <= min_unique_characters){

				printf("unique characters:%i \n",repeating_chains((char*) onion));
				printf("repeating chains:%i \n",unique_characters((char*) onion));

				/* Found a possible key,
				 * from here on down performance is not critical. */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
				BIGNUM *new_e;
				new_e = BN_bin2bn((uint8_t *)&e_be, SIZE_OF_E, NULL);
				if (new_e == NULL)
					error("Failed to convert e to BIGNUM!\n");
				if(!RSA_set0_key(rsa, NULL, new_e, NULL))
					error("Failed to set e in RSA key!\n");
#else
				if (!BN_bin2bn((uint8_t *)&e_be, SIZE_OF_E, rsa->e))
					error("Failed to set e in RSA key!\n");
#endif
				if (!validkey(rsa))
					error("A bad key was found!\n");

				onion_enc(onionfinal, rsa);

				pthread_mutex_lock(&printresult_lock);
				printresult(rsa, onionfinal);

				pthread_mutex_unlock(&printresult_lock);
			}
		}
		RSA_free(rsa);
	}
	return 0;
}


/* Check if the RSA key is ok (PKCS#1 v2.1). */
_Bool
validkey(RSA *rsa)
{
	BN_CTX	*ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BIGNUM	*p1 = BN_CTX_get(ctx),		/* p - 1 */
		*q1 = BN_CTX_get(ctx),		/* q - 1 */
		*gcd = BN_CTX_get(ctx),		/* GCD(p - 1, q - 1) */
		*lambda = BN_CTX_get(ctx),	/* LCM(p - 1, q - 1) */
		*tmp = BN_CTX_get(ctx);		/* temporary storage */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BIGNUM const *n = BN_CTX_get(ctx),
				 *e = BN_CTX_get(ctx),
				 *d = BN_CTX_get(ctx);
	BIGNUM const *p = BN_CTX_get(ctx),
				 *q = BN_CTX_get(ctx);
	BIGNUM const *dmp1 = BN_CTX_get(ctx),
				 *dmq1 = BN_CTX_get(ctx),
				 *iqmp = BN_CTX_get(ctx);

	RSA_get0_key(rsa, &n, &e, &d);
	if (n == NULL || e == NULL || d == NULL)
		error("RSA_get0_key() failed!\n");

	RSA_get0_factors(rsa, &p, &q);
	if (p == NULL || q == NULL)
		error("RSA_get0_factors() failed!\n");

	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if (dmp1 == NULL || dmq1 == NULL || iqmp == NULL)
		error("RSA_get0_crt_params() failed!\n");

	BN_sub(p1, p, BN_value_one());	/* p - 1 */
	BN_sub(q1, q, BN_value_one());	/* q - 1 */
#else
	BN_sub(p1, rsa->p, BN_value_one());	/* p - 1 */
	BN_sub(q1, rsa->q, BN_value_one());	/* q - 1 */
#endif
	BN_gcd(gcd, p1, q1, ctx);			/* gcd(p - 1, q - 1) */

	BN_div(tmp, NULL, p1, gcd, ctx);
	BN_mul(lambda, q1, tmp, ctx);		/* lambda(n) */

	/* Check if e is coprime to lambda(n). */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BN_gcd(tmp, lambda, e, ctx);
#else
	BN_gcd(tmp, lambda, rsa->e, ctx);
#endif
	if (!BN_is_one(tmp)) {
		return 0;
	}

	/* Check if public exponent e is less than n - 1. */
	/* Subtract n from e to avoid checking BN_is_zero. */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BN_sub(tmp, n, BN_value_one());
	if (BN_cmp(e, tmp) >= 0) {
		return 0;
	}
#else
	BN_sub(tmp, rsa->n, BN_value_one());
	if (BN_cmp(rsa->e, tmp) >= 0) {
		/* verbose("WARNING: Key check failed - e is less than (n - 1)!\n"); */
		return 0;
	}
#endif

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BIGNUM *new_d = BN_new(),
		   *new_dmp1 = BN_new(),
		   *new_dmq1 = BN_new(),
		   *new_iqmp = BN_new();

	BN_mod_inverse(new_d, e, lambda, ctx);	/* d */
	BN_mod(new_dmp1, new_d, p1, ctx);		/* d mod(p - 1) */
	BN_mod(new_dmq1, new_d, q1, ctx);		/* d mod(q - 1) */
	BN_mod_inverse(new_iqmp, q, p, ctx);	/* q ^ -1 mod p */

	if (!RSA_set0_key(rsa, NULL, NULL, new_d))
		error("RSA_set0_key() failed!\n");

	if (!RSA_set0_crt_params(rsa, new_dmp1, new_dmq1, new_iqmp))
		error("RSA_set0_crt_params() failed!\n");
#else
	BN_mod_inverse(rsa->d, rsa->e, lambda, ctx);	/* d */
	BN_mod(rsa->dmp1, rsa->d, p1, ctx);		/* d mod(p - 1) */
	BN_mod(rsa->dmq1, rsa->d, q1, ctx);		/* d mod(q - 1) */
	BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);	/* q ^ -1 mod p */
#endif
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	/* In theory this should never be true,
	 * unless the guy before me made a mistake ;). */
	if (RSA_check_key(rsa) != 1) {
		/* verbose("WARNING: OpenSSL's RSA_check_key(rsa) failed!\n"); */
		return 0;
	}
	return 1;
}

/* Base32 encode 10 byte long 'src' into 16 character long 'dst' */
/* Experimental, unroll everything. So far, it seems to be the fastest of the
 * algorithms that I've tried. TODO: review and decide if it's final.*/
void
base32_enc (uint8_t *dst, uint8_t *src)
{
	dst[ 0] = BASE32_ALPHABET[ (src[0] >> 3)				];
	dst[ 1] = BASE32_ALPHABET[((src[0] << 2) | (src[1] >> 6))	& 31];
	dst[ 2] = BASE32_ALPHABET[ (src[1] >> 1)			& 31];
	dst[ 3] = BASE32_ALPHABET[((src[1] << 4) | (src[2] >> 4))	& 31];
	dst[ 4] = BASE32_ALPHABET[((src[2] << 1) | (src[3] >> 7))	& 31];
	dst[ 5] = BASE32_ALPHABET[ (src[3] >> 2)			& 31];
	dst[ 6] = BASE32_ALPHABET[((src[3] << 3) | (src[4] >> 5))	& 31];
	dst[ 7] = BASE32_ALPHABET[	src[4]				& 31];

	dst[ 8] = BASE32_ALPHABET[ (src[5] >> 3)				];
	dst[ 9] = BASE32_ALPHABET[((src[5] << 2) | (src[6] >> 6))	& 31];
	dst[10] = BASE32_ALPHABET[ (src[6] >> 1)			& 31];
	dst[11] = BASE32_ALPHABET[((src[6] << 4) | (src[7] >> 4))	& 31];
	dst[12] = BASE32_ALPHABET[((src[7] << 1) | (src[8] >> 7))	& 31];
	dst[13] = BASE32_ALPHABET[ (src[8] >> 2)			& 31];
	dst[14] = BASE32_ALPHABET[((src[8] << 3) | (src[9] >> 5))	& 31];
	dst[15] = BASE32_ALPHABET[	src[9]				& 31];

	dst[16] = '\0';
}


/* Print found .onion name and PEM formatted RSA key. */
void
printresult(RSA *rsa, uint8_t *actual)
{
	uint8_t		*dst;
	BUF_MEM		*buf;
	BIO		*b;

	b = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(b, rsa, NULL, NULL, 0, NULL, NULL);
	BIO_get_mem_ptr(b, &buf);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	BIO_free(b);

	if ((dst = (uint8_t *)malloc(buf->length + 1)) == NULL)
		error("malloc(buf->length + 1) failed!\n");
	memcpy(dst, buf->data, buf->length);

	dst[buf->length] = '\0';

	printf("----------------------------------------------------------------\n");
	printf("%s.onion\n", actual);
	printf("%s\n", dst);
	fflush(stdout);

	BUF_MEM_free(buf);
	free(dst);
}

/* Generate .onion name from the RSA key. */
/* (using the same method as the official TOR client) */
void
onion_enc(uint8_t *onion, RSA *rsa)
{
	uint8_t		*bufa, *bufb, digest[SHA_DIGEST_LENGTH];
	signed int	derlen;

	if((derlen = i2d_RSAPublicKey(rsa, NULL)) < 0)
		error("DER encoding failed!\n");

	if ((bufa = bufb = (uint8_t *)malloc(derlen)) == NULL)
		error("malloc(derlen) failed!\n");

	if (i2d_RSAPublicKey(rsa, &bufb) != derlen)
		error("DER encoding failed!\n");

	SHA1(bufa, derlen, digest);
	free(bufa);
	base32_enc(onion, digest);
}


/* Print usage information and exit. */
void
usage(void)
{
	fprintf(stderr,
		"usage:\n"
			"%s [min unique characters] [min repeating chains ]\n",
		 __progname);
	exit(1);
}

void
normal(__attribute__((unused)) char *unused, ...)
{
}

/* Print error message and exit. */
/* (Not all Linuxes implement the err/errx functions properly.) */
void
error(char *message, ...)
{
	va_list	ap;

	va_start(ap, message);
	fprintf(stderr, "ERROR: ");
	vfprintf(stderr, message, ap);
	va_end(ap);
	exit(1);
}

unsigned int repeating_chains(char* str){
	int u = 0;
	for(int i = 1; i< 16; i++){
		if(str[i] != str[i-1]) {
			u++;
		}
	}
	return u;
}

unsigned int unique_characters(char* str){
	int count = 0;

	for (int i = 0; i < 16; i++){
		 char appears = 0;
		 for (int j = 0; j < i; j++){
			  if (str[j] == str[i]){
				  appears = 1;
				  break;
			  }
		 }
		 if (!appears){
			 count++;
		 }
	}
	return count;
}

