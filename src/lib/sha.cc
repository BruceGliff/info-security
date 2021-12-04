#include "sha.h"

#include "gcrypt_openssl_wrapper.h"

#include <cstring>
#include <cassert>
#include <arpa/inet.h>

struct SHA_CTX {
	unsigned long long size;
	unsigned int h0, h1, h2, h3, h4;
	unsigned int W[16];
};

#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))

#define SHA_ASM(op, x, n)                                                      \
	__extension__({                                                            \
		unsigned int __res;                                                    \
		__asm__(op " %1,%0" : "=r"(__res) : "i"(n), "0"(x));                   \
		__res;                                                                 \
	})
#define SHA_ROL(x, n) SHA_ASM("rol", x, n)
#define SHA_ROR(x, n) SHA_ASM("ror", x, n)

#else

#define SHA_ROT(X, l, r) (((X) << (l)) | ((X) >> (r)))
#define SHA_ROL(X, n) SHA_ROT(X, n, 32 - (n))
#define SHA_ROR(X, n) SHA_ROT(X, 32 - (n), n)

#endif

#if defined(__i386__) || defined(__x86_64__)
#define setW(x, val) (*(volatile unsigned int *) &W(x) = (val))
#elif defined(__GNUC__) && defined(__arm__)
#define setW(x, val)                                                           \
	do                                                                         \
	{                                                                          \
		W(x) = (val);                                                          \
		__asm__("" ::: "memory");                                              \
	} while (0)
#else
#define setW(x, val) (W(x) = (val))
#endif


#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86)               \
	|| defined(_M_X64) || defined(__ppc__) || defined(__ppc64__)               \
	|| defined(__powerpc__) || defined(__powerpc64__) || defined(__s390__)     \
	|| defined(__s390x__)

#define get_be32(p) ntohl(*(unsigned int *) (p))
#define put_be32(p, v)                                                         \
	do                                                                         \
	{                                                                          \
		*(unsigned int *) (p) = htonl(v);                                      \
	} while (0)

#else

#define get_be32(p)                                                            \
	((*((unsigned char *) (p) + 0) << 24)                                      \
	 | (*((unsigned char *) (p) + 1) << 16)                                    \
	 | (*((unsigned char *) (p) + 2) << 8)                                     \
	 | (*((unsigned char *) (p) + 3) << 0))
#define put_be32(p, v)                                                         \
	do                                                                         \
	{                                                                          \
		unsigned int __v = (v);                                                \
		*((unsigned char *) (p) + 0) = __v >> 24;                              \
		*((unsigned char *) (p) + 1) = __v >> 16;                              \
		*((unsigned char *) (p) + 2) = __v >> 8;                               \
		*((unsigned char *) (p) + 3) = __v >> 0;                               \
	} while (0)

#endif

/* This "rolls" over the 512-bit array */
#define W(x) (array[(x) &15])

/*
 * Where do we get the source from? The first 16 iterations get it from
 * the input data, the next mix it from the 512-bit array.
 */
#define SHA_SRC(t) get_be32(data + t)
#define SHA_MIX(t) SHA_ROL(W(t + 13) ^ W(t + 8) ^ W(t + 2) ^ W(t), 1)

#define SHA_ROUND(t, input, fn, constant, A, B, C, D, E)                       \
	do                                                                         \
	{                                                                          \
		unsigned int TEMP = input(t);                                          \
		setW(t, TEMP);                                                         \
		E += TEMP + SHA_ROL(A, 5) + (fn) + (constant);                         \
		B = SHA_ROR(B, 2);                                                     \
	} while (0)

#define T_0_15(t, A, B, C, D, E)                                               \
	SHA_ROUND(                                                                 \
		t, SHA_SRC, ((((C) ^ (D)) & (B)) ^ (D)), 0x5a827999, A, B, C, D, E)
#define T_16_19(t, A, B, C, D, E)                                              \
	SHA_ROUND(                                                                 \
		t, SHA_MIX, ((((C) ^ (D)) & (B)) ^ (D)), 0x5a827999, A, B, C, D, E)
#define T_20_39(t, A, B, C, D, E)                                              \
	SHA_ROUND(t, SHA_MIX, ((B) ^ (C) ^ (D)), 0x6ed9eba1, A, B, C, D, E)
#define T_40_59(t, A, B, C, D, E)                                              \
	SHA_ROUND(t,                                                               \
			  SHA_MIX,                                                         \
			  (((B) & (C)) + ((D) & ((B) ^ (C)))),                             \
			  0x8f1bbcdc,                                                      \
			  A,                                                               \
			  B,                                                               \
			  C,                                                               \
			  D,                                                               \
			  E)
#define T_60_79(t, A, B, C, D, E)                                              \
	SHA_ROUND(t, SHA_MIX, ((B) ^ (C) ^ (D)), 0xca62c1d6, A, B, C, D, E)

static void SHA1_Block(SHA_CTX * ctx, const unsigned int * data) {
	unsigned int A, B, C, D, E;
	unsigned int array[16];

	A = ctx->h0;
	B = ctx->h1;
	C = ctx->h2;
	D = ctx->h3;
	E = ctx->h4;

	/* Round 1 - iterations 0-16 take their input from 'data' */
	T_0_15(0, A, B, C, D, E);
	T_0_15(1, E, A, B, C, D);
	T_0_15(2, D, E, A, B, C);
	T_0_15(3, C, D, E, A, B);
	T_0_15(4, B, C, D, E, A);
	T_0_15(5, A, B, C, D, E);
	T_0_15(6, E, A, B, C, D);
	T_0_15(7, D, E, A, B, C);
	T_0_15(8, C, D, E, A, B);
	T_0_15(9, B, C, D, E, A);
	T_0_15(10, A, B, C, D, E);
	T_0_15(11, E, A, B, C, D);
	T_0_15(12, D, E, A, B, C);
	T_0_15(13, C, D, E, A, B);
	T_0_15(14, B, C, D, E, A);
	T_0_15(15, A, B, C, D, E);

	/* Round 1 - tail. Input from 512-bit mixing array */
	T_16_19(16, E, A, B, C, D);
	T_16_19(17, D, E, A, B, C);
	T_16_19(18, C, D, E, A, B);
	T_16_19(19, B, C, D, E, A);

	/* Round 2 */
	T_20_39(20, A, B, C, D, E);
	T_20_39(21, E, A, B, C, D);
	T_20_39(22, D, E, A, B, C);
	T_20_39(23, C, D, E, A, B);
	T_20_39(24, B, C, D, E, A);
	T_20_39(25, A, B, C, D, E);
	T_20_39(26, E, A, B, C, D);
	T_20_39(27, D, E, A, B, C);
	T_20_39(28, C, D, E, A, B);
	T_20_39(29, B, C, D, E, A);
	T_20_39(30, A, B, C, D, E);
	T_20_39(31, E, A, B, C, D);
	T_20_39(32, D, E, A, B, C);
	T_20_39(33, C, D, E, A, B);
	T_20_39(34, B, C, D, E, A);
	T_20_39(35, A, B, C, D, E);
	T_20_39(36, E, A, B, C, D);
	T_20_39(37, D, E, A, B, C);
	T_20_39(38, C, D, E, A, B);
	T_20_39(39, B, C, D, E, A);

	/* Round 3 */
	T_40_59(40, A, B, C, D, E);
	T_40_59(41, E, A, B, C, D);
	T_40_59(42, D, E, A, B, C);
	T_40_59(43, C, D, E, A, B);
	T_40_59(44, B, C, D, E, A);
	T_40_59(45, A, B, C, D, E);
	T_40_59(46, E, A, B, C, D);
	T_40_59(47, D, E, A, B, C);
	T_40_59(48, C, D, E, A, B);
	T_40_59(49, B, C, D, E, A);
	T_40_59(50, A, B, C, D, E);
	T_40_59(51, E, A, B, C, D);
	T_40_59(52, D, E, A, B, C);
	T_40_59(53, C, D, E, A, B);
	T_40_59(54, B, C, D, E, A);
	T_40_59(55, A, B, C, D, E);
	T_40_59(56, E, A, B, C, D);
	T_40_59(57, D, E, A, B, C);
	T_40_59(58, C, D, E, A, B);
	T_40_59(59, B, C, D, E, A);

	/* Round 4 */
	T_60_79(60, A, B, C, D, E);
	T_60_79(61, E, A, B, C, D);
	T_60_79(62, D, E, A, B, C);
	T_60_79(63, C, D, E, A, B);
	T_60_79(64, B, C, D, E, A);
	T_60_79(65, A, B, C, D, E);
	T_60_79(66, E, A, B, C, D);
	T_60_79(67, D, E, A, B, C);
	T_60_79(68, C, D, E, A, B);
	T_60_79(69, B, C, D, E, A);
	T_60_79(70, A, B, C, D, E);
	T_60_79(71, E, A, B, C, D);
	T_60_79(72, D, E, A, B, C);
	T_60_79(73, C, D, E, A, B);
	T_60_79(74, B, C, D, E, A);
	T_60_79(75, A, B, C, D, E);
	T_60_79(76, E, A, B, C, D);
	T_60_79(77, D, E, A, B, C);
	T_60_79(78, C, D, E, A, B);
	T_60_79(79, B, C, D, E, A);

	ctx->h0 += A;
	ctx->h1 += B;
	ctx->h2 += C;
	ctx->h3 += D;
	ctx->h4 += E;
}

void SHA1_Init(SHA_CTX * ctx) {
	ctx->size = 0;

	/* Initialize H with the magic constants (see FIPS180 for constants) */
	ctx->h0 = 0x67452301;
	ctx->h1 = 0xefcdab89;
	ctx->h2 = 0x98badcfe;
	ctx->h3 = 0x10325476;
	ctx->h4 = 0xc3d2e1f0;
}

void SHA1_Update(SHA_CTX * ctx, const void * data, unsigned long len) {
	unsigned int lenW = ctx->size & 63;

	ctx->size += len;

	/* Read the data into W and process blocks as they get full */
	if (lenW) {
		unsigned int left = 64 - lenW;
		if (len < left) left = len;
		memcpy(lenW + (char *) ctx->W, data, left);
		lenW = (lenW + left) & 63;
		len -= left;
		data = ((const char *) data + left);
		if (lenW) return;
		SHA1_Block(ctx, ctx->W);
	}
	while (len >= 64) {
		SHA1_Block(ctx, (unsigned int*)data);
		data = ((const char *) data + 64);
		len -= 64;
	}
	if (len) memcpy(ctx->W, data, len);
}

void SHA1_Final(unsigned char hashout[20], SHA_CTX * ctx) {
	static const unsigned char pad[64] = {0x80}; //-V1009
	unsigned int padlen[2];
	int i;

	/* Pad with a binary 1 (ie 0x80), then zeroes, then length */
	padlen[0] = htonl((uint32_t)(ctx->size >> 29));
	padlen[1] = htonl((uint32_t)(ctx->size << 3));

	i = ctx->size & 63;
	SHA1_Update(ctx, pad, 1 + (63 & (55 - i)));
	SHA1_Update(ctx, padlen, 8);

	/* Output hash */
	put_be32(&hashout[0], ctx->h0);
	put_be32(&hashout[4], ctx->h1);
	put_be32(&hashout[8], ctx->h2);
	put_be32(&hashout[12], ctx->h3);
	put_be32(&hashout[16], ctx->h4);
}





void calc_pmk(uint8_t const * key, uint8_t const * essid_pre, uint32_t essid_pre_len, uint8_t pmk[40]) {
	int i, j, slen;
	unsigned char buffer[65];
	char essid[33 + 4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	if (essid_pre_len > 32) {
		essid_pre_len = 32;
	}

	memset(essid, 0, sizeof(essid));
	memcpy(essid, essid_pre, essid_pre_len);
	slen = (int) essid_pre_len + 4;

	/* setup the inner and outer contexts */

	memset(buffer, 0, sizeof(buffer));
	strncpy((char *) buffer, (char *) key, sizeof(buffer) - 1);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x36;

	SHA1_Init(&ctx_ipad);
	SHA1_Update(&ctx_ipad, buffer, 64);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x6A;

	SHA1_Init(&ctx_opad);
	SHA1_Update(&ctx_opad, buffer, 64);

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC(EVP_sha1(),
		 key,
		 (int) strlen((char *) key),
		 (unsigned char *) essid,
		 (size_t) slen,
		 pmk,
		 NULL);
	memcpy(buffer, pmk, 20); //-V512

	for (i = 1; i < 4096; i++) {
		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		for (j = 0; j < 20; j++) pmk[j] ^= buffer[j];
	}

	essid[slen - 1] = '\2';
	HMAC(EVP_sha1(),
		 (unsigned char *) key,
		 (int) strlen((char *) key),
		 (unsigned char *) essid,
		 (size_t) slen,
		 pmk + 20,
		 NULL);
	memcpy(buffer, pmk + 20, 20);

	for (i = 1; i < 4096; i++) {
		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		for (j = 0; j < 20; j++) pmk[j + 20] ^= buffer[j];
	}
}
