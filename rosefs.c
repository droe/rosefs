/*
 * RoseFS/0.0 - Rock-Solid Encrypted File System, Version 0, Revision 0
 * Copyright (c) 2010-2011, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/RoseFS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This code is EXPERIMENTAL.
 * Do not rely on it with your economic success or even your life.
 */

/*
 * Build on MacOS X:
 *
 * % export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
 * % gcc -O2 -std=c99 -mmacosx-version-min=10.5 \
 *       `pkg-config --cflags --libs fuse openssl` -o rosefs rosefs.c
 *
 * Add -DHAVE_FDATASYNC if fdatasync() is available and should be used.
 * Add -DNDEBUG if you don't want the assertions and selfchecks.
 * Add -g -Wall -pedantic for debugging.
 */

/*
 * NAME
 *     RoseFS - The Rock-Solid Encrypted File System
 *
 * SYNOPSIS
 *     rosefs /var/backend /mnt/point
 *
 * DESCRIPTION
 *     RoseFS is a transparent, encrypted passthrough filesystem based on
 *     FUSE.  It was designed for everyday use by the pragmatical paranoid.
 *     It encrypts filenames and content, but not file attributes such as
 *     file size, structure of directory layout or owner and permissions.
 *
 * DESIGN GOALS
 *     Correctness, dependability, reliability, compatibility, robustness:
 *     The filesystem should be correctly handling all corner cases and error
 *     conditions and support all necessary features of modern filesystems
 *     (including extended attributes, sparse files and relative symlinks).
 *     It should be able to use case insensitive filesystems as storage
 *     backend, such as HFS+ on MacOS X.  It should fail gracefully.
 *
 *     Security with focus on static confidentiality:
 *     The filesystem should use a proven cryptographic design based on proven
 *     cryptographic algorithms.  No home-grown crypto primitives or dubious
 *     modifications of algorithms, modes or protocols.  In it's current
 *     invocation, the protection of integrity is not a design goal.
 *
 *     Performance:
 *     The filesystem should be reasonably performant while not sacrificing
 *     correctness or security.  For example, filesystem operations expected
 *     to run in constant time should not require re-encryption of file data.
 *     Dubious extras whish do not add any real security should be avoided.
 *
 *     Simple backwards compatibility:
 *     Every RoseFS binary only supports it's own backend file format, in
 *     order to reduce software complexity.  However, RoseFS will exec() a
 *     suitable older version of RoseFS automatically if it encounters an
 *     older filesystem (e.g. rosefs1 for version 1, searched in PATH and
 *     libexec directories, see ROSE_PATH below).
 *
 * CRYPTOGRAPHIC DESIGN
 *     Key derivation:
 *     Encryption keys are generated from the volume password using PKCS #5
 *     PBKDF2 with HMAC-SHA-256 with two different 256 bit random salts,
 *     one for filename encryption and one for data encryption.  Because the
 *     filename and data encryption have totally different cryptographical
 *     characteristics, using two distinct keys makes one independent from
 *     the other.
 *
 *     Random number generation:
 *     The arc4random() API is used to generate nonces, salts and IVs.
 *     The arc4random() random number generator automatically seeds from the
 *     kernel entropy pool via /dev/urandom.  Some additional seeding is
 *     done when initializing RoseFS.  The arc4random() generator is
 *     generally considered to provide randomness suitable for crypto use.
 *
 *     Encryption of file content:
 *     AES-256 in CTR mode and per-file random nonce.  A 64-bit block
 *     counter is added to a per-file 128-bit random nonce to produce the
 *     input block for the CTR mode.  The 128-bit nonce is stored in the
 *     first 128 bits of each file, effectively enlarging all files by
 *     128 bits and shifting file offsets by 128 bit.  This means that
 *     applications which align their reads and writes to block boundaries
 *     will get unaligned disk accesses and thus a performance hit.
 *     Storing the nonce at the end instead of the beginning of files
 *     would solve this at a cost of an increased complexity of write
 *     operations at the end of files.
 *
 *     Encryption of file and directory names:
 *     AES-256 in CBC mode with a fixed zero IV and Base32 encoding.
 *     This design was chosen to allow context-free random access and
 *     rename and move operations in constant time.  Base32 encoding is
 *     used to support case-insensitive backend filesystems (such as is
 *     the default on MacOS X), at the cost of longer filenames and lower
 *     length limits.
 *
 *     Encryption of extended attributes:
 *     Extended attributes are at the moment not directly supported by
 *     RoseFS.  MacOS X stores extended attributes in separate ._* files
 *     which are then encrypted as regular files by RoseFS.
 *
 * LIMITATIONS
 *     RoseFS does not pass file sparseness to the backend both for reasons
 *     of confidentiality and of portability.
 *
 *     Avoid moving/copying backends from case-insensitive filesystems to
 *     case-sensitive ones, since that may result in backends with
 *     non-canonicalized filenames (i.e. with the wrong case).
 *
 *     The filename encryption and encoding results in roughly 60% longer
 *     file and directory names.  This in turn means that the virtual
 *     RoseFS filesystem will have somewhat lower name limits than the
 *     system's PATH_MAX and NAME_MAX.
 *
 *     Files being written to keep their nonce in order to prevent
 *     reencryption of whole files for each write call.  As a consequence,
 *     attackers with the ability to write chosen data into the backend, or
 *     to observe the encrypted backend over write operations, can recover
 *     the keystream for the particular file, or parts of it.
 *
 *     The filename encryption uses a global, constant IV.  This means that
 *     files with the same name will get encrypted to the same encrypted
 *     name.  This is a direct consequence of the random access requirement
 *     of filenames.  If that violates your security requirements, you
 *     should consider encrypted filesystems with a single file backend.
 *     The same argument holds for file attributes such as size, owner,
 *     group and permissions.
 */

/*
 * TODO
 * -   investigate tuning statfs parameters.
 * -   use a global, random IV for filename encryption.
 * -   port to and test on FreeBSD and Linux.
 * -   encrypt extended attributes and their names.
 * -   add password/key verification checksums.
 * -   lock backend directory.
 * -   add support for external password entry mechanisms.
 */

#include <sys/param.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include <openssl/aes.h>
#include <openssl/sha.h>
#ifndef SHA256_BLOCK_LENGTH
#define SHA256_BLOCK_LENGTH	64
#endif

#define ROSE_VER	0
#define ROSE_REV	0
#define KEY_BITS	256
#define KEY_SIZE	(KEY_BITS/8)
#define PBKDF2_ROUNDS	8192
#define CHUNK_SIZE	1024
#define ROSE_PATH	"/usr/libexec:/usr/local/libexec"

#ifndef HAVE_FDATASYNC
#define fdatasync(x) fsync(x)
#endif

#define Q_(x)		#x
#define Q(x)		Q_(x)
#define UNUSED		__attribute__((__unused__))
#define FUSE_CTX	(fuse_get_context()->private_data)

/* initialization context */
struct rose_ictx {
	char *backend;		/* backend path, including trailing slash */
	unsigned char name_keybuf[KEY_SIZE];	/* raw name encryption key */
	unsigned char data_keybuf[KEY_SIZE];	/* raw data encryption key */
/*	unsigned char name_ivbuf[AES_BLOCK_SIZE]; */
};

/* per-filesystem context */
struct rose_ctx {
	char *backend;		/* backend path, including trailing slash */
	size_t backendsz;	/* number of chars in backend path, w/o \0 */
	AES_KEY name_ekey;	/* name encryption expanded key, for CBC */
	AES_KEY name_dkey;	/* name decryption expanded key, for CBC */
	AES_KEY data_ekey;	/* data encryption expanded key, for CTR */
/*	unsigned char name_iv[AES_BLOCK_SIZE]; */
};

/* per-directory context */
struct rose_dctx {
	DIR *dirp;		/* open directory pointer to backend dir */
};

/* per-file context */
struct rose_fctx {
	int fd;			/* open file descriptor to backend file */
	off_t vsize;		/* virtual file size, without header/nonce */
	unsigned char *nonce;	/* nonce, allocated iff regular file */
};

static const unsigned char zeroes[CHUNK_SIZE] = { 0 };


/*
 * general utility functions
 */

/* overwrite string s with zeroes in a single pass */
static void
rose_strzero(void *s)
{
	char *p = (char *)s;
	while (*p) {
		*(p++) = '\0';
	}
}


/*
 * encoding primitives
 */

/* base32hex encoder, upper case variant (cf. RFC 4648)
 * Returns number of characters written to outbuf, or negative errno.
 * Output buffer is never null terminated. */
static ssize_t
rose_base32_encode(char *outbuf, size_t outsz, const unsigned char *inbuf, size_t insz)
{
	static const uint64_t alphabet[32] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
		'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
		'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V' };
	size_t i, o;
	uint64_t tmp;

	for (i = 0, o = 0; i + 5 <= insz && o + 8 <= outsz; i += 5, o += 8) {
		tmp  = (uint64_t) inbuf[i] << 32;
		tmp += (uint64_t) inbuf[i+1] << 24;
		tmp += (uint64_t) inbuf[i+2] << 16;
		tmp += (uint64_t) inbuf[i+3] <<  8;
		tmp += (uint64_t) inbuf[i+4];
		outbuf[o]   = alphabet[(tmp >> 35) & 0x1f];
		outbuf[o+1] = alphabet[(tmp >> 30) & 0x1f];
		outbuf[o+2] = alphabet[(tmp >> 25) & 0x1f];
		outbuf[o+3] = alphabet[(tmp >> 20) & 0x1f];
		outbuf[o+4] = alphabet[(tmp >> 15) & 0x1f];
		outbuf[o+5] = alphabet[(tmp >> 10) & 0x1f];
		outbuf[o+6] = alphabet[(tmp >>  5) & 0x1f];
		outbuf[o+7] = alphabet[ tmp        & 0x1f];
	}

	if (i == insz) return o;
	tmp =  (uint64_t) inbuf[i++] << 32;
	if (o < outsz) outbuf[o++] = alphabet[(tmp >> 35) & 0x1f];
	else return -ENAMETOOLONG;
	if (i == insz) {
		if (o < outsz) outbuf[o++] = alphabet[(tmp >> 30) & 0x1f];
		else return -ENAMETOOLONG;
		return o;
	}
	tmp += (uint64_t) inbuf[i++] << 24;
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = alphabet[(tmp >> 30) & 0x1f];
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = alphabet[(tmp >> 25) & 0x1f];
	if (i == insz) {
		if (o == outsz) return -ENAMETOOLONG;
		outbuf[o++] = alphabet[(tmp >> 20) & 0x1f];
		return o;
	}
	tmp += (uint64_t) inbuf[i++] << 16;
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = alphabet[(tmp >> 20) & 0x1f];
	if (i == insz) {
		if (o == outsz) return -ENAMETOOLONG;
		outbuf[o++] = alphabet[(tmp >> 15) & 0x1f];
		return o;
	}
	tmp += (uint64_t) inbuf[i++] <<  8;
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = alphabet[(tmp >> 15) & 0x1f];
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = alphabet[(tmp >> 10) & 0x1f];
	if (i == insz) {
		if (o == outsz) return -ENAMETOOLONG;
		outbuf[o++] = alphabet[(tmp >>  5) & 0x1f];
		return o;
	}
	tmp += (uint64_t) inbuf[i++];
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = alphabet[(tmp >>  5) & 0x1f];
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = alphabet[ tmp        & 0x1f];
	assert(i == insz);
	return o;
}

/* base32hex decoder, case-agnostic (cf. RFC 4648)
 * Returns number of characters written to outbuf, or negative errno. */
static ssize_t
rose_base32_decode(unsigned char *outbuf, size_t outsz, const char *inbuf, size_t insz)
{
	static const uint64_t revalphabet[256] = {
		 0,  0,  0,  0,  0,  0,  0,  0, /*   0 ..   7 */
		 0,  0,  0,  0,  0,  0,  0,  0, /*   8 ..  15 */
		 0,  0,  0,  0,  0,  0,  0,  0, /*  16 ..  23 */
		 0,  0,  0,  0,  0,  0,  0,  0, /*  24 ..  31 */
		 0,  0,  0,  0,  0,  0,  0,  0, /*  32 ..  39 */
		 0,  0,  0,  0,  0,  0,  0,  0, /*  40 ..  47 */
		 0,  1,  2,  3,  4,  5,  6,  7, /*  48 ..  55 */
		 8,  9,  0,  0,  0,  0,  0,  0, /*  56 ..  63 */
		 0, 10, 11, 12, 13, 14, 15, 16, /*  64 ..  71 */
		17, 18, 19, 20, 21, 22, 23, 24, /*  72 ..  79 */
		25, 26, 27, 28, 29, 30, 31,  0, /*  80 ..  87 */
		 0,  0,  0,  0,  0,  0,  0,  0, /*  88 ..  95 */
		 0, 10, 11, 12, 13, 14, 15, 16, /*  96 .. 103 */
		17, 18, 19, 20, 21, 22, 23, 24, /* 104 .. 111 */
		25, 26, 27, 28, 29, 30, 31,  0, /* 112 .. 119 */
		0 /* 120 .. 255 */ };
	size_t i, o;
	uint64_t tmp;

	for (i = 0, o = 0; i + 8 <= insz && o + 5 <= outsz; i += 8, o += 5) {
		tmp =  revalphabet[(unsigned char)inbuf[i]] << 35;
		tmp += revalphabet[(const unsigned char)inbuf[i+1]] << 30;
		tmp += revalphabet[(const unsigned char)inbuf[i+2]] << 25;
		tmp += revalphabet[(const unsigned char)inbuf[i+3]] << 20;
		tmp += revalphabet[(const unsigned char)inbuf[i+4]] << 15;
		tmp += revalphabet[(const unsigned char)inbuf[i+5]] << 10;
		tmp += revalphabet[(const unsigned char)inbuf[i+6]] <<  5;
		tmp += revalphabet[(const unsigned char)inbuf[i+7]];
		outbuf[o]   = (tmp >> 32) & 0xff;
		outbuf[o+1] = (tmp >> 24) & 0xff;
		outbuf[o+2] = (tmp >> 16) & 0xff;
		outbuf[o+3] = (tmp >>  8) & 0xff;
		outbuf[o+4] =  tmp        & 0xff;
	}

	if (i == insz) return o;
	tmp = (uint64_t)revalphabet[(unsigned char)inbuf[i++]] << 35;
	if (i == insz) return -EINVAL;
	tmp += revalphabet[(unsigned char)inbuf[i++]] << 30;
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = (tmp >> 32) & 0xff;
	if (i == insz) return o;
	tmp += revalphabet[(unsigned char)inbuf[i++]] << 25;
	if (i == insz) return -EINVAL;
	tmp += revalphabet[(unsigned char)inbuf[i++]] << 20;
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = (tmp >> 24) & 0xff;
	if (i == insz) return o;
	tmp += revalphabet[(unsigned char)inbuf[i++]] << 15;
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = (tmp >> 16) & 0xff;
	if (i == insz) return o;
	tmp += revalphabet[(unsigned char)inbuf[i++]] << 10;
	if (i == insz) return -EINVAL;
	tmp += revalphabet[(unsigned char)inbuf[i++]] <<  5;
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] = (tmp >>  8) & 0xff;
	if (i == insz) return o;
	tmp += revalphabet[(unsigned char)inbuf[i++]];
	if (o == outsz) return -ENAMETOOLONG;
	outbuf[o++] =  tmp        & 0xff;
	assert(i == insz);
	return o;
}

#ifndef NDEBUG
static int
rose_base32_test()
{
	unsigned char foobar[] = "foobar";
	char s[16];
	unsigned char b[32];
	ssize_t n;

	assert((n = rose_base32_encode(s, sizeof(s), foobar, 0)) == 0);
	assert((n = rose_base32_decode(b, sizeof(b), s, n)) == 0);

	assert((n = rose_base32_encode(s, sizeof(s), foobar, 1)) == 2);
	assert(!memcmp(s, "CO", n));
	assert((n = rose_base32_decode(b, sizeof(b), s, n)) == 1);
	assert(!memcmp(b, foobar, n));

	assert((n = rose_base32_encode(s, sizeof(s), foobar, 2)) == 4);
	assert(!memcmp(s, "CPNG", n));
	assert((n = rose_base32_decode(b, sizeof(b), s, n)) == 2);
	assert(!memcmp(b, foobar, n));

	assert((n = rose_base32_encode(s, sizeof(s), foobar, 3)) == 5);
	assert(!memcmp(s, "CPNMU", n));
	assert((n = rose_base32_decode(b, sizeof(b), s, n)) == 3);
	assert(!memcmp(b, foobar, n));

	assert((n = rose_base32_encode(s, sizeof(s), foobar, 4)) == 7);
	assert(!memcmp(s, "CPNMUOG", n));
	assert((n = rose_base32_decode(b, sizeof(b), s, n)) == 4);
	assert(!memcmp(b, foobar, n));

	assert((n = rose_base32_encode(s, sizeof(s), foobar, 5)) == 8);
	assert(!memcmp(s, "CPNMUOJ1", n));
	assert((n = rose_base32_decode(b, sizeof(b), s, n)) == 5);
	assert(!memcmp(b, foobar, n));

	assert((n = rose_base32_encode(s, sizeof(s), foobar, 6)) == 10);
	assert(!memcmp(s, "CPNMUOJ1E8", n));
	assert((n = rose_base32_decode(b, sizeof(b), s, n)) == 6);
	assert(!memcmp(b, foobar, n));

	assert(rose_base32_encode(s, 1, foobar, 1) == -ENAMETOOLONG);
	assert(rose_base32_decode(b, 1, "CPNMUOJ1E8", 10) == -ENAMETOOLONG);
	assert(rose_base32_decode(b, sizeof(b), "CPNMUOJ1E8", 9) == -EINVAL);
	assert(rose_base32_decode(b, sizeof(b), "CPNMUOJ1E8", 6) == -EINVAL);
	assert(rose_base32_decode(b, sizeof(b), "CPNMUOJ1E8", 3) == -EINVAL);
	assert(rose_base32_decode(b, sizeof(b), "CPNMUOJ1E8", 1) == -EINVAL);

	return 0;
}
#endif


/*
 * Crypto primitives
 */

/* HMAC-SHA-256 (cf. RFC 4231). */
static void
rose_hmac_sha256(unsigned char digest[SHA256_DIGEST_LENGTH],
                 const unsigned char *data, size_t datasz,
                 const unsigned char *key, size_t keysz)
{
	unsigned char keypad[SHA256_BLOCK_LENGTH];
	unsigned char tmpkey[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	int i;

	if (keysz > SHA256_BLOCK_LENGTH) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, keysz);
		SHA256_Final(tmpkey, &ctx);
		key = tmpkey;
		keysz = SHA256_DIGEST_LENGTH;
	}

	memset(keypad, 0, sizeof(keypad));
	memcpy(keypad, key, keysz);
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++)
		keypad[i] ^= 0x36;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, keypad, SHA256_BLOCK_LENGTH);
	SHA256_Update(&ctx, data, datasz);
	SHA256_Final(digest, &ctx);

	memset(keypad, 0, sizeof(keypad));
	memcpy(keypad, key, keysz);
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++)
		keypad[i] ^= 0x5c;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, keypad, SHA256_BLOCK_LENGTH);
	SHA256_Update(&ctx, digest, SHA256_DIGEST_LENGTH);
	SHA256_Final(digest, &ctx);
}

#ifndef NDEBUG
/* RFC 4868 test vectors for HMAC-SHA-256 */
static int
rose_hmac_sha256_test()
{
	unsigned char key1[20] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b };
	unsigned char data1[8] = "Hi There";
	unsigned char hmac1[SHA256_DIGEST_LENGTH] = {
		0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
		0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
		0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
		0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 };
	unsigned char key2[4] = "Jefe";
	unsigned char data2[28] = "what do ya want for nothing?";
	unsigned char hmac2[SHA256_DIGEST_LENGTH] = {
		0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
		0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
		0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
		0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 };
	unsigned char key3[20] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa };
	unsigned char data3[50] = {
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd };
	unsigned char hmac3[SHA256_DIGEST_LENGTH] = {
		0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
		0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
		0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
		0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe };
	unsigned char key4[25] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19 };
	unsigned char data4[50] = {
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd };
	unsigned char hmac4[SHA256_DIGEST_LENGTH] = {
		0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
		0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
		0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
		0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b };
	unsigned char key5[131] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa };
	unsigned char data5[54] =
		"Test Using Larger Than Block-Size Key - Hash "
		"Key First";
	unsigned char hmac5[SHA256_DIGEST_LENGTH] = {
		0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
		0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
		0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
		0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54 };
	/* unsigned char key6[131] = { 0xaa ... }; */
	unsigned char data6[152] =
		"This is a test using a larger than block-size"
		" key and a larger than block-size data. The k"
		"ey needs to be hashed before being used by th"
		"e HMAC algorithm.";
	unsigned char hmac6[SHA256_DIGEST_LENGTH] = {
		0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
		0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
		0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
		0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2 };
	unsigned char hmac[SHA256_DIGEST_LENGTH];

	rose_hmac_sha256(hmac, data1, sizeof(data1), key1, sizeof(key1));
	assert(!memcmp(hmac, hmac1, sizeof(hmac1)));
	rose_hmac_sha256(hmac, data2, sizeof(data2), key2, sizeof(key2));
	assert(!memcmp(hmac, hmac2, sizeof(hmac2)));
	rose_hmac_sha256(hmac, data3, sizeof(data3), key3, sizeof(key3));
	assert(!memcmp(hmac, hmac3, sizeof(hmac3)));
	rose_hmac_sha256(hmac, data4, sizeof(data4), key4, sizeof(key4));
	assert(!memcmp(hmac, hmac4, sizeof(hmac4)));
	rose_hmac_sha256(hmac, data5, sizeof(data5), key5, sizeof(key5));
	assert(!memcmp(hmac, hmac5, sizeof(hmac5)));
	rose_hmac_sha256(hmac, data6, sizeof(data6), key5, sizeof(key5));
	assert(!memcmp(hmac, hmac6, sizeof(hmac6)));
	return 0;
}
#endif

/* PKCS #5 PBKDF2 (cf. RFC 2898).
 * Returns 0 on success, negative errno on error. */
static int
rose_pkcs5_pbkdf2(unsigned char *key, size_t keysz,
                  const char *passwd, size_t passwdsz,
                  const unsigned char *salt, size_t saltsz,
                  unsigned int rounds)
{
	unsigned char keyblock[SHA256_DIGEST_LENGTH];
	unsigned char dnext[SHA256_DIGEST_LENGTH];
	unsigned char d[SHA256_DIGEST_LENGTH];
	unsigned char *indexedsalt;
	unsigned int blockindex, c, i;
	size_t n;

	assert(keysz > 0 && keysz < SIZE_MAX);
	assert(passwdsz > 0);
	assert(saltsz > 0);
	assert(rounds > 0);

	if (!(indexedsalt = malloc(saltsz + 4)))
		return -ENOMEM;
	memcpy(indexedsalt, salt, saltsz);

	for (blockindex = 1; keysz > 0; blockindex++) {
		indexedsalt[saltsz + 0] = (blockindex >> 24) & 0xff;
		indexedsalt[saltsz + 1] = (blockindex >> 16) & 0xff;
		indexedsalt[saltsz + 2] = (blockindex >>  8) & 0xff;
		indexedsalt[saltsz + 3] =  blockindex        & 0xff;
		rose_hmac_sha256(d, indexedsalt, saltsz + 4,
		                 (unsigned char *)passwd, passwdsz);
		memcpy(keyblock, d, sizeof(keyblock));
		for (c = 1; c < rounds; c++) {
			rose_hmac_sha256(dnext, d, sizeof(d),
			                 (unsigned char *)passwd, passwdsz);
			memcpy(d, dnext, sizeof(d));
			for (i = 0; i < sizeof(keyblock); i++)
				keyblock[i] ^= d[i];
		}

		n = keysz;
		if (n > SHA256_DIGEST_LENGTH)
			n = SHA256_DIGEST_LENGTH;
		memcpy(key, keyblock, n);
		key += n;
		keysz -= n;
	};

	memset(keyblock, 0, sizeof(keyblock));
	memset(d, 0, sizeof(d));
	memset(dnext, 0, sizeof(dnext));
	memset(indexedsalt, 0, saltsz + 4);
	free(indexedsalt);
	return 0;
}

#ifndef NDEBUG
/* PKCS #5 PBKDF2 test vectors
 * also consider testing against https://github.com/emerose/pbkdf2-ruby */
static int
rose_pkcs5_pbkdf2_test()
{
	char passwd1[8] = "password";
	unsigned char salt1[8] = {
		0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06 };
	unsigned char key1[24] = {
		0x97, 0xb5, 0xa9, 0x1d, 0x35, 0xaf, 0x54, 0x23,
		0x24, 0x88, 0x13, 0x15, 0xc4, 0xf8, 0x49, 0xe3,
		0x27, 0xc4, 0x70, 0x7d, 0x1b, 0xc9, 0xd3, 0x22
	};
	size_t rounds1 = 2048;
	unsigned char key[24];

	rose_pkcs5_pbkdf2(key, sizeof(key1), passwd1, sizeof(passwd1),
	                  salt1, sizeof(salt1), rounds1);
	assert(!memcmp(key, key1, sizeof(key1)));
	return 0;
}
#endif

/* Initialize the PRNG. */
static void
rose_random_init()
{
	uint32_t seed[] = { time(NULL), clock(), getpid(), getuid() };

	arc4random_stir();
	arc4random_addrandom((unsigned char *) seed, sizeof(seed));
}

/* Produce sz of random bytes into rnd. */
static void
rose_random(unsigned char *rnd, size_t sz)
{
	uint32_t *p = (uint32_t*)(rnd + sz);

	while (p-- != (uint32_t*)rnd) {
		*p = arc4random();
	}
}

/* (in-place) CTR encryption and decryption of arbitrary sized buffers */
static void
rose_ctr_crypt(unsigned char *dst, const unsigned char *src, size_t sz,
               off_t off, unsigned char nonce[AES_BLOCK_SIZE], AES_KEY *key)
{
	unsigned char block[AES_BLOCK_SIZE];
	unsigned char keystream[AES_BLOCK_SIZE];
	uint64_t i;

	memcpy(block, nonce, AES_BLOCK_SIZE);
	*(uint64_t *)block += off / AES_BLOCK_SIZE;

	i = 0;
	if (off % AES_BLOCK_SIZE) {
		AES_encrypt(block, keystream, key);
		(*(uint64_t *)block)++;
		while (i < (uint64_t) off % AES_BLOCK_SIZE) {
			dst[i] = src[i] ^ keystream[(off+i) % AES_BLOCK_SIZE];
			i++;
		}
	}

	while (i < sz - AES_BLOCK_SIZE) {
		AES_encrypt(block, keystream, key);
		(*(uint64_t *)block)++;
		*(uint64_t*)(dst+i) = *(uint64_t*)(src+i)
			^ *(uint64_t*)(keystream+((off+i) % AES_BLOCK_SIZE));
		i += 8;
		*(uint64_t*)(dst+i) = *(uint64_t*)(src+i)
			^ *(uint64_t*)(keystream+((off+i) % AES_BLOCK_SIZE));
		i += 8;
	}

	if (i < sz) {
		AES_encrypt(block, keystream, key);
		(*(uint64_t *)block)++;
		while (i < sz) {
			dst[i] = src[i] ^ keystream[(off+i) % AES_BLOCK_SIZE];
			i++;
		}
	}
}

#ifndef NDEBUG
static int
rose_ctr_test()
{
/*	unsigned char buf[1024];
	AES_KEY key;

	AES_set_encrypt_key(zeroes, 256, &key);

	for (int i = 0; i < 1000000; i++) {
		rose_ctr_crypt(buf, buf, 1000, 13, zeroes, &key);
	}
*/
	return 0;
}
#endif

/* (in-place) CBC encryption, buffer sizes must be a multiple of block size. */
static void
rose_cbc_encrypt(unsigned char *dst, const unsigned char *src, size_t sz,
                 const unsigned char iv[AES_BLOCK_SIZE], AES_KEY *key)
{
	size_t i;

	assert(sz > 0 && sz % AES_BLOCK_SIZE == 0);

	*(uint64_t *)(dst)   = *(uint64_t *)(src)   ^ *(uint64_t *)(iv);
	*(uint64_t *)(dst+8) = *(uint64_t *)(src+8) ^ *(uint64_t *)(iv+8);
	AES_encrypt(dst, dst, key);
	for (i = AES_BLOCK_SIZE; i < sz; i += AES_BLOCK_SIZE) {
		*(uint64_t *)(dst+i)   =
			*(uint64_t *)(src+i)   ^ *(uint64_t *)(dst+i-16);
		*(uint64_t *)(dst+i+8) =
			*(uint64_t *)(src+i+8) ^ *(uint64_t *)(dst+i-8);
		AES_encrypt(dst+i, dst+i, key);
	}
}

/* (in-place) CBC decryption, buffer sizes must be a multiple of block size. */
static void
rose_cbc_decrypt(unsigned char *dst, const unsigned char *src, size_t sz,
                 const unsigned char iv[AES_BLOCK_SIZE], AES_KEY *key)
{
	size_t i;

	assert(sz > 0 && sz % AES_BLOCK_SIZE == 0);

	for (i = sz - AES_BLOCK_SIZE; i > 0; i -= AES_BLOCK_SIZE) {
		AES_decrypt(src+i, dst+i, key);
		*(uint64_t *)(dst+i)   ^= *(uint64_t *)(dst+i-16);
		*(uint64_t *)(dst+i+8) ^= *(uint64_t *)(dst+i-8);
	}
	AES_decrypt(src, dst, key);
	*(uint64_t *)(dst)   ^= *(uint64_t *)(iv);
	*(uint64_t *)(dst+8) ^= *(uint64_t *)(iv+8);
}

#ifndef NDEBUG
/* RFC 3602 test vectors for AES-CBC */
static int
rose_cbc_test()
{
	unsigned char key1[16] = {
		0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
		0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06 };
	unsigned char iv1[16] = {
		0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
		0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41 };
	unsigned char plain1[AES_BLOCK_SIZE] = "Single block msg";
	unsigned char cipher1[AES_BLOCK_SIZE] = {
		0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8,
		0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a };
	unsigned char key2[16] = {
		0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0,
		0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a };
	unsigned char iv2[16] = {
		0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28,
		0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 };
	unsigned char plain2[2*AES_BLOCK_SIZE] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	unsigned char cipher2[2*AES_BLOCK_SIZE] = {
		0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a,
		0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
		0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9,
		0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1 };
	unsigned char key3[16] = {
		0x6c, 0x3e, 0xa0, 0x47, 0x76, 0x30, 0xce, 0x21,
		0xa2, 0xce, 0x33, 0x4a, 0xa7, 0x46, 0xc2, 0xcd };
	unsigned char iv3[16] = {
		0xc7, 0x82, 0xdc, 0x4c, 0x09, 0x8c, 0x66, 0xcb,
		0xd9, 0xcd, 0x27, 0xd8, 0x25, 0x68, 0x2c, 0x81 };
	unsigned char plain3[3*AES_BLOCK_SIZE] =
		"This is a 48-byte message (exactly 3 AES blocks)";
	unsigned char cipher3[3*AES_BLOCK_SIZE] = {
		0xd0, 0xa0, 0x2b, 0x38, 0x36, 0x45, 0x17, 0x53,
		0xd4, 0x93, 0x66, 0x5d, 0x33, 0xf0, 0xe8, 0x86,
		0x2d, 0xea, 0x54, 0xcd, 0xb2, 0x93, 0xab, 0xc7,
		0x50, 0x69, 0x39, 0x27, 0x67, 0x72, 0xf8, 0xd5,
		0x02, 0x1c, 0x19, 0x21, 0x6b, 0xad, 0x52, 0x5c,
		0x85, 0x79, 0x69, 0x5d, 0x83, 0xba, 0x26, 0x84 };
	unsigned char key4[16] = {
		0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74,
		0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49 };
	unsigned char iv4[16] = {
		0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c,
		0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9 };
	unsigned char plain4[4*AES_BLOCK_SIZE] = {
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
		0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf };
	unsigned char cipher4[4*AES_BLOCK_SIZE] = {
		0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e,
		0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f, 0x71, 0xaa,
		0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6,
		0x84, 0xdb, 0x20, 0x7e, 0xb0, 0xef, 0x8e, 0x4e,
		0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf,
		0x86, 0x8b, 0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad,
		0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d,
		0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55 };
	AES_KEY ekey, dkey;
	unsigned char buf[4*AES_BLOCK_SIZE];

	AES_set_encrypt_key(key1, 128, &ekey);
	AES_set_decrypt_key(key1, 128, &dkey);
	rose_cbc_encrypt(buf, plain1, AES_BLOCK_SIZE, iv1, &ekey);
	assert(!memcmp(buf, cipher1, AES_BLOCK_SIZE));
	rose_cbc_decrypt(buf, cipher1, AES_BLOCK_SIZE, iv1, &dkey);
	assert(!memcmp(buf, plain1, AES_BLOCK_SIZE));

	AES_set_encrypt_key(key2, 128, &ekey);
	AES_set_decrypt_key(key2, 128, &dkey);
	rose_cbc_encrypt(buf, plain2, AES_BLOCK_SIZE, iv2, &ekey);
	assert(!memcmp(buf, cipher2, AES_BLOCK_SIZE));
	rose_cbc_decrypt(buf, cipher2, AES_BLOCK_SIZE, iv2, &dkey);
	assert(!memcmp(buf, plain2, AES_BLOCK_SIZE));

	AES_set_encrypt_key(key3, 128, &ekey);
	AES_set_decrypt_key(key3, 128, &dkey);
	rose_cbc_encrypt(buf, plain3, AES_BLOCK_SIZE, iv3, &ekey);
	assert(!memcmp(buf, cipher3, AES_BLOCK_SIZE));
	rose_cbc_decrypt(buf, cipher3, AES_BLOCK_SIZE, iv3, &dkey);
	assert(!memcmp(buf, plain3, AES_BLOCK_SIZE));

	AES_set_encrypt_key(key4, 128, &ekey);
	AES_set_decrypt_key(key4, 128, &dkey);
	rose_cbc_encrypt(buf, plain4, AES_BLOCK_SIZE, iv4, &ekey);
	assert(!memcmp(buf, cipher4, AES_BLOCK_SIZE));
	rose_cbc_decrypt(buf, cipher4, AES_BLOCK_SIZE, iv4, &dkey);
	assert(!memcmp(buf, plain4, AES_BLOCK_SIZE));

	return 0;
}
#endif

/*
 * pathname handling
 */

/* Encrypt file or directory name (without path); no zero terminations.
 * Returns number of characters written, or negative errno. */
static ssize_t
rose_name_encrypt(char *dst, size_t dstsz, const char *src, size_t srcsz,
                  struct rose_ctx *ctx)
{
	unsigned char buf[NAME_MAX];
	size_t pad;

	if (srcsz == 0)
		return 0;
	if (src[0] == '.' && (srcsz == 1 || (srcsz == 2 && src[1] == '.'))) {
		if (dstsz < srcsz)
			return -ENAMETOOLONG;
		memcpy(dst, src, srcsz);
		return srcsz;
	}

	pad = (AES_BLOCK_SIZE - srcsz % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
	if (srcsz + pad > sizeof(buf))
		return -ENAMETOOLONG;
	memcpy(buf, src, srcsz);
	if (pad)
		memset(buf + srcsz, 0, pad);
	rose_cbc_encrypt(buf, buf, srcsz + pad, zeroes, &ctx->name_ekey);
	return rose_base32_encode(dst, dstsz, buf, srcsz + pad);
}

/* Decrypt file or directory name (without path); no zero terminations.
 * Returns number of characters written, or negative errno. */
static ssize_t
rose_name_decrypt(char *dst, size_t dstsz, const char *src, size_t srcsz,
                  struct rose_ctx *ctx)
{
	unsigned char buf[NAME_MAX];
	ssize_t n;

	if (srcsz == 0)
		return 0;
	if (src[0] == '.' && (srcsz == 1 || (srcsz == 2 && src[1] == '.'))) {
		if (dstsz < srcsz)
			return -ENAMETOOLONG;
		memcpy(dst, src, srcsz);
		return srcsz;
	}

	n = rose_base32_decode(buf, sizeof(buf), src, srcsz);
	if (n < 0)
		return n;
	if (n == 0 || n % AES_BLOCK_SIZE != 0)
		return -EINVAL;
	rose_cbc_decrypt(buf, buf, n, zeroes, &ctx->name_dkey);
	while (n && !buf[n-1])
		n--;
	if (n > (ssize_t)dstsz)
		return -ENAMETOOLONG;
	memcpy(dst, buf, n);
	return n;
}

/* Encrypt path, relative or absolute; no null terminations.
 * Returns number of characters written, or negative errno. */
static ssize_t
rose_path_encrypt(char *dst, size_t dstsz, const char *src, size_t srcsz,
                  struct rose_ctx *ctx)
{
	ssize_t n;
	char *d;
	const char *s, *se, *p;

	d = dst;
	s = src; se = src + srcsz;
	p = src;
	while (p < se) {
		while (p < se && *p != '/') p++;
		n = rose_name_encrypt(d, dstsz - (d - dst), s, p - s, ctx);
		if (n < 0)
			return n;
		d += n;
		if (p == se)
			return (d - dst);
		if (d - dst == (ptrdiff_t)dstsz)
			return -ENAMETOOLONG;
		*(d++) = '/';
		s = ++p;
	}
	return (d - dst);
}

/* Decrypt path, relative or absolute; no null terminations.
 * Returns number of characters written, or negative errno. */
static ssize_t
rose_path_decrypt(char *dst, size_t dstsz, const char *src, size_t srcsz,
                  struct rose_ctx *ctx)
{
	ssize_t n;
	char *d;
	const char *s, *se, *p;

	d = dst;
	s = src; se = src + srcsz;
	p = src;
	while (p < se) {
		while (p < se && *p != '/') p++;
		n = rose_name_decrypt(d, dstsz - (d - dst), s, p - s, ctx);
		if (n < 0)
			return n;
		d += n;
		if (p == se)
			return (d - dst);
		if (d - dst == (ptrdiff_t)dstsz)
			return -ENAMETOOLONG;
		*(d++) = '/';
		s = ++p;
	}
	return (d - dst);
}

/* Translates absolute plain path into absolute encrypted path.
 * Encrypted backend-path will be null-terminated.
 * Returns number of characters written, including terminating null. */
static ssize_t
rose_path_xlate(char *dst, size_t dstsz, const char *src, struct rose_ctx *ctx)
{
	ssize_t n;

	if (dstsz-- <= ctx->backendsz)
		return -ENAMETOOLONG;
	memcpy(dst, ctx->backend, ctx->backendsz);
	n = rose_path_encrypt(dst + ctx->backendsz, dstsz - ctx->backendsz,
			src, strlen(src), ctx);
	if (n < 0)
		return n;
	dst[ctx->backendsz + n] = '\0';
	return (ctx->backendsz + n + 1);
}


/*
 * FUSE operations: directory
 */

/* Create a directory */
int
rose_op_mkdir(const char *path, mode_t mode)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;
	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (mkdir(bepath, mode) == -1)
		return -errno;
	return 0;
}

/* Remove a directory */
int
rose_op_rmdir(const char *path)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;
	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (rmdir(bepath) == -1)
		return -errno;
	return 0;
}

/* Open directory */
int
rose_op_opendir(const char *path, struct fuse_file_info *fi)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	struct rose_dctx *dctx;
	DIR *dirp;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;

	if (!(dirp = opendir(bepath)))
		return -errno;

	dctx = malloc(sizeof(struct rose_dctx));
	if (!dctx)
		return -ENOMEM;
	dctx->dirp = dirp;
	fi->fh = (uintptr_t) dctx;
	return 0;
}

/* Read directory */
int
rose_op_readdir(const char *path UNUSED, void *buf, fuse_fill_dir_t fill,
                off_t off, struct fuse_file_info *fi)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	struct rose_dctx *dctx = (struct rose_dctx *) fi->fh;
	char name[NAME_MAX + 1];
	struct dirent *de;
	struct stat st;
	ssize_t n;

	if (!ctx)
		return -ENXIO;
	if (!dctx)
		return -EBADF;

	seekdir(dctx->dirp, off);
	while ((de = readdir(dctx->dirp))) {
		if (de->d_name[0] == '.' &&
		    de->d_name[1] != '\0' &&
		    de->d_name[1] != '.')
			continue; /* skip RoseFS config files */
		n = rose_name_decrypt(name, sizeof(name) - 1,
		                      de->d_name, strlen(de->d_name), ctx);
		if (n < 0)
			return n;
		name[n] = '\0';
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = DTTOIF(de->d_type);
		if (fill(buf, name, &st, telldir(dctx->dirp)))
			break;
	}
	return 0;
}

/* Release directory
 * Error probably ignored too, like release(). */
int
rose_op_releasedir(const char *path UNUSED, struct fuse_file_info *fi)
{
	struct rose_dctx *dctx = (struct rose_dctx *) fi->fh;
	int rv;

	if (!dctx)
		return -EBADF;

	rv = closedir(dctx->dirp);
	free(dctx);
	return ((rv == -1) ? -errno : 0);
}

/* Synchronize directory contents */
int
rose_op_fsyncdir(const char *path UNUSED, int data UNUSED,
                 struct fuse_file_info *fi UNUSED)
{
	return 0;
}


/*
 * FUSE operations: file
 */

/* Get attributes from an open file */
int
rose_op_fgetattr(const char *path UNUSED, struct stat *buf,
                 struct fuse_file_info *fi)
{
	struct rose_fctx *fctx = (struct rose_fctx*) fi->fh;

	if (!fctx)
		return -EBADF;

	if (fstat(fctx->fd, buf) == -1)
		return -errno;

	if (S_ISREG(buf->st_mode)) {
		buf->st_size -= AES_BLOCK_SIZE;
		assert(fctx->vsize == buf->st_size);
	}

	return 0;
}

/* Get file attributes */
int
rose_op_getattr(const char *path, struct stat *st)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;

	if (lstat(bepath, st) == -1)
		return -errno;

	if (S_ISREG(st->st_mode))
		st->st_size -= AES_BLOCK_SIZE;

	return 0;
}

/* Change the size of an open file */
int
rose_op_ftruncate(const char *path UNUSED, off_t off,
                  struct fuse_file_info *fi)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	struct rose_fctx *fctx = (struct rose_fctx *) fi->fh;
	unsigned char chunk[CHUNK_SIZE];
	ssize_t n;
	off_t chunksz;

	if (!ctx)
		return -ENXIO;
	if (!fctx)
		return -EBADF;

	assert(fctx->nonce); /* regular file */

	if (ftruncate(fctx->fd, off + AES_BLOCK_SIZE) == -1)
		return -errno;

	/* fill sparse file holes with encrypted zeroes */
	while (off > fctx->vsize) {
		chunksz = off - fctx->vsize;
		if ((off_t)sizeof(chunk) < chunksz)
			chunksz = sizeof(chunk);
		rose_ctr_crypt(chunk, zeroes, chunksz, fctx->vsize,
		               fctx->nonce, &ctx->data_ekey);
		n = pwrite(fctx->fd, chunk, chunksz,
		           fctx->vsize + AES_BLOCK_SIZE);
		if (n < chunksz)
			return -EIO;
		fctx->vsize += chunksz;
	}
	fctx->vsize = off;

	return 0;
}

/* Change the size of a file */
int
rose_op_truncate(const char *path, off_t off)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	struct stat st;
	unsigned char chunk[CHUNK_SIZE];
	ssize_t n;
	off_t chunksz, vpos;
	unsigned char nonce[AES_BLOCK_SIZE];
	int fd;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;

	if (lstat(bepath, &st) == -1)
		return -errno;

	if (!S_ISREG(st.st_mode))
		return 0;

	if (truncate(bepath, off + AES_BLOCK_SIZE) == -1)
		return -errno;

	/* fill sparse file holes with encrypted zeroes */
	if (off + AES_BLOCK_SIZE > st.st_size) {
		vpos = st.st_size - AES_BLOCK_SIZE;

		if ((fd = open(bepath, O_RDWR)) == -1)
			return -EIO;
		if (pread(fd, nonce, AES_BLOCK_SIZE, 0) < AES_BLOCK_SIZE) {
			close(fd);
			return -EIO;
		}
		while (off > vpos) {
			chunksz = off - vpos;
			if ((off_t)sizeof(chunk) < chunksz)
				chunksz = sizeof(chunk);
			rose_ctr_crypt(chunk, zeroes, chunksz, vpos, nonce,
			               &ctx->data_ekey);
			n = pwrite(fd, chunk, chunksz, vpos + AES_BLOCK_SIZE);
			if (n < chunksz) {
				close(fd);
				return -EIO;
			}
			vpos += chunksz;
		}
		close(fd);
	}

	return 0;
}

/* Release an open file
 * For every open, there will be exactly one release call.
 * Return value is ignored, it is not possible to return an error. */
int
rose_op_release(const char *path UNUSED, struct fuse_file_info *fi)
{
	struct rose_fctx *fctx = (struct rose_fctx *) fi->fh;
	int rv;

	if (!fctx)
		return -EBADF;

	rv = close(fctx->fd);
	if (fctx->nonce)
		free(fctx->nonce);
	free(fctx);

	return ((rv == -1) ? -errno : 0);
}

/* File open operation
 * O_CREAT, O_EXCL, O_TRUNC are never passed to open() by default */
int
rose_op_open(const char *path, struct fuse_file_info *fi)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	struct rose_fctx *fctx;
	struct stat st;
	char bepath[PATH_MAX + 1];
	unsigned char *nonce = NULL;
	off_t size = 0;
	ssize_t n;
	int fd;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;

	if (fi->flags & O_WRONLY)
		fi->flags ^= O_WRONLY ^ O_RDWR;

	if ((fd = open(bepath, fi->flags)) == -1)
		return -errno;

	fstat(fd, &st);
	if (S_ISREG(st.st_mode)) {
		assert(st.st_size >= AES_BLOCK_SIZE);
		size = st.st_size - AES_BLOCK_SIZE;
		nonce = malloc(AES_BLOCK_SIZE);
		if (!nonce) {
			close(fd);
			return -ENOMEM;
		}
		if (pread(fd, nonce, AES_BLOCK_SIZE, 0) < AES_BLOCK_SIZE) {
			free(nonce);
			return -EIO;
		}
	}

	fctx = malloc(sizeof(struct rose_fctx));
	if (!fctx) {
		close(fd);
		return -ENOMEM;
	}
	fctx->fd = fd;
	fctx->vsize = size;
	fctx->nonce = nonce;
	fi->fh = (uintptr_t) fctx;
	return 0;
}

/* Create and open a file */
int
rose_op_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	struct rose_fctx *fctx;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	assert(S_ISREG(mode));

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;

	fctx = malloc(sizeof(struct rose_fctx));
	if (!fctx)
		return -ENOMEM;
	fctx->nonce = malloc(AES_BLOCK_SIZE);
	if (!fctx->nonce) {
		free(fctx);
		return -ENOMEM;
	}
	rose_random(fctx->nonce, AES_BLOCK_SIZE);
	fctx->vsize = 0;

	if ((fctx->fd = open(bepath, fi->flags, mode)) == -1) {
		free(fctx->nonce);
		free(fctx);
		return -errno;
	}

	if (pwrite(fctx->fd, fctx->nonce, AES_BLOCK_SIZE, 0)<AES_BLOCK_SIZE) {
		close(fctx->fd);
		free(fctx->nonce);
		free(fctx);
		return -EIO;
	}

	fi->fh = (uintptr_t) fctx;
	return 0;
}

/* Create a file node (non-dir, non-symlink)
 * if create is implemented, for regular files, create will called instead */
int
rose_op_mknod(const char *path, mode_t mode, dev_t dev)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	assert(!S_ISREG(mode));
	assert(!S_ISDIR(mode));
	assert(!S_ISLNK(mode));

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (mknod(bepath, mode, dev) == -1)
		return -errno;
	return 0;
}

/* Read data from an open file */
int
rose_op_read(const char *path UNUSED, char *buf, size_t count, off_t off,
             struct fuse_file_info *fi)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	struct rose_fctx *fctx = (struct rose_fctx *) fi->fh;
	off_t physoff = off;
	ssize_t n;

	if (!ctx)
		return -ENXIO;
	if (!fctx)
		return -EBADF;

	if (fctx->nonce) {
		physoff += AES_BLOCK_SIZE;
	}

	n = pread(fctx->fd, buf, count, physoff);

	if (fctx->nonce) {
		rose_ctr_crypt((unsigned char *) buf, (unsigned char *) buf,
		               count, off, fctx->nonce, &ctx->data_ekey);
	}

	return ((n == -1) ? -errno : n);
}

/* Write data to an open file */
int
rose_op_write(const char *path UNUSED, const char *buf, size_t count,
              off_t off, struct fuse_file_info *fi)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	struct rose_fctx *fctx = (struct rose_fctx *) fi->fh;
	unsigned char chunk[CHUNK_SIZE];
	ssize_t n, written;
	off_t chunksz;

	if (!ctx)
		return -ENXIO;
	if (!fctx)
		return -EBADF;

	assert(count <= SIZE_MAX/2);

	if (fctx->nonce) {
		/* fill sparse file holes with encrypted zeroes */
		while (off > fctx->vsize) {
			chunksz = off - fctx->vsize;
			if ((off_t)sizeof(chunk) < chunksz)
				chunksz = sizeof(chunk);
			rose_ctr_crypt(chunk, zeroes, chunksz, fctx->vsize,
			               fctx->nonce, &ctx->data_ekey);
			n = pwrite(fctx->fd, chunk, chunksz,
			           fctx->vsize + AES_BLOCK_SIZE);
			if (n < chunksz)
				return (n == -1) ? -errno : 0;
			fctx->vsize += chunksz;
		}

		written = 0;
		while (written < (ssize_t)count) {
			chunksz = count - written;
			if ((off_t)sizeof(chunk) < chunksz)
				chunksz = sizeof(chunk);
			rose_ctr_crypt(chunk, (unsigned char *)(buf+written),
			               chunksz, off+written, fctx->nonce,
			               &ctx->data_ekey);
			n = pwrite(fctx->fd, chunk, chunksz,
			           off+written + AES_BLOCK_SIZE);
			if (n < chunksz)
				return (n == -1) ? -errno : n+written;
			written += chunksz;
		}
		if (fctx->vsize < off + (ssize_t)count)
			fctx->vsize = off + (ssize_t)count;
	} else { /* !fctx->nonce */
		written = pwrite(fctx->fd, buf, count, off);
		if (written < (ssize_t)count)
			return ((written == -1) ? -errno : written);
	}

	return written;
}

/* Possibly flush cached data */
int
rose_op_flush(const char *path UNUSED, struct fuse_file_info *fi UNUSED)
{
	return 0;
}

/* Synchronize file contents */
int
rose_op_fsync(const char *path UNUSED, int data, struct fuse_file_info *fi)
{
	struct rose_fctx *fctx = (struct rose_fctx *) fi->fh;

	if (!fctx)
		return -EBADF;

	if ((data ? fdatasync(fctx->fd) : fsync(fctx->fd)) == -1)
		return -errno;
	return 0;
}


/*
 * FUSE operations: misc operations on files and directories
 */

/* Read the target of a symbolic link */
int
rose_op_readlink(const char *path, char *buf, size_t bufsz)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	char linkdata[PATH_MAX];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if ((n = readlink(bepath, linkdata, sizeof(linkdata))) == -1)
		return -errno;
	if ((n = rose_path_decrypt(buf, bufsz, linkdata, n, ctx)) < 0)
		return n;
	return 0;
}

/* Create a symbolic link */
int
rose_op_symlink(const char *linkpath, const char *path)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	char belinkpath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_encrypt(belinkpath, sizeof(belinkpath) - 1,
	                           linkpath, strlen(linkpath), ctx)) < 0)
		return n;
	belinkpath[n] = '\0';
	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (symlink(belinkpath, bepath) == -1)
		return -errno;
	return 0;
}

/* Rename a file */
int
rose_op_rename(const char *opath, const char *npath)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char beopath[PATH_MAX + 1];
	char benpath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(beopath, sizeof(beopath), opath, ctx)) < 0)
		return n;
	if ((n = rose_path_xlate(benpath, sizeof(benpath), npath, ctx)) < 0)
		return n;
	if (rename(beopath, benpath) == -1)
		return -errno;
	return 0;
}

/* Create a hard link to a file */
int
rose_op_link(const char *linkpath, const char *path)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	char belinkpath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(belinkpath, sizeof(belinkpath),
	                         linkpath, ctx)) < 0)
		return n;
	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (link(belinkpath, bepath) == -1)
		return -errno;
	return 0;
}

/* Remove a file */
int
rose_op_unlink(const char *path)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (unlink(bepath) == -1)
		return -errno;
	return 0;
}

/* Check file access permissions */
int
rose_op_access(const char *path, int mode)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (access(bepath, mode) == -1)
		return -errno;
	return 0;
}

/* Change the permission bits of a file */
int
rose_op_chmod(const char *path, mode_t mode)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (chmod(bepath, mode) == -1)
		return -errno;
	return 0;
}

/* Change the owner and group of a file */
int
rose_op_chown(const char *path, uid_t uid, gid_t gid)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (chown(bepath, uid, gid) == -1)
		return -errno;
	return 0;
}

/* Change the access and modification times of a file */
int
rose_op_utime(const char *path, struct utimbuf *ut)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (utime(bepath, ut) == -1)
		return -errno;
	return 0;
}


#if 0
/*
 * FUSE operations: extended attributes
 *
 * The code below is plain, unencrypted passthrough.
 * It extended attribute support is omitted, then MacOS X
 * will fall back to ._* files to store the attributes
 * (which will be encrypted by RoseFS as normal files).
 * TODO add extended attribute data and name encryption.
 *
 * com.apple.ResourceFork - offset, encrypt + rename
 * com.apple.TextEncoding - encrypt + rename
 * com.apple.quarantine - encrypt + rename
 */

#ifdef __APPLE__
/* Set extended attributes */
int
rose_op_setxattr(const char *path, const char *name, const char *value,
                 size_t size, int flags, uint32_t pos)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (setxattr(bepath, name, value, size, pos, flags) == -1)
		return -errno;
	return 0;
}

/* Get extended attributes */
int
rose_op_getxattr(const char *path, const char *name, char *value,
                 size_t size, uint32_t pos)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if ((n = getxattr(bepath, name, value, size, pos,
	                  XATTR_NOFOLLOW)) == -1)
		return -errno;
	return n;
}

/* List extended attributes */
int
rose_op_listxattr(const char *path, char *list, size_t size)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if ((n = listxattr(bepath, list, size, XATTR_NOFOLLOW)) == -1)
		return -errno;
	return n;
}

/* Remove extended attributes */
int
rose_op_removexattr(const char *path, const char *name)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (removexattr(bepath, name, XATTR_NOFOLLOW) == -1)
		return -errno;
	return 0;
}
#else /* __APPLE__ */
#error Not implemented
#endif /* __APPLE__ */
#endif


/*
 * FUSE operations: filesystem
 */

/* Initialize filesystem
 * Return value will be passed in private_data to all operations. */
void *
rose_op_init(struct fuse_conn_info *conn UNUSED)
{
	struct rose_ictx *ictx = (struct rose_ictx *) FUSE_CTX;
	struct rose_ctx *ctx;

	if (!ictx)
		return NULL;

	rose_random_init();

	ctx = malloc(sizeof(struct rose_ctx));
	if (!ctx) {
		free(ictx->backend);
		goto leave;
	}

	ctx->backend = ictx->backend;
	ctx->backendsz = strlen(ctx->backend);
	AES_set_encrypt_key(ictx->name_keybuf, KEY_BITS, &ctx->name_ekey);
	AES_set_decrypt_key(ictx->name_keybuf, KEY_BITS, &ctx->name_dkey);
	AES_set_encrypt_key(ictx->data_keybuf, KEY_BITS, &ctx->data_ekey);

leave:
	free(ictx);
	return ctx;
}

/* Clean up filesystem */
void
rose_op_destroy(void *stuff)
{
	struct rose_ctx *ctx = (struct rose_ctx *) stuff;

	if (!ctx)
		return;

	free(ctx->backend);
	free(ctx);
	return;
}

/* Get file system statistics */
int
rose_op_statfs(const char *path, struct statvfs *stat)
{
	struct rose_ctx *ctx = (struct rose_ctx *) FUSE_CTX;
	char bepath[PATH_MAX + 1];
	ssize_t n;

	if (!ctx)
		return -ENXIO;

	if ((n = rose_path_xlate(bepath, sizeof(bepath), path, ctx)) < 0)
		return n;
	if (statvfs(bepath, stat) == -1)
		return -errno;

	/* XXX modify f_namemax f_fbrsize f_bsize
	 * and consider using pathconf() */

	return 0;
}


/*
 * FUSE glue
 */
struct fuse_operations rose_oper = {
	.access		= rose_op_access,
	.chmod		= rose_op_chmod,
	.chown		= rose_op_chown,
	.create		= rose_op_create,
	.destroy	= rose_op_destroy,
	.fgetattr	= rose_op_fgetattr,
	.flush		= rose_op_flush,
	.fsync		= rose_op_fsync,
	.fsyncdir	= rose_op_fsyncdir,
	.ftruncate	= rose_op_ftruncate,
	.getattr	= rose_op_getattr,
/*	.getxattr	= rose_op_getxattr, */
	.init		= rose_op_init,
/*	.ioctl		= rose_op_ioctl, */
	.link		= rose_op_link,
/*	.listxattr	= rose_op_listxattr, */
	.mkdir		= rose_op_mkdir,
	.mknod		= rose_op_mknod,
	.open		= rose_op_open,
	.opendir	= rose_op_opendir,
/*	.poll		= rose_op_poll, */
	.read		= rose_op_read,
	.readdir	= rose_op_readdir,
	.readlink	= rose_op_readlink,
	.release	= rose_op_release,
	.releasedir	= rose_op_releasedir,
/*	.removexattr	= rose_op_removexattr, */
	.rename		= rose_op_rename,
	.rmdir		= rose_op_rmdir,
/*	.setxattr	= rose_op_setxattr, */
	.statfs		= rose_op_statfs,
	.symlink	= rose_op_symlink,
	.truncate	= rose_op_truncate,
	.unlink		= rose_op_unlink,
	.utime		= rose_op_utime,
	.write		= rose_op_write,
};


/*
 * Entry point and backend loading.
 */

/* Read some bytes from a file, used for configuration files.
 * Pathbuf must be slash-terminated.
 * Returns number of characters read, or a negative errno. */
static ssize_t
rose_read_file(unsigned char *buf, size_t bufsz,
               const char *pathbuf, const char *filename) {
	char fn[PATH_MAX];
	ssize_t n;
	int fd;

	n = snprintf(fn, sizeof(fn), "%s%s", pathbuf, filename);
	if (n >= (ssize_t)sizeof(fn))
		return -ENAMETOOLONG;
	if (n == -1)
		return -errno;

	fd = open(fn, O_RDONLY);
	if (fd == -1)
		return -errno;

	n = read(fd, buf, bufsz);
	if (n == -1) {
		close(fd);
		return -errno;
	}

	close(fd);
	return n;
}

/* Write some bytes to a file, used for configuration files.
 * Pathbuf must be slash-terminated.
 * Returns number of characters written, or a negative errno. */
static ssize_t
rose_write_file(const unsigned char *buf, size_t bufsz,
                const char *pathbuf, const char *filename) {
	char fn[PATH_MAX];
	ssize_t n;
	int fd;

	n = snprintf(fn, sizeof(fn), "%s%s", pathbuf, filename);
	if (n >= (ssize_t)sizeof(fn))
		return -ENAMETOOLONG;
	if (n == -1)
		return -errno;

	fd = open(fn, O_WRONLY|O_TRUNC|O_CREAT, 0400);
	if (fd == -1)
		return -errno;

	n = write(fd, buf, bufsz);
	if (n == -1) {
		close(fd);
		return -errno;
	}

	close(fd);
	return n;
}

/* Initialize an empty directory for use as RoseFS backend.
 * Returns 0 on success, negated error value on error. */
static int
rose_backend_initialize(const char *backend)
{
	unsigned char vstr[] = "RoseFS/" Q(ROSE_VER) "." Q(ROSE_REV) "\n";
	unsigned char salt[KEY_SIZE];
	ssize_t rv;

	rose_random_init();

	rv = rose_write_file(vstr, sizeof(vstr) - 1, backend, ".version");
	if (rv < 0)
		return rv;
	if (rv < (ssize_t)(sizeof(vstr) - 1))
		return -EIO;

	rose_random(salt, KEY_SIZE);
	rv = rose_write_file(salt, sizeof(salt), backend, ".name_salt");
	if (rv < 0)
		return rv;
	if (rv < (ssize_t)sizeof(salt))
		return -EIO;

	rose_random(salt, KEY_SIZE);
	rv = rose_write_file(salt, sizeof(salt), backend, ".data_salt");
	if (rv < 0)
		return rv;
	if (rv < (ssize_t)sizeof(salt))
		return -EIO;

	/* XXX write more files here */

	memset(salt, 0, sizeof(salt));
	return 0;
}

/* Load an existing RoseFS backend, generate keys and fill ictx.
 * Returns 0 on success, negated error value on error. */
static int
rose_backend_load(struct rose_ictx *ictx, const char *backend,
                  const char *passwd)
{
	unsigned char salt[KEY_SIZE];
	size_t passwdsz;
	ssize_t rv;

	passwdsz = strlen(passwd);

	rv = rose_read_file(salt, sizeof(salt), backend, ".name_salt");
	if (rv < (ssize_t)sizeof(salt))
		return rv;
	rose_pkcs5_pbkdf2(ictx->name_keybuf, sizeof(ictx->name_keybuf),
	                  passwd, passwdsz, salt, sizeof(salt), PBKDF2_ROUNDS);

	/* XXX verify key against .name_chk := ^^uint32 of SHA256 of key */

	rv = rose_read_file(salt, sizeof(salt), backend, ".data_salt");
	if (rv < (ssize_t)sizeof(salt))
		return rv;
	rose_pkcs5_pbkdf2(ictx->data_keybuf, sizeof(ictx->data_keybuf),
	                  passwd, passwdsz, salt, sizeof(salt), PBKDF2_ROUNDS);

	/* XXX verify key against .data_chk := ^^uint32 of SHA256 of key */

	/* XXX read global IV for filenames */

	passwdsz = 0;
	memset(salt, 0, sizeof(salt));
	return 0;
}

/* perform self-tests of crypto primitives */
void
rose_selftest(void)
{
	assert(!rose_hmac_sha256_test());
	assert(!rose_pkcs5_pbkdf2_test());
	assert(!rose_cbc_test());
	assert(!rose_ctr_test());
	assert(!rose_base32_test());
}

/* The actual entry point. */
int
main(int argc, char *argv[])
{
	char enomem_msg[] = "Out of memory\n";
	unsigned char versionbuf[20] = { 0 };
	char pathbuf[PATH_MAX];
	size_t pathlen;
	struct stat st;
	DIR *dirp;
	int rv, ver, rev;
	char *passwd;
	struct rose_ictx *ictx;

	rose_selftest();

	/* verify arguments */
	if (argc < 3) {
		printf("RoseFS %u (rev %u)\n\n", ROSE_VER, ROSE_REV);
		char *argv[] = { "rosefs backend", "-h" };
		return fuse_main(2, argv, &rose_oper, NULL);
	}

	umask(0);

	/* verify backend filesystem directory, create if necessary */
	realpath(argv[1], pathbuf);
	pathlen = strlen(pathbuf);
	if (pathlen + 2 >= PATH_MAX) {
		fprintf(stderr, "%s - %s\n", pathbuf, strerror(ENAMETOOLONG));
		return EXIT_FAILURE;
	}
	if (pathbuf[pathlen - 1] != '/') {
		strcat(pathbuf, "/");
		pathlen++;
	}
	if (lstat(pathbuf, &st) == -1) {
		if (errno == ENOENT) {
			if (mkdir(pathbuf, 0700) == -1) {
				fprintf(stderr, "%s - %s\n", pathbuf,
				        strerror(errno));
				return EXIT_FAILURE;
			}
		} else {
			fprintf(stderr, "%s - %s\n", pathbuf, strerror(errno));
			return EXIT_FAILURE;
		}
	} else if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "%s - %s\n", pathbuf, strerror(ENOTDIR));
		return EXIT_FAILURE;
	}

	/* read and verify version of backend directory */
	rv = rose_read_file(versionbuf, sizeof(versionbuf) - 1,
	                    pathbuf, ".version");
	if (rv == -ENOENT) {
		/* initialize filesystem if empty directory */
		if (!(dirp = opendir(pathbuf))) {
			fprintf(stderr, "%s vanished - %s\n",
			        pathbuf, strerror(errno));
			return EXIT_FAILURE;
		}
		if (readdir(dirp) && readdir(dirp) && readdir(dirp)) {
			fprintf(stderr, "%s is neither a backend nor empty.\n"
			                "Please supply an empty directory.\n",
			                pathbuf);
			closedir(dirp);
			return EXIT_FAILURE;
		}
		closedir(dirp);
		printf("%s is empty.\n"
		       "Press enter to initialize new backend or ^C to abort.",
		       pathbuf);
		fflush(stdout);
		getpass("");
		rv = rose_backend_initialize(pathbuf);
		if (rv < 0) {
			fprintf(stderr, "initializing %s - %s\n",
			        pathbuf, strerror(-rv));
			return EXIT_FAILURE;
		}
		printf("Initialized RoseFS/%d.%d backend.\n",
		       ROSE_VER, ROSE_REV);
		fflush(stdout);
	} else if (rv < 0) {
		fprintf(stderr, "%s.version - %s\n", pathbuf, strerror(-rv));
		return EXIT_FAILURE;
	} else {
		/* verify version string */
		if (!sscanf((char*)versionbuf, "RoseFS/%d.%d", &ver, &rev)) {
			fprintf(stderr, "%s is not a RoseFS backend.\n",
				pathbuf);
			return EXIT_FAILURE;
		}
		if (ver != ROSE_VER) {
			/* find a matching rosefs */
			fprintf(stderr, "RoseFS backend version %d found.\n"
			                "This binary supports version %d.\n"
			                "Executing rosefs%d...\n",
			                ver, ROSE_VER, ver);
			snprintf(pathbuf, sizeof(pathbuf), "rosefs%d", ver);
			execvp(pathbuf, argv);
			if (errno != ENOENT) {
				fprintf(stderr, "executing %s - %s", pathbuf,
				        strerror(errno));
				return EXIT_FAILURE;
			}
			execvP(pathbuf, ROSE_PATH, argv);
			if (errno != ENOENT) {
				fprintf(stderr, "executing %s - %s", pathbuf,
				        strerror(errno));
				return EXIT_FAILURE;
			}
			fprintf(stderr, "%s was not found in PATH or '%s'.\n"
				"No compatible version of RoseFS found.\n",
				pathbuf, ROSE_PATH);
			return EXIT_FAILURE;
		}
	}

	/* read passphrase and prepare keys */
	ictx = malloc(sizeof(struct rose_ictx));
	if (!ictx) {
		goto leave_enomem;
	}
	ictx->backend = malloc(pathlen + 1);
	if (!ictx->backend) {
		free(ictx);
		goto leave_enomem;
	}
	strncpy(ictx->backend, pathbuf, pathlen);
	ictx->backend[pathlen] = '\0';

	passwd = getpass("RoseFS Passphrase: ");
	if (!passwd) {
		free(ictx->backend);
		free(ictx);
		goto leave_enomem;
	}
	rv = rose_backend_load(ictx, pathbuf, passwd);
	rose_strzero(passwd);
	if (rv < 0) {
		free(ictx->backend);
		free(ictx);
		fprintf(stderr, "loading %s - %s\n", pathbuf, strerror(rv));
		return EXIT_FAILURE;
	}

	argv[1] = argv[0];
	return fuse_main(argc - 1, argv + 1, &rose_oper, ictx);

leave_enomem:
	write(2, enomem_msg, sizeof(enomem_msg));
	return EXIT_FAILURE;
}


