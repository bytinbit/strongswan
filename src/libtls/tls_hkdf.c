/*
 * Copyright (C) 2020 Pascal Knecht
 * Copyright (C) 2020 Méline Sieber
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "tls_hkdf.h"
#include <utils/chunk.h>
#include <library.h>
#include <crypto/prf_plus.h>

typedef struct private_tls_hkdf_t private_tls_hkdf_t;

typedef enum hkdf_phase {
	HKDF_PHASE_0,
	HKDF_PHASE_1,
	HKDF_PHASE_2,
	HKDF_PHASE_3,
} hkdf_phase;

struct private_tls_hkdf_t {

	/**
	 * Public tls_hkdf_t interface.
	 */
	struct tls_hkdf_t public;

	/**
	 * Phase we are in.
	 */
	hkdf_phase phase;

	/**
	 * Hash algorithm used.
	 */
	hash_algorithm_t hash_algorithm;

	/**
	 * Length of this hash output in bytes.
	 */
	size_t hash_length;

	/**
	 * Preshared key IKM
	 */
	chunk_t *psk;

	/**
	 * (EC)DHE IKM
	 */
	chunk_t *shared_secret;

	/**
	 * Pseudorandom function used.
	 */
	prf_t *prf;

	/**
	 * Pseudorandom plus function used.
	 */
	prf_plus_t *prf_plus;

	/**
	 * Hasher used.
	 */
	hasher_t *hasher;

	/**
	 * Salt used.
	 */
	chunk_t salt;

	/**
	 * IKM used.
	 */
	chunk_t ikm;

	/**
	 * PRK used.
	 */
	chunk_t prk;

	/**
	 * Info used.
	 */
	chunk_t info;

	/**
	 * OKM used.
	 */
	chunk_t okm;

	/**
	 * Length of the desired key output.
	 */
	size_t L;
};

static char *hkdf_labels[] = {
	"tls13 ext binder",
	"tls13 res binder",
	"tls13 c e traffic",
	"tls13 e expt master",
	"tls13 c hs traffic",
	"tls13 s hs traffic",
	"tls13 c ap traffic",
	"tls13 s ap traffic",
	"tls13 exp master",
	"tls13 res master",
};

/* HKDF-Extract(this->salt, this->ikm) -> this->prk */
static bool extract(private_tls_hkdf_t *this, chunk_t *salt, chunk_t *ikm, chunk_t *prk)
{
	if (!this->prf->set_key(this->prf, *salt))
	{
		DBG1(DBG_TLS, "unable to set PRF salt");
		return FALSE;
	}
	chunk_clear(prk);
	if(!this->prf->allocate_bytes(this->prf, *ikm, prk))
	{
		DBG1(DBG_TLS, "unable to allocate PRF space");
		return FALSE;
	}

	DBG3(DBG_TLS, "PRK: %B", prk);

	return TRUE;
}

/* HKDF-Expand(this->prk, this->info, this->L) -> this->okm */
static bool expand(private_tls_hkdf_t *this, chunk_t *prk, chunk_t *info, size_t lenght, chunk_t *okm)
{
	if (!this->prf->set_key(this->prf, *prk))
	{
		DBG1(DBG_TLS, "unable to set PRF PRK");
		chunk_free(&this->info);
		return FALSE;
	}
	DESTROY_IF(this->prf_plus);
	this->prf_plus = prf_plus_create(this->prf, TRUE, *info);
	chunk_clear(&this->okm);
	if (!this->prf_plus->allocate_bytes(this->prf_plus, lenght, okm))
	{
		DBG1(DBG_TLS, "unable to allocate PRF plus space");
		chunk_clear(okm);
		chunk_free(&this->info);
		return FALSE;
	}
	chunk_free(&this->info);

	DBG3(DBG_TLS, "OKM: %B", okm);

	return TRUE;
}

static bool expand_label(private_tls_hkdf_t *this, chunk_t *secret, chunk_t *label, chunk_t *context, uint16_t length, chunk_t *key)
{
	if (label->len < 7 || label->len > 255 ||
		context->len < 0 || context->len > 255)
	{
		chunk_free(context);
		return FALSE;
	}

	/* HKDFLabel */
	size_t offset = 0;
	size_t chunk_len = 2 + 1 + label->len + 1 + context->len;
	this->info = chunk_alloc(chunk_len);
	this->info.ptr[1] = length & 0xFF;
	this->info.ptr[0] = length >> 8;
	this->info.ptr[2] = label->len;
	offset += 3;
	memcpy(&(this->info).ptr[offset], label->ptr, label->len);
	offset += label->len;
	this->info.ptr[offset] = context->len;
	offset += 1;
	memcpy(&(this->info).ptr[offset], context->ptr, context->len);
	offset += context->len;

	expand(this, secret, &this->info, length, key);

	return TRUE;
}

static bool derive_secret(private_tls_hkdf_t *this, chunk_t *label, chunk_t *messages)
{
	size_t chunk_len = this->L;
	chunk_t context = chunk_alloca(chunk_len);

	if (!this->hasher || !this->hasher->allocate_hash(this->hasher, *messages, &context))
	{
		DBG1(DBG_TLS, "%N not supported", hash_algorithm_names, this->hash_algorithm);
		return FALSE;
	}

	DBG3(DBG_TLS, "HASH: %B", &context);

	expand_label(this, &this->prk, label, &context, this->L, &this->okm);

	chunk_free(&context);

	return TRUE;
}

static bool move_to_phase_1(private_tls_hkdf_t *this)
{
	switch (this->phase)
	{
		case HKDF_PHASE_0:
			if (!extract(this, &this->salt, &this->ikm, &this->prk))
			{
				DBG1(DBG_TLS, "unable extract PRK");
				return FALSE;
			}
			this->phase = HKDF_PHASE_1;
			return TRUE;
		case HKDF_PHASE_1:
			return TRUE;
		default:
			DBG1(DBG_TLS, "invalid HKDF phase");
			return FALSE;
	}
}

static bool move_to_phase_2(private_tls_hkdf_t *this)
{
	chunk_t empty, derived;

	switch (this->phase)
	{
		case HKDF_PHASE_0:
			move_to_phase_1(this);
		case HKDF_PHASE_1:
			empty = chunk_empty;
			derived = chunk_from_str("tls13 derived");
			if (!derive_secret(this, &derived, &empty))
			{
				DBG1(DBG_TLS, "unable to derive secret");
				return FALSE;
			}

			if (!this->shared_secret)
			{
				DBG1(DBG_TLS, "no shared secret set");
				return FALSE;
			}
			else
			{
				chunk_free(&this->ikm);
				this->ikm = chunk_alloc(this->shared_secret->len);
				memcpy(this->ikm.ptr, this->shared_secret->ptr, this->shared_secret->len);
				this->ikm.len = this->shared_secret->len;
			}

			if (!extract(this, &this->okm, &this->ikm, &this->prk))
			{
				DBG1(DBG_TLS, "unable extract PRK");
				return FALSE;
			}
			this->phase = HKDF_PHASE_2;
			return TRUE;
		case HKDF_PHASE_2:
			return TRUE;
		default:
			DBG1(DBG_TLS, "invalid HKDF phase");
			return FALSE;
	}
}

static bool move_to_phase_3(private_tls_hkdf_t *this)
{
	chunk_t empty, derived;

	switch (this->phase)
	{
		case HKDF_PHASE_0:
		case HKDF_PHASE_1:
			move_to_phase_2(this);
		case HKDF_PHASE_2:
			/* prepare okm for next extract */
			empty = chunk_empty;
			derived = chunk_from_str("tls13 derived");
			if (!derive_secret(this, &derived, &empty))
			{
				DBG1(DBG_TLS, "unable to derive secret");
				return FALSE;
			}

			chunk_t ikm = chunk_from_chars(
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			);

			if (!extract(this, &this->okm, &ikm, &this->prk))
			{
				DBG1(DBG_TLS, "unable extract PRK");
				return FALSE;
			}
			this->phase = HKDF_PHASE_3;
			return TRUE;
		case HKDF_PHASE_3:
			return TRUE;
		default:
			DBG1(DBG_TLS, "invalid HKDF phase");
			return FALSE;
	}
}

static bool write_key_to_caller_secret(private_tls_hkdf_t *this, chunk_t *key, chunk_t *secret)
{
	*secret = chunk_alloc(this->L);
	memset(secret->ptr, 0, this->L);
	memcpy(secret->ptr + secret->len - key->len,
		   key->ptr, key->len);

	return TRUE;
}

METHOD(tls_hkdf_t, set_shared_secret, bool, private_tls_hkdf_t *this, chunk_t *shared_secret)
{
	if (!shared_secret)
	{
		DBG1(DBG_TLS, "no shared secret provided");
		return FALSE;
	}

	this->shared_secret = shared_secret;
	return TRUE;
}

METHOD(tls_hkdf_t, generate_secret, bool, private_tls_hkdf_t *this, enum tls_hkdf_labels_t label, chunk_t *messages, chunk_t *secret)
{
	chunk_t label_name;
	this->L = this->hasher->get_hash_size(this->hasher);
	label_name = chunk_from_str(hkdf_labels[label]);

	switch (label)
	{
		case TLS_HKDF_EXT_BINDER:
		case TLS_HKDF_RES_BINDER:
		case TLS_HKDF_C_E_TRAFFIC:
		case TLS_HKDF_E_EXP_MASTER:
			if (!move_to_phase_1(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 1.");
				return FALSE;
			}
			break;
		case TLS_HKDF_C_HS_TRAFFIC:
		case TLS_HKDF_S_HS_TRAFFIC:
			if (!move_to_phase_2(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 2.");
				return FALSE;
			}
			break;
		case TLS_HKDF_C_AP_TRAFFIC:
		case TLS_HKDF_S_AP_TRAFFIC:
		case TLS_HKDF_EXP_MASTER:
		case TLS_HKDF_RES_MASTER:
			if (!move_to_phase_3(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 3.");
				return FALSE;
			}
			break;
		default:
			DBG1(DBG_TLS, "invalid HKDF label.");
			return FALSE;
	}

	if (!derive_secret(this, &label_name, messages))
	{
		DBG1(DBG_TLS, "unable to derive secret");
		return FALSE;
	}

	if (!secret)
	{
		return TRUE;
	}

	if (!write_key_to_caller_secret(this, &this->okm, secret))
	{
		DBG1(DBG_TLS, "unable to write secret back to caller");
		return FALSE;
	}

	return TRUE;
}

METHOD(tls_hkdf_t, derive_key, bool, private_tls_hkdf_t *this, bool is_server, size_t length, chunk_t *key)
{
	chunk_t label_name = chunk_from_str("tls13 key");
	chunk_t messages = chunk_empty;
	this->L = length;
	chunk_t result;

	if (!expand_label(this, &this->okm, &label_name, &messages, length, &result))
	{
		DBG1(DBG_TLS, "unable to derive secret");
		chunk_clear(&result);
		return FALSE;
	}

	if (!key)
	{
		DBG1(DBG_TLS, "no memory for key provided");
		return FALSE;
	}

	if (!write_key_to_caller_secret(this, &result, key))
	{
		DBG1(DBG_TLS, "unable to write secret back to caller");
		return FALSE;
	}

	chunk_clear(&result);
	return TRUE;
}

METHOD(tls_hkdf_t, derive_iv, bool, private_tls_hkdf_t *this, bool is_server, size_t length, chunk_t *iv)
{
	chunk_t label_name = chunk_from_str("tls13 iv");
	chunk_t messages = chunk_empty;
	this->L = length;

	chunk_t result;

	if (!expand_label(this, &this->okm, &label_name, &messages, length, &result))
	{
		DBG1(DBG_TLS, "unable to derive secret");
		chunk_clear(&result);
		return FALSE;
	}

	if (!iv)
	{
		DBG1(DBG_TLS, "no memory for iv provided");
		return FALSE;
	}

	if (!write_key_to_caller_secret(this, &result, iv))
	{
		DBG1(DBG_TLS, "unable to write secret back to caller");
		return FALSE;
	}

	chunk_clear(&result);
	return TRUE;
}

METHOD(tls_hkdf_t, derive_finished, bool, private_tls_hkdf_t *this, bool is_server, size_t length, chunk_t *finished)
{
	chunk_t label_name = chunk_from_str("tls13 finished");
	chunk_t messages = chunk_empty;
	this->L = length;

	chunk_t result;

	if (!expand_label(this, &this->okm, &label_name, &messages, length, &result))
	{
		DBG1(DBG_TLS, "unable to derive secret");
		chunk_clear(&result);
		return FALSE;
	}

	if (!finished)
	{
		DBG1(DBG_TLS, "no memory for finished provided");
		return FALSE;
	}

	if (!write_key_to_caller_secret(this, &result, finished))
	{
		DBG1(DBG_TLS, "unable to write secret back to caller");
		return FALSE;
	}

	chunk_clear(&result);
	return TRUE;
}

METHOD(tls_hkdf_t, destroy, void,
	   private_tls_hkdf_t *this)
{
	chunk_free(&this->salt);
	chunk_free(&this->ikm);
	chunk_free(&this->info);
	chunk_clear(&this->prk);
	chunk_clear(&this->okm);
	DESTROY_IF(this->prf_plus);
	this->prf->destroy(this->prf);
	this->hasher->destroy(this->hasher);
	free(this);
}

tls_hkdf_t *tls_hkdf_create(hash_algorithm_t hash_algorithm, chunk_t *psk)
{
	private_tls_hkdf_t *this;

	INIT(this,
		.public = {
			.set_shared_secret = _set_shared_secret,
			.generate_secret = _generate_secret,
			.derive_key = _derive_key,
			.derive_iv = _derive_iv,
			.derive_finished = _derive_finished,
			.destroy = _destroy,
		},
		.phase = HKDF_PHASE_0,
		.hash_algorithm = hash_algorithm,
		.L = 32,
		.prf = lib->crypto->create_prf(lib->crypto, PRF_HMAC_SHA2_256),
		.hasher = lib->crypto->create_hasher(lib->crypto, hash_algorithm),
	);

	this->salt = chunk_alloc(this->L);
	memset(this->salt.ptr, 0, this->salt.len);

	if (!psk)
	{
		this->ikm = chunk_alloc(this->L);
		memset(this->ikm.ptr, 0, this->ikm.len);
	}
	else
	{
		chunk_create_clone(psk->ptr, this->ikm);
	}

	if (!this->hasher)
	{
		DBG1(DBG_TLS, "unable to set hash");
		destroy(this);
		return NULL;
	}

	return &this->public;
}