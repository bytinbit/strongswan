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
#include "../libstrongswan/utils/chunk.h"
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

/* HKDF-Extract(this->salt, this->ikm) -> this->prk */
static bool extract(private_tls_hkdf_t *this)
{
	if (!this->prf->set_key(this->prf, this->salt))
	{
		DBG2(DBG_TLS, "unable to set PRF salt");
		return FALSE;
	}
	if(!this->prf->allocate_bytes(this->prf, this->ikm, &this->prk))
	{
		DBG2(DBG_TLS, "unable to allocate PRF space");
		return FALSE;
	}

	DBG1(DBG_TLS, "PRK: %B", &this->prk);

	return TRUE;
}

/* HKDF-Expand(this->prk, this->info, this->L) -> this->okm */
static bool expand(private_tls_hkdf_t *this)
{
	if (!this->prf->set_key(this->prf, this->prk))
	{
		DBG2(DBG_TLS, "unable to set PRF PRK");
		return FALSE;
	}
	this->prf_plus = prf_plus_create(this->prf, TRUE, this->info);
	if (!this->prf_plus->allocate_bytes(this->prf_plus, this->L, &this->okm))
	{
		DBG2(DBG_TLS, "unable to allocate PRF plus space");
		return FALSE;
	}

	DBG1(DBG_TLS, "OKM: %B", &this->okm);

	return TRUE;
}

static bool expand_label(private_tls_hkdf_t *this, chunk_t *label, chunk_t *context, uint16_t length)
{
	/*
	 * pack label and context into structure hkdflabel
	 */
	if (label->len < 7 || label->len > 255 ||
		context->len < 0 || context->len > 255)
	{
		return FALSE;
	}
	/* HKDFLabel */
	size_t offset = 0;
	size_t chunk_len = 2 + 1 + label->len + 1 + context->len;
	this->info = chunk_create(malloc(chunk_len), chunk_len);
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

	expand(this);

	return TRUE;
}

static bool derive_secret(private_tls_hkdf_t *this, chunk_t *label, chunk_t *messages)
{
	/*
	 * calculate hash of message
	 */
	/*
	 * Hash messages and call expand
	 */
	size_t chunk_len = 32;
	chunk_t context = chunk_create(malloc(chunk_len), chunk_len);

	if (!this->hasher || !this->hasher->allocate_hash(this->hasher, *messages, &context))
	{
		DBG2(DBG_TLS, "%N not supported", hash_algorithm_names, this->hash_algorithm);
		return FALSE;
	}

	expand_label(this, label, &context, 32);
	chunk_free(&context);

	return TRUE;
}

static bool move_to_phase_1(private_tls_hkdf_t *this)
{
	if (this->phase == HKDF_PHASE_0)
	{
		if (!extract(this))
		{
			DBG2(DBG_TLS, "unable extract PRK");
			return FALSE;
		}
		this->phase = HKDF_PHASE_1;
		/* prepare okm for next extract */
		chunk_t empty = chunk_empty;
		chunk_t derived = chunk_from_str("tls13 derived");
		if (!derive_secret(this, &derived, &empty))
		{
			DBG2(DBG_TLS, "unable to derive secret");
			return FALSE;
		}
		return TRUE;
	}

	if (this->phase == HKDF_PHASE_1)
	{
		return TRUE;
	}
	else
	{
		DBG2(DBG_TLS, "invalid HKDF phase");
		return FALSE;
	}
}

static bool move_to_phase_2(private_tls_hkdf_t *this)
{
	if (this->phase == HKDF_PHASE_0)
	{
		move_to_phase_1(this);
	}

	if (this->phase == HKDF_PHASE_1)
	{
		this->salt = this->okm;

		if (!this->shared_secret)
		{
			DBG2(DBG_TLS, "no shared secret set");
			return FALSE;
		}
		else
		{
			memcpy(this->ikm.ptr, this->shared_secret->ptr, this->shared_secret->len);
			this->ikm.len = this->shared_secret->len;
		}

		if (!extract(this))
		{
			DBG2(DBG_TLS, "unable extract PRK");
			return FALSE;
		}
		this->phase = HKDF_PHASE_2;
		/* prepare okm for next extract */
		chunk_t empty = chunk_empty;
		chunk_t derived = chunk_from_str("tls13 derived");
		if (!derive_secret(this, &derived, &empty))
		{
			DBG2(DBG_TLS, "unable to derive secret");
			return FALSE;
		}
		return TRUE;
	}

	if (this->phase == HKDF_PHASE_2)
	{
		return TRUE;
	}
	else
	{
		DBG2(DBG_TLS, "invalid HKDF phase");
		return FALSE;
	}
}

/*
static bool move_to_phase_3(private_tls_hkdf_t *this)
{
	*/
/*
	 * (salt, ikm) -> prk
	 *//*

	if (this->phase == HKDF_PHASE_0)
	{
		move_to_phase_1(this);
	}

	if (this->phase == HKDF_PHASE_1)
	{
		move_to_phase_2(this);
	}

	if (this->phase == HKDF_PHASE_2)
	{
		this->salt = this->okm;

		this->ikm = chunk_from_chars(
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		);

		if (!extract(this))
		{
			DBG2(DBG_TLS, "unable extract PRK");
			return FALSE;
		}
		this->phase = HKDF_PHASE_3;
		return TRUE;
	}

	if (this->phase == HKDF_PHASE_3)
	{
		return TRUE;
	}
	else
	{
		DBG2(DBG_TLS, "invalid HKDF phase");
		return FALSE;
	}
}
*/

static bool get_secret(private_tls_hkdf_t *this, chunk_t *secret)
{
	*secret = chunk_alloc(this->L);
	memset(secret->ptr, 0, this->L);
	memcpy(secret->ptr + secret->len - this->okm.len,
		   this->okm.ptr, this->okm.len);
	return TRUE;
}

METHOD(tls_hkdf_t, set_shared_secret, bool, private_tls_hkdf_t *this, chunk_t *shared_secret)
{
	if (shared_secret)
	{
		this->shared_secret = shared_secret;
		return TRUE;
	}
	else
	{
		DBG2(DBG_TLS, "no shared secret provided");
		return FALSE;
	}
}

METHOD(tls_hkdf_t, generate_secret, bool, private_tls_hkdf_t *this, enum tls_hkdf_labels_t label, chunk_t *messages, chunk_t *secret)
{
	/*
	 * 1. Prüfe Eingabeparameter
	 * 2. Springe in Phase des gewünschten Secrets
	 * 3. Gebe Secret zurück
	 */
	chunk_t label_name;

	switch (label)
	{
		/*
		case TLS_HKDF_EXT_BINDER:
			label_name = chunk_from_str("tls13 ext binder");
			if (this->phase <= HKDF_PHASE_1)
			{
				if (!move_to_phase_1(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 1.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
		case TLS_HKDF_RES_BINDER:
			label_name = chunk_from_str("tls13 res binder");
			if (this->phase <= HKDF_PHASE_1)
			{
				if (!move_to_phase_1(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 1.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
		case TLS_HKDF_C_E_TRAFFIC:
			label_name = chunk_from_str("tls13 c e traffic");
			if (this->phase <= HKDF_PHASE_1)
			{
				if (!move_to_phase_1(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 1.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
		case TLS_HKDF_E_EXP_MASTER:
			label_name = chunk_from_str("tls13 e exp master");
			if (this->phase <= HKDF_PHASE_1)
			{
				if (!move_to_phase_1(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 1.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
*/
		case TLS_HKDF_C_HS_TRAFFIC:
			label_name = chunk_from_str("tls13 c hs traffic");
			if (this->phase <= HKDF_PHASE_2)
			{
				if (!move_to_phase_2(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 2.");
					return FALSE;
				}
				DBG2(DBG_TLS, "see this\n");
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
		case TLS_HKDF_S_HS_TRAFFIC:
			label_name = chunk_from_str("tls13 s hs traffic");
			if (this->phase <= HKDF_PHASE_2)
			{
				if (!move_to_phase_2(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 2.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
/*
		case TLS_HKDF_C_AP_TRAFFIC:
			label_name = chunk_from_str("tls13 c ap traffic");
			if (this->phase <= HKDF_PHASE_3)
			{
				if (!move_to_phase_3(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 3.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
		case TLS_HKDF_S_AP_TRAFFIC:
			label_name = chunk_from_str("tls13 s ap traffic");
			if (this->phase <= HKDF_PHASE_3)
			{
				if (!move_to_phase_3(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 3.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
		case TLS_HKDF_EXP_MASTER:
			label_name = chunk_from_str("tls13 exp master");
			if (this->phase <= HKDF_PHASE_3)
			{
				if (!move_to_phase_3(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 3.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
		case TLS_HKDF_RES_MASTER:
			label_name = chunk_from_str("tls13 res master");
			if (this->phase <= HKDF_PHASE_3)
			{
				if (!move_to_phase_3(this))
				{
					DBG2(DBG_TLS, "unable to move to phase 3.");
					return FALSE;
				}
				break;
			}
			else
			{
				DBG2(DBG_TLS, "invalid HKDF label for current phase.");
				return FALSE;
			}
*/
		default:
			DBG2(DBG_TLS, "invalid HKDF label.");
			return FALSE;
	}

	/*
	* return okm via secret
	*/
	if (!derive_secret(this, &label_name, messages))
	{
		DBG2(DBG_TLS, "unable to derive secret");
		return FALSE;
	}

	if (!get_secret(this, secret))
	{
		DBG2(DBG_TLS, "unable to get secret");
		return FALSE;
	}

	return TRUE;
}

METHOD(tls_hkdf_t, destroy, void,
	   private_tls_hkdf_t *this)
{
	chunk_clear(&this->prk);
	chunk_clear(&this->okm);
	this->prf_plus->destroy(this->prf_plus);
	this->prf->destroy(this->prf);
}

tls_hkdf_t *tls_hkdf_create(hash_algorithm_t hash_algorithm, chunk_t *psk)
{
	private_tls_hkdf_t *this;

	INIT(this,
		.public = {
			.set_shared_secret = _set_shared_secret,
			.generate_secret = _generate_secret,
			.destroy = _destroy,
		},
		.phase = HKDF_PHASE_0,
		.hash_algorithm = hash_algorithm,
		.prf = lib->crypto->create_prf(lib->crypto, PRF_HMAC_SHA2_256),
		.hasher = lib->crypto->create_hasher(lib->crypto, hash_algorithm),
	);

	this->salt = chunk_alloc(32);
	memset(this->salt.ptr, 0, this->salt.len);

	if (!psk)
	{
		this->ikm = chunk_alloc(32);
		memset(this->ikm.ptr, 0, this->ikm.len);
	}
	else
	{
		chunk_create_clone(psk->ptr, this->ikm);
	}

	if (!this->hasher)
	{
		DBG2(DBG_TLS, "unable to set hash");
		return NULL;
	}
	this->hash_length = this->hasher->get_hash_size(this->hasher);
	this->L = this->hasher->get_hash_size(this->hasher);

	return &this->public;
}