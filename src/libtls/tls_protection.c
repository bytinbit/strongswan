/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "tls_protection.h"

#include <utils/debug.h>

typedef struct private_tls_protection_t private_tls_protection_t;

/**
 * Private data of an tls_protection_t object.
 */
struct private_tls_protection_t {

	/**
	 * Public tls_protection_t interface.
	 */
	tls_protection_t public;

	/**
	 * negotiated TLS version
	 */
	tls_version_t version;

	/**
	 * Upper layer, TLS record compression
	 */
	tls_compression_t *compression;

	/**
	 * TLS alert handler
	 */
	tls_alert_t *alert;

	/**
	 * Sequence number of incoming records
	 */
	uint64_t seq_in;

	/**
	 * Sequence number for outgoing records
	 */
	uint64_t seq_out;

	/**
	 * AEAD transform for inbound traffic
	 */
	tls_aead_t *aead_in;

	/**
	 * AEAD transform for outbound traffic
	 */
	tls_aead_t *aead_out;
};

/**
 * Decrypt incoming payload
 */
static bool decrypt_payload(private_tls_protection_t *this,
                            tls_content_type_t *type, chunk_t *data)
{
	if (this->aead_in)
	{
		if (!this->aead_in->decrypt(this->aead_in, this->version,
		                            type, this->seq_in, data))
		{
			return false;
		}
	}
	return true;
}

METHOD(tls_protection_t, process, status_t,
	private_tls_protection_t *this, tls_content_type_t type, chunk_t data)
{
	if (this->alert->fatal(this->alert))
	{	/* don't accept more input, fatal error occurred */
		return NEED_MORE;
	}

	if (this-> version < TLS_1_3)
	{
		if(!decrypt_payload(this, &type, &data))
		{
			DBG1(DBG_TLS, "TLS record decryption for legacy TLS failed");
			this->alert->add(this->alert, TLS_FATAL, TLS_BAD_RECORD_MAC);
			return NEED_MORE;
		}

		/* TODO: aead_in gesetzt, wenn change cipher spec verarbeitet
		 * => check original code */
		if (type == TLS_CHANGE_CIPHER_SPEC)
		{
			this->seq_in = 0;
		}
		else
		{
			this->seq_in++;
		}
	}
	else
	{
		if (type == TLS_HANDSHAKE)
		{
			this->seq_in = 0;
		}
		if (type == TLS_APPLICATION_DATA)
		{
			if(!decrypt_payload(this, &type, &data))
			{
				DBG1(DBG_TLS, "TLS record decryption failed");
				this->alert->add(this->alert, TLS_FATAL, TLS_BAD_RECORD_MAC);
				return NEED_MORE;
			}
			this->seq_in++;
		}

	}
	return this->compression->process(this->compression, type, data);

}

METHOD(tls_protection_t, build, status_t,
	private_tls_protection_t *this, tls_content_type_t *type, chunk_t *data)
{
	status_t status;

	status = this->compression->build(this->compression, type, data);
	if (status == NEED_MORE)
	{
		if (this-> version < TLS_1_3)
		{
			if (*type == TLS_CHANGE_CIPHER_SPEC)
			{
				this->seq_out = 0;
				return status;
			}
			if (this->aead_out)
			{
				if (!this->aead_out->encrypt(this->aead_out, this->version,
				                             type, this->seq_out, data))
				{
					DBG1(DBG_TLS, "TLS record encryption failed");
					chunk_free(data);
					return FAILED;
				}
			}
			this->seq_out++;
		}
		else
		{
			if (*type == TLS_HANDSHAKE)
			{
				this->seq_out = 0;
			}
			if (this->aead_out)
			{
				if (!this->aead_out->encrypt(this->aead_out, this->version,
				                             type, this->seq_out, data))
				{
					DBG1(DBG_TLS, "TLS record encryption failed");
					chunk_free(data);
					return FAILED;
				}
			}
			if (*type == TLS_APPLICATION_DATA)
			{

				this->seq_out++;
			}
		}

	}
	return status;
}

METHOD(tls_protection_t, set_cipher, void,
	private_tls_protection_t *this, bool inbound, tls_aead_t *aead)
{
	/* TODO set sequence number here, to do more generically? */
	if (inbound)
	{
		this->aead_in = aead;
	}
	else
	{
		this->aead_out = aead;
	}
}

METHOD(tls_protection_t, set_version, void,
	private_tls_protection_t *this, tls_version_t version)
{
	this->version = version;
}

METHOD(tls_protection_t, destroy, void,
	private_tls_protection_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_protection_t *tls_protection_create(tls_compression_t *compression,
										tls_alert_t *alert)
{
	private_tls_protection_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.set_cipher = _set_cipher,
			.set_version = _set_version,
			.destroy = _destroy,
		},
		.alert = alert,
		.compression = compression,
	);

	return &this->public;
}
