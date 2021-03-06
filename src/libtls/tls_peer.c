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

#include "tls_peer.h"

#include <utils/debug.h>
#include <credentials/certificates/x509.h>

#include <time.h>

typedef struct private_tls_peer_t private_tls_peer_t;

typedef enum {
	STATE_INIT,
	STATE_HELLO_SENT,
	STATE_HELLO_RECEIVED,
	STATE_HELLO_DONE,
	STATE_CERT_SENT,
	STATE_CERT_RECEIVED,
	STATE_KEY_EXCHANGE_RECEIVED,
	STATE_CERTREQ_RECEIVED,
	STATE_KEY_EXCHANGE_SENT,
	STATE_VERIFY_SENT,
	STATE_CIPHERSPEC_CHANGED_OUT,
	STATE_FINISHED_SENT,
	STATE_CIPHERSPEC_CHANGED_IN,
	STATE_FINISHED_RECEIVED,
	/* new states in TLS 1.3 */
	STATE_HELLORETRYREQ_RECEIVED,
	STATE_ENCRYPTED_EXTENSIONS_RECEIVED,
	STATE_CERT_VERIFY_RECEIVED,
	STATE_FINISHED_SENT_KEY_SWITCHED,

} peer_state_t;

/**
 * Private data of an tls_peer_t object.
 */
struct private_tls_peer_t {

	/**
	 * Public tls_peer_t interface.
	 */
	tls_peer_t public;

	/**
	 * TLS stack
	 */
	tls_t *tls;

	/**
	 * TLS crypto context
	 */
	tls_crypto_t *crypto;

	/**
	 * TLS alert handler
	 */
	tls_alert_t *alert;

	/**
	 * Peer identity, NULL for no client authentication
	 */
	identification_t *peer;

	/**
	 * Server identity
	 */
	identification_t *server;

	/**
	 * State we are in
	 */
	peer_state_t state;

	/**
	 * TLS version we offered in hello
	 */
	tls_version_t hello_version;

	/**
	 * Hello random data selected by client
	 */
	char client_random[32];

	/**
	 * Hello random data selected by server
	 */
	char server_random[32];

	/**
	 * Auth helper for peer authentication
	 */
	auth_cfg_t *peer_auth;

	/**
	 * Auth helper for server authentication
	 */
	auth_cfg_t *server_auth;

	/**
	 * Peer private key
	 */
	private_key_t *private;

	/**
	 * DHE exchange
	 */
	diffie_hellman_t *dh;

	/**
	 * Resuming a session?
	 */
	bool resume;

	/**
	 * TLS session identifier
	 */
	chunk_t session;

	/**
	 * List of server-supported hashsig algorithms
	 */
	chunk_t hashsig;

	/**
	 * List of server-supported client certificate types
	 */
	chunk_t cert_types;
};

/**
 * Process a server hello message
 */
static status_t process_server_hello(private_tls_peer_t *this,
									 bio_reader_t *reader)
{
	uint8_t compression;
	uint16_t version, cipher;
	chunk_t random, session, ext = chunk_empty, ext_key_share = chunk_empty;
	tls_cipher_suite_t suite = 0;
	int offset = 0;
	uint16_t extension_type, extension_length;
	uint16_t key_type, key_length;

	this->crypto->append_handshake(this->crypto,
								   TLS_SERVER_HELLO, reader->peek(reader));

	if (!reader->read_uint16(reader, &version) ||
		!reader->read_data(reader, sizeof(this->server_random), &random) ||
		!reader->read_data8(reader, &session) ||
		!reader->read_uint16(reader, &cipher) ||
		!reader->read_uint8(reader, &compression) ||
		(reader->remaining(reader) && !reader->read_data16(reader, &ext)))
	{
		DBG1(DBG_TLS, "received invalid ServerHello");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}

	memcpy(this->server_random, random.ptr, sizeof(this->server_random));

	bio_reader_t *extension_reader = bio_reader_create(ext);

	/* parse extension to decide which tls version of the state machine we
	 * want to go
	 */
	while (offset < ext.len)
	{
		chunk_t extension_payload = chunk_empty;

		extension_reader->read_uint16(extension_reader, &extension_type);
		extension_reader->read_uint16(extension_reader, &extension_length);
		offset += extension_length + 4;

		if (!extension_reader->read_data(extension_reader,
										 extension_length,
										 &extension_payload))
		{
			DBG2(DBG_TLS, "unable to read extension payload data");
		}

		bio_reader_t *ext_payload_reader = bio_reader_create(extension_payload);

		switch (extension_type)
		{
			case TLS_EXT_SUPPORTED_VERSIONS:
				ext_payload_reader->read_uint16(ext_payload_reader, &version);
				break;

			case TLS_EXT_KEY_SHARE:
				ext_payload_reader->read_uint16(ext_payload_reader, &key_type);
				ext_payload_reader->read_uint16(ext_payload_reader, &key_length);
				if (!ext_payload_reader->read_data(ext_payload_reader,
												   key_length,
												   &ext_key_share))
				{
					DBG2(DBG_TLS, "no valid key share found in extension");
				}
				break;
			default:
				continue;
		}
		ext_payload_reader->destroy(ext_payload_reader);
	}
	extension_reader->destroy(extension_reader);

	if (!this->tls->set_version(this->tls, version))
	{
		DBG1(DBG_TLS, "negotiated version %N not supported",
			 tls_version_names, version);
		this->alert->add(this->alert, TLS_FATAL, TLS_PROTOCOL_VERSION);
		return NEED_MORE;
	}

	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		if (chunk_equals(this->session, session))
		{
			suite = this->crypto->resume_session(this->crypto, session,
												 this->server, chunk_from_thing
												 (this->client_random),
												 chunk_from_thing
												 (this->server_random));
			if (suite)
			{
				DBG1(DBG_TLS, "resumed %N using suite %N",
					 tls_version_names, version, tls_cipher_suite_names, suite);
				this->resume = TRUE;
			}
		}
		DESTROY_IF(this->dh);
		this->dh = NULL;
	}
	if (!suite)
	{
		suite = cipher;
		if (!this->crypto->select_cipher_suite(this->crypto, &suite, 1, KEY_ANY))
		{
			DBG1(DBG_TLS, "received TLS cipher suite %N unacceptable",
				 tls_cipher_suite_names, suite);
			this->alert->add(this->alert, TLS_FATAL, TLS_HANDSHAKE_FAILURE);
			return NEED_MORE;
		}
		DBG1(DBG_TLS, "negotiated %N using suite %N",
			 tls_version_names, version, tls_cipher_suite_names, suite);
		free(this->session.ptr);
		this->session = chunk_clone(session);
	}

	if (this->tls->get_version_max(this->tls) == TLS_1_3)
	{
		chunk_t shared_secret;

		if (key_type != CURVE_25519 &&
			!this->dh->set_other_public_value(this->dh, ext_key_share))
		{
			DBG2(DBG_TLS, "server key share unable to save");
		}
		if (!this->dh->get_shared_secret(this->dh, &shared_secret))
		{
			DBG2(DBG_TLS, "No shared secret key found");
		}

		if (!this->crypto->derive_handshake_secret(this->crypto, shared_secret))
		{
			DBG2(DBG_TLS, "derive handshake traffic secret failed");
		}
	}

	this->state = STATE_HELLO_RECEIVED;
	return NEED_MORE;
}

/**
* Process a server encrypted extensions message
*/
static status_t process_encrypted_extensions(private_tls_peer_t *this,
											 bio_reader_t *reader)
{
	uint16_t length;
	chunk_t ext = chunk_empty;
	int offset = 0;
	uint16_t extension_type, extension_length;

	this->crypto->append_handshake(this->crypto,
								   TLS_ENCRYPTED_EXTENSIONS, reader->peek(reader));


	if (!reader->read_uint16(reader, &length) ||
		(reader->remaining(reader) && !reader->read_data16(reader, &ext)))
	{
		DBG1(DBG_TLS, "received invalid EncryptedExtensions");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}
	if (ext.len == 0)
	{
		this->state = STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
		return NEED_MORE;
	}
	else
	{
		bio_reader_t *extension_reader = bio_reader_create(ext);

		while (offset < ext.len)
		{
			chunk_t extension_payload = chunk_empty;
			extension_reader->read_uint16(extension_reader, &extension_type);
			extension_reader->read_uint16(extension_reader, &extension_length);
			offset += extension_length + 4;

			if (!extension_reader->read_data(extension_reader,
											 extension_length,
											 &extension_payload))
			{
				DBG2(DBG_TLS, "unable to read extension payload data");
			}
			switch (extension_type)
			{
				/* fall through because not supported so far */
				case TLS_EXT_SERVER_NAME:
				case TLS_EXT_MAX_FRAGMENT_LENGTH:
				case TLS_EXT_SUPPORTED_GROUPS:
				case TLS_EXT_USE_SRTP:
				case TLS_EXT_HEARTBEAT:
				case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
				case TLS_SERVER_CERTIFICATE_TYPE:
					this->state = STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
					extension_reader->destroy(extension_reader);
					break;
				default:
					DBG1(DBG_TLS, "received forbidden EncryptedExtensions");
					this->alert->add(this->alert, TLS_FATAL,
									 TLS_ILLEGAL_PARAMETER);
					extension_reader->destroy(extension_reader);
					return NEED_MORE;
			}
		}

	}
	return NEED_MORE;
}

/**
 * Check if a server certificate is acceptable for the given server identity
 */
static bool check_certificate(private_tls_peer_t *this, certificate_t *cert)
{
	identification_t *id;

	if (cert->has_subject(cert, this->server))
	{
		return TRUE;
	}
	id = cert->get_subject(cert);
	if (id->matches(id, this->server))
	{
		return TRUE;
	}
	if (cert->get_type(cert) == CERT_X509)
	{
		x509_t *x509 = (x509_t*)cert;
		enumerator_t *enumerator;

		enumerator = x509->create_subjectAltName_enumerator(x509);
		while (enumerator->enumerate(enumerator, &id))
		{
			if (id->matches(id, this->server))
			{
				enumerator->destroy(enumerator);
				return TRUE;
			}
		}
		enumerator->destroy(enumerator);
	}
	DBG1(DBG_TLS, "server certificate does not match to '%Y'", this->server);
	return FALSE;
}

/**
 * Process a Certificate message
 */
static status_t process_certificate(private_tls_peer_t *this,
									bio_reader_t *reader)
{
	certificate_t *cert;
	bio_reader_t *certs;
	chunk_t data;
	bool first = TRUE;

	this->crypto->append_handshake(this->crypto,
								   TLS_CERTIFICATE, reader->peek(reader));

	if (this->tls->get_version_max(this->tls) > TLS_1_2)
	{
		if (!reader->read_data8(reader, &data))
		{
			DBG1(DBG_TLS, "certificate request context invalid");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
			return NEED_MORE;
		}
		if (data.len > 0)
		{
			DBG1(DBG_TLS, "certificate request context available,"
				 "but CertificateRequest not received");
		}
	}
	if (!reader->read_data24(reader, &data))
	{
		DBG1(DBG_TLS, "certificate message header invalid");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}
	certs = bio_reader_create(data);
	while (certs->remaining(certs))
	{
		if (!certs->read_data24(certs, &data))
		{
			DBG1(DBG_TLS, "certificate message invalid");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
			certs->destroy(certs);
			return NEED_MORE;
		}
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_BLOB_ASN1_DER, data, BUILD_END);
		if (cert)
		{
			if (first)
			{
				if (!check_certificate(this, cert))
				{
					cert->destroy(cert);
					certs->destroy(certs);
					this->alert->add(this->alert, TLS_FATAL, TLS_ACCESS_DENIED);
					return NEED_MORE;
				}
				this->server_auth->add(this->server_auth,
									   AUTH_HELPER_SUBJECT_CERT, cert);
				DBG1(DBG_TLS, "received TLS server certificate '%Y'",
					 cert->get_subject(cert));
				first = FALSE;
			}
			else
			{
				DBG1(DBG_TLS, "received TLS intermediate certificate '%Y'",
					 cert->get_subject(cert));
				this->server_auth->add(this->server_auth,
									   AUTH_HELPER_IM_CERT, cert);
			}
		}
		else
		{
			DBG1(DBG_TLS, "parsing TLS certificate failed, skipped");
			this->alert->add(this->alert, TLS_WARNING, TLS_BAD_CERTIFICATE);
		}
		if (this->tls->get_version_max(this->tls) > TLS_1_2)
		{
			if (!certs->read_data16(certs, &data))
			{
				DBG1(DBG_TLS, "reading extension field of certificate failed",
					 &data);
				this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
				return NEED_MORE;
			}
			break;
		}
	}
	certs->destroy(certs);
	this->state = STATE_CERT_RECEIVED;
	return NEED_MORE;
}

/**
 *  Process Certificate verify
 */
static status_t process_cert_verify(private_tls_peer_t *this,
									bio_reader_t *reader)
{
	bool verified = FALSE;
	enumerator_t *enumerator;
	public_key_t *public;
	auth_cfg_t *auth;
	bio_reader_t *sig;
	enumerator = lib->credmgr->create_public_enumerator(lib->credmgr,
														KEY_ANY, this->server,
														this->server_auth, TRUE);
	while (enumerator->enumerate(enumerator, &public, &auth))
	{
		sig = bio_reader_create(reader->peek(reader));
		verified = this->crypto->verify_handshake(this->crypto, public, sig);
		sig->destroy(sig);
		if (verified)
		{
			this->server_auth->merge(this->server_auth, auth, FALSE);
			break;
		}
		DBG1(DBG_TLS, "signature verification failed, trying another key");
	}
	enumerator->destroy(enumerator);

	if (!verified)
	{
		DBG1(DBG_TLS, "no trusted certificate found for '%Y' to verify TLS peer",
			 this->server);
		this->server->destroy(this->server);
		this->peer = NULL;
		this->state = STATE_KEY_EXCHANGE_RECEIVED;
	}
	else
	{
		this->state = STATE_CERT_VERIFY_RECEIVED;
	}
	this->crypto->append_handshake(this->crypto,
								   TLS_CERTIFICATE_VERIFY, reader->peek(reader));
	return NEED_MORE;
}

/**
 * Find a trusted public key to encrypt/verify key exchange data
 */
static public_key_t *find_public_key(private_tls_peer_t *this)
{
	public_key_t *public = NULL, *current;
	certificate_t *cert, *found;
	enumerator_t *enumerator;
	auth_cfg_t *auth;

	cert = this->server_auth->get(this->server_auth, AUTH_HELPER_SUBJECT_CERT);
	if (cert)
	{
		enumerator = lib->credmgr->create_public_enumerator(lib->credmgr,
											KEY_ANY, cert->get_subject(cert),
											this->server_auth, TRUE);
		while (enumerator->enumerate(enumerator, &current, &auth))
		{
			found = auth->get(auth, AUTH_RULE_SUBJECT_CERT);
			if (found && cert->equals(cert, found))
			{
				public = current->get_ref(current);
				this->server_auth->merge(this->server_auth, auth, FALSE);
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return public;
}

/**
 * Process a Key Exchange message using MODP Diffie Hellman
 */
static status_t process_modp_key_exchange(private_tls_peer_t *this,
										  bio_reader_t *reader)
{
	chunk_t prime, generator, pub, chunk;
	public_key_t *public;

	chunk = reader->peek(reader);
	if (!reader->read_data16(reader, &prime) ||
		!reader->read_data16(reader, &generator) ||
		!reader->read_data16(reader, &pub))
	{
		DBG1(DBG_TLS, "received invalid Server Key Exchange");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}
	/* reject (export) DH groups using primes smaller than 1024 bit */
	if (prime.len < 1024 / 8)
	{
		DBG1(DBG_TLS, "short DH prime received (%zu bytes)", prime.len);
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}
	public = find_public_key(this);
	if (!public)
	{
		DBG1(DBG_TLS, "no TLS public key found for server '%Y'", this->server);
		this->alert->add(this->alert, TLS_FATAL, TLS_CERTIFICATE_UNKNOWN);
		return NEED_MORE;
	}

	chunk.len = 2 + prime.len + 2 + generator.len + 2 + pub.len;
	chunk = chunk_cat("ccc", chunk_from_thing(this->client_random),
					  chunk_from_thing(this->server_random), chunk);
	if (!this->crypto->verify(this->crypto, public, reader, chunk))
	{
		public->destroy(public);
		free(chunk.ptr);
		DBG1(DBG_TLS, "verifying DH parameters failed");
		this->alert->add(this->alert, TLS_FATAL, TLS_BAD_CERTIFICATE);
		return NEED_MORE;
	}
	public->destroy(public);
	free(chunk.ptr);

	this->dh = lib->crypto->create_dh(lib->crypto, MODP_CUSTOM,
									  generator, prime);
	if (!this->dh)
	{
		DBG1(DBG_TLS, "custom DH parameters not supported");
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}
	if (!this->dh->set_other_public_value(this->dh, pub))
	{
		DBG1(DBG_TLS, "applying DH public value failed");
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}

	this->state = STATE_KEY_EXCHANGE_RECEIVED;
	return NEED_MORE;
}

/**
 * Get the EC group for a TLS named curve
 */
static diffie_hellman_group_t curve_to_ec_group(private_tls_peer_t *this,
												tls_named_group_t curve)
{
	diffie_hellman_group_t group;
	tls_named_group_t current;
	enumerator_t *enumerator;

	enumerator = this->crypto->create_ec_enumerator(this->crypto);
	while (enumerator->enumerate(enumerator, &group, &current))
	{
		if (current == curve)
		{
			enumerator->destroy(enumerator);
			return group;
		}
	}
	enumerator->destroy(enumerator);
	return 0;
}

/**
 * Process a Key Exchange message using EC Diffie Hellman
 */
static status_t process_ec_key_exchange(private_tls_peer_t *this,
										bio_reader_t *reader)
{
	diffie_hellman_group_t group;
	public_key_t *public;
	uint8_t type;
	uint16_t curve;
	chunk_t pub, chunk;

	chunk = reader->peek(reader);
	if (!reader->read_uint8(reader, &type))
	{
		DBG1(DBG_TLS, "received invalid Server Key Exchange");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}
	if (type != TLS_ECC_NAMED_CURVE)
	{
		DBG1(DBG_TLS, "ECDH curve type %N not supported",
			 tls_ecc_curve_type_names, type);
		this->alert->add(this->alert, TLS_FATAL, TLS_HANDSHAKE_FAILURE);
		return NEED_MORE;
	}
	if (!reader->read_uint16(reader, &curve) ||
		!reader->read_data8(reader, &pub) || pub.len == 0)
	{
		DBG1(DBG_TLS, "received invalid Server Key Exchange");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}

	group = curve_to_ec_group(this, curve);
	if (!group)
	{
		DBG1(DBG_TLS, "ECDH curve %N not supported",
			 tls_named_group_names, curve);
		this->alert->add(this->alert, TLS_FATAL, TLS_HANDSHAKE_FAILURE);
		return NEED_MORE;
	}

	public = find_public_key(this);
	if (!public)
	{
		DBG1(DBG_TLS, "no TLS public key found for server '%Y'", this->server);
		this->alert->add(this->alert, TLS_FATAL, TLS_CERTIFICATE_UNKNOWN);
		return NEED_MORE;
	}

	chunk.len = 4 + pub.len;
	chunk = chunk_cat("ccc", chunk_from_thing(this->client_random),
					  chunk_from_thing(this->server_random), chunk);
	if (!this->crypto->verify(this->crypto, public, reader, chunk))
	{
		public->destroy(public);
		free(chunk.ptr);
		DBG1(DBG_TLS, "verifying DH parameters failed");
		this->alert->add(this->alert, TLS_FATAL, TLS_BAD_CERTIFICATE);
		return NEED_MORE;
	}
	public->destroy(public);
	free(chunk.ptr);

	this->dh = lib->crypto->create_dh(lib->crypto, group);
	if (!this->dh)
	{
		DBG1(DBG_TLS, "DH group %N not supported",
			 diffie_hellman_group_names, group);
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}

	if (pub.ptr[0] != TLS_ANSI_UNCOMPRESSED)
	{
		DBG1(DBG_TLS, "DH point format '%N' not supported",
			 tls_ansi_point_format_names, pub.ptr[0]);
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}
	if (!this->dh->set_other_public_value(this->dh, chunk_skip(pub, 1)))
	{
		DBG1(DBG_TLS, "applying DH public value failed");
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}

	this->state = STATE_KEY_EXCHANGE_RECEIVED;
	return NEED_MORE;
}

/**
 * Process a Server Key Exchange
 */
static status_t process_key_exchange(private_tls_peer_t *this,
									 bio_reader_t *reader)
{
	diffie_hellman_group_t group;

	this->crypto->append_handshake(this->crypto,
								TLS_SERVER_KEY_EXCHANGE, reader->peek(reader));

	group = this->crypto->get_dh_group(this->crypto);
	if (group == MODP_NONE)
	{
		DBG1(DBG_TLS, "received Server Key Exchange, but not required "
			 "for current suite");
		this->alert->add(this->alert, TLS_FATAL, TLS_HANDSHAKE_FAILURE);
		return NEED_MORE;
	}
	if (diffie_hellman_group_is_ec(group))
	{
		return process_ec_key_exchange(this, reader);
	}
	return process_modp_key_exchange(this, reader);
}

/**
 * Process a Certificate Request message
 */
static status_t process_certreq(private_tls_peer_t *this, bio_reader_t *reader)
{
	chunk_t types, hashsig, data;
	bio_reader_t *authorities;
	identification_t *id;
	certificate_t *cert;

	if (!this->peer)
	{
		DBG1(DBG_TLS, "server requested a certificate, but client "
			 "authentication disabled");
	}
	this->crypto->append_handshake(this->crypto,
								TLS_CERTIFICATE_REQUEST, reader->peek(reader));

	if (!reader->read_data8(reader, &types))
	{
		DBG1(DBG_TLS, "certreq message header invalid");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}
	this->cert_types = chunk_clone(types);
	if (this->tls->get_version_max(this->tls) >= TLS_1_2)
	{
		if (!reader->read_data16(reader, &hashsig))
		{
			DBG1(DBG_TLS, "certreq message invalid");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
			return NEED_MORE;
		}
		this->hashsig = chunk_clone(hashsig);
	}
	if (!reader->read_data16(reader, &data))
	{
		DBG1(DBG_TLS, "certreq message invalid");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}
	authorities = bio_reader_create(data);
	while (authorities->remaining(authorities))
	{
		if (!authorities->read_data16(authorities, &data))
		{
			DBG1(DBG_TLS, "certreq message invalid");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
			authorities->destroy(authorities);
			return NEED_MORE;
		}
		if (this->peer)
		{
			id = identification_create_from_encoding(ID_DER_ASN1_DN, data);
			cert = lib->credmgr->get_cert(lib->credmgr,
										  CERT_X509, KEY_ANY, id, TRUE);
			if (cert)
			{
				DBG1(DBG_TLS, "received TLS cert request for '%Y", id);
				this->peer_auth->add(this->peer_auth, AUTH_RULE_CA_CERT, cert);
			}
			else
			{
				DBG1(DBG_TLS, "received TLS cert request for unknown CA '%Y'", id);
			}
			id->destroy(id);
		}
	}
	authorities->destroy(authorities);
	this->state = STATE_CERTREQ_RECEIVED;
	return NEED_MORE;
}

/**
 * Process Hello Done message
 */
static status_t process_hello_done(private_tls_peer_t *this,
								   bio_reader_t *reader)
{
	this->crypto->append_handshake(this->crypto,
								   TLS_SERVER_HELLO_DONE, reader->peek(reader));
	this->state = STATE_HELLO_DONE;
	return NEED_MORE;
}

/**
 * Process finished message
 */
static status_t process_finished(private_tls_peer_t *this, bio_reader_t *reader)
{
	chunk_t received, verify_data;
	char buf[12];
	uint32_t hash_length;

	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		if (!reader->read_data(reader, sizeof(buf), &received))
		{
			DBG1(DBG_TLS, "received server finished too short");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
			return NEED_MORE;
		}
		if (!this->crypto->calculate_finished(this->crypto, "server finished",
											  buf))
		{
			DBG1(DBG_TLS, "calculating server finished failed");
			this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
			return NEED_MORE;
		}
		if (!chunk_equals_const(received, chunk_from_thing(buf)))
		{
			DBG1(DBG_TLS, "received server finished invalid");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECRYPT_ERROR);
			return NEED_MORE;
		}
	}
	else
	{
		hash_length = reader->remaining(reader);
		if (!reader->read_data(reader, hash_length, &received))
		{
			DBG1(DBG_TLS, "received server finished too short");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
			return NEED_MORE;
		}
		if (!this->crypto->calculate_finished_tls13(this->crypto, true,
			&verify_data))
		{
			DBG1(DBG_TLS, "calculating server finished failed");
			this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
			return NEED_MORE;
		}
		if (!chunk_equals(received, verify_data))
		{
			DBG1(DBG_TLS, "received server finished invalid");
			this->alert->add(this->alert, TLS_FATAL, TLS_DECRYPT_ERROR);
			return NEED_MORE;
		}
	}
	this->state = STATE_FINISHED_RECEIVED;
	this->crypto->append_handshake(this->crypto, TLS_FINISHED, received);

	return NEED_MORE;
}

/**
 * Process New Session Ticket message
 */
static status_t process_new_session_ticket(private_tls_peer_t *this,
										   bio_reader_t *reader)
{
	uint32_t ticket_lifetime, ticket_age_add;
	chunk_t ticket_nonce, ticket, extensions;

	if (!reader->read_uint32(reader, &ticket_lifetime) ||
		!reader->read_uint32(reader, &ticket_age_add) ||
		!reader->read_data8(reader, &ticket_nonce) ||
		!reader->read_data16(reader, &ticket) ||
		!reader->read_data16(reader, &extensions))
	{
		DBG1(DBG_TLS, "received invalid NewSessionTicket");
		this->alert->add(this->alert, TLS_FATAL, TLS_DECODE_ERROR);
		return NEED_MORE;
	}
	return NEED_MORE;
}

METHOD(tls_handshake_t, process, status_t,
	private_tls_peer_t *this, tls_handshake_type_t type, bio_reader_t *reader)
{
	tls_handshake_type_t expected;

	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		switch (this->state)
		{
			case STATE_HELLO_SENT:
				if (type == TLS_SERVER_HELLO)
				{
					return process_server_hello(this, reader);
				}
				expected = TLS_SERVER_HELLO;
				break;
			case STATE_HELLO_RECEIVED:
				if (type == TLS_CERTIFICATE)
				{
					return process_certificate(this, reader);
				}
				expected = TLS_CERTIFICATE;
				break;
			case STATE_CERT_RECEIVED:
				if (type == TLS_SERVER_KEY_EXCHANGE)
				{
					return process_key_exchange(this, reader);
				}
				/* fall through since TLS_SERVER_KEY_EXCHANGE is optional */
			case STATE_KEY_EXCHANGE_RECEIVED:
				if (type == TLS_CERTIFICATE_REQUEST)
				{
					return process_certreq(this, reader);
				}
				/* no cert request, server does not want to authenticate us */
				DESTROY_IF(this->peer);
				this->peer = NULL;
				/* fall through since TLS_CERTIFICATE_REQUEST is optional */
			case STATE_CERTREQ_RECEIVED:
				if (type == TLS_SERVER_HELLO_DONE)
				{
					return process_hello_done(this, reader);
				}
				expected = TLS_SERVER_HELLO_DONE;
				break;
			case STATE_CIPHERSPEC_CHANGED_IN:
				if (type == TLS_FINISHED)
				{
					return process_finished(this, reader);
				}
				expected = TLS_FINISHED;
				break;
			default:
				DBG1(DBG_TLS, "TLS %N not expected in current state",
					 tls_handshake_type_names, type);
				this->alert->add(this->alert, TLS_FATAL, TLS_UNEXPECTED_MESSAGE);
				return NEED_MORE;
		}
	}
	else
	{
		switch (this->state)
		{
			case STATE_HELLO_SENT:
				if (type == TLS_SERVER_HELLO)
				{
					return process_server_hello(this, reader);
				}
				expected = TLS_SERVER_HELLO;
				break;
			case STATE_CIPHERSPEC_CHANGED_IN:
			case STATE_HELLO_RECEIVED:
				if (type == TLS_ENCRYPTED_EXTENSIONS)
				{
					return process_encrypted_extensions(this, reader);
				}
				expected = TLS_ENCRYPTED_EXTENSIONS;
				break;
			case STATE_ENCRYPTED_EXTENSIONS_RECEIVED:
				if (type == TLS_CERTIFICATE)
				{
					return process_certificate(this, reader);
				}
				expected = TLS_CERTIFICATE;
				break;
			case STATE_CERT_RECEIVED:
				if (type == TLS_CERTIFICATE_VERIFY)
				{
					return process_cert_verify(this, reader);
				}
				expected = TLS_CERTIFICATE_VERIFY;
				break;
			case STATE_CERT_VERIFY_RECEIVED:
				if (type == TLS_FINISHED)
				{
					return process_finished(this, reader);
				}
				expected = TLS_FINISHED;
				break;
			case STATE_FINISHED_RECEIVED:
				return NEED_MORE;
			case STATE_FINISHED_SENT_KEY_SWITCHED:
				if (type == TLS_NEW_SESSION_TICKET)
				{
					return process_new_session_ticket(this, reader);
				}
				expected = TLS_NEW_SESSION_TICKET;
				break;
			default:
				DBG1(DBG_TLS, "TLS %N not expected in current state",
					 tls_handshake_type_names, type);
				this->alert->add(this->alert, TLS_FATAL, TLS_UNEXPECTED_MESSAGE);
				return NEED_MORE;
		}
	}
	DBG1(DBG_TLS, "TLS %N expected, but received %N",
		 tls_handshake_type_names, expected, tls_handshake_type_names, type);
	this->alert->add(this->alert, TLS_FATAL, TLS_UNEXPECTED_MESSAGE);
	return NEED_MORE;
}

/**
 * Send a client hello
 */
static status_t send_client_hello(private_tls_peer_t *this,
							tls_handshake_type_t *type, bio_writer_t *writer)
{
	tls_cipher_suite_t *suites;
	bio_writer_t *extensions, *curves = NULL;
	tls_version_t version_max, version_min;
	tls_named_group_t curve;
	enumerator_t *enumerator;
	int count, i, v;
	rng_t *rng;
	chunk_t pub;
	u_int8_t nof_tls_versions;

	htoun32(&this->client_random, time(NULL));
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng ||
		!rng->get_bytes(rng, sizeof(this->client_random) - 4,
						this->client_random + 4))
	{
		DBG1(DBG_TLS, "failed to generate client random");
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		DESTROY_IF(rng);
		return NEED_MORE;
	}
	rng->destroy(rng);

	/* Client Key Generation */
	this->dh = lib->crypto->create_dh(lib->crypto, CURVE_25519);

	/* TLS version_max in Handshake Protocol */
	version_max = this->tls->get_version_max(this->tls);
	version_min = this->tls->get_version_min(this->tls);
	if (version_max < TLS_1_3)
	{
		this->hello_version = version_max;
	}
	else
	{
		this->hello_version = TLS_1_2;
	}
	writer->write_uint16(writer, this->hello_version);
	writer->write_data(writer, chunk_from_thing(this->client_random));

	/* session identifier */
	this->session = this->crypto->get_session(this->crypto, this->server);
	writer->write_data8(writer, this->session);

	/* add TLS cipher suites */
	count = this->crypto->get_cipher_suites(this->crypto, &suites);
	writer->write_uint16(writer, count * 2);
	for (i = 0; i < count; i++)
	{
		writer->write_uint16(writer, suites[i]);
	}

	/* NULL compression only */
	writer->write_uint8(writer, 1);
	writer->write_uint8(writer, 0);

	extensions = bio_writer_create(32);

	/* Extensions */
	if (this->server->get_type(this->server) == ID_FQDN)
	{
		bio_writer_t *names;

		DBG2(DBG_TLS, "sending extension: Server Name Indication for '%Y'", this->server);
		names = bio_writer_create(8);
		names->write_uint8(names, TLS_NAME_TYPE_HOST_NAME);
		names->write_data16(names, this->server->get_encoding(this->server));
		names->wrap16(names);
		extensions->write_uint16(extensions, TLS_EXT_SERVER_NAME);
		extensions->write_data16(extensions, names->get_buf(names));
		names->destroy(names);
	}

	DBG2(DBG_TLS, "sending extension: Supported Groups");
	/* add supported elliptic curves, if any */
	enumerator = this->crypto->create_ec_enumerator(this->crypto);
	while (enumerator->enumerate(enumerator, NULL, &curve))
	{
		if (!curves)
		{
			extensions->write_uint16(extensions, TLS_EXT_SUPPORTED_GROUPS);
			curves = bio_writer_create(16);
		}
		curves->write_uint16(curves, curve);
	}
	enumerator->destroy(enumerator);
	if (curves)
	{
		if (version_max == TLS_1_3)
		{
			curves->write_uint16(curves, TLS_CURVE25519);
		}
		curves->wrap16(curves);
		extensions->write_data16(extensions, curves->get_buf(curves));
		curves->destroy(curves);

		/* if we support curves, add point format extension */
		extensions->write_uint16(extensions, TLS_EXT_EC_POINT_FORMATS);
		extensions->write_uint16(extensions, 2);
		extensions->write_uint8(extensions, 1);
		extensions->write_uint8(extensions, TLS_EC_POINT_UNCOMPRESSED);
	}

	DBG2(DBG_TLS, "sending extension: %N",
		tls_extension_names, TLS_EXT_SUPPORTED_VERSIONS);
	nof_tls_versions = (version_max - version_min + 1)*2;
	extensions->write_uint16(extensions, TLS_EXT_SUPPORTED_VERSIONS);
	extensions->write_uint16(extensions, nof_tls_versions+1);
	extensions->write_uint8(extensions, nof_tls_versions);
	for (v = version_max; v >= version_min; v--)
	{
		extensions->write_uint16(extensions, v);
		nof_tls_versions += 2;
	}

	DBG2(DBG_TLS, "sending extension: %N",
		tls_extension_names, TLS_EXT_SIGNATURE_ALGORITHMS);
	extensions->write_uint16(extensions, TLS_EXT_SIGNATURE_ALGORITHMS);
	this->crypto->get_signature_algorithms(this->crypto, extensions);

	DBG2(DBG_TLS, "sending extension: %N",
		 tls_extension_names, TLS_EXT_KEY_SHARE);
	if (!this->dh->get_my_public_value(this->dh, &pub))
	{
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}
	extensions->write_uint16(extensions, TLS_EXT_KEY_SHARE);
	extensions->write_uint16(extensions, pub.len+6);
	extensions->write_uint16(extensions, pub.len+4);
	extensions->write_uint16(extensions, TLS_CURVE25519);
	extensions->write_uint16(extensions, pub.len);
	extensions->write_data(extensions, pub);
	free(pub.ptr);

	writer->write_data16(writer, extensions->get_buf(extensions));
	extensions->destroy(extensions);

	*type = TLS_CLIENT_HELLO;
	this->state = STATE_HELLO_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Find a private key suitable to sign Certificate Verify
 */
static private_key_t *find_private_key(private_tls_peer_t *this)
{
	private_key_t *key = NULL;
	bio_reader_t *reader;
	key_type_t type;
	uint8_t cert;

	if (!this->peer)
	{
		return NULL;
	}
	reader = bio_reader_create(this->cert_types);
	while (reader->remaining(reader) && reader->read_uint8(reader, &cert))
	{
		switch (cert)
		{
			case TLS_RSA_SIGN:
				type = KEY_RSA;
				break;
			case TLS_ECDSA_SIGN:
				type = KEY_ECDSA;
				break;
			default:
				continue;
		}
		key = lib->credmgr->get_private(lib->credmgr, type,
										this->peer, this->peer_auth);
		if (key)
		{
			break;
		}
	}
	reader->destroy(reader);
	return key;
}

/**
 * Send Certificate
 */
static status_t send_certificate(private_tls_peer_t *this,
							tls_handshake_type_t *type, bio_writer_t *writer)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	auth_rule_t rule;
	bio_writer_t *certs;
	chunk_t data;

	this->private = find_private_key(this);
	if (!this->private)
	{
		DBG1(DBG_TLS, "no TLS peer certificate found for '%Y', "
			 "skipping client authentication", this->peer);
		this->peer->destroy(this->peer);
		this->peer = NULL;
	}

	/* generate certificate payload */
	certs = bio_writer_create(256);
	if (this->peer)
	{
		cert = this->peer_auth->get(this->peer_auth, AUTH_RULE_SUBJECT_CERT);
		if (cert)
		{
			if (cert->get_encoding(cert, CERT_ASN1_DER, &data))
			{
				DBG1(DBG_TLS, "sending TLS peer certificate '%Y'",
					 cert->get_subject(cert));
				certs->write_data24(certs, data);
				free(data.ptr);
			}
		}
		enumerator = this->peer_auth->create_enumerator(this->peer_auth);
		while (enumerator->enumerate(enumerator, &rule, &cert))
		{
			if (rule == AUTH_RULE_IM_CERT)
			{
				if (cert->get_encoding(cert, CERT_ASN1_DER, &data))
				{
					DBG1(DBG_TLS, "sending TLS intermediate certificate '%Y'",
						 cert->get_subject(cert));
					certs->write_data24(certs, data);
					free(data.ptr);
				}
			}
		}
		enumerator->destroy(enumerator);
	}

	writer->write_data24(writer, certs->get_buf(certs));
	certs->destroy(certs);

	*type = TLS_CERTIFICATE;
	this->state = STATE_CERT_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send client key exchange, using premaster encryption
 */
static status_t send_key_exchange_encrypt(private_tls_peer_t *this,
							tls_handshake_type_t *type, bio_writer_t *writer)
{
	public_key_t *public;
	rng_t *rng;
	char premaster[48];
	chunk_t encrypted;

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng || !rng->get_bytes(rng, sizeof(premaster) - 2, premaster + 2))
	{
		DBG1(DBG_TLS, "failed to generate TLS premaster secret");
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		DESTROY_IF(rng);
		return NEED_MORE;
	}
	rng->destroy(rng);
	htoun16(premaster, this->hello_version);

	if (!this->crypto->derive_secrets(this->crypto, chunk_from_thing(premaster),
									  this->session, this->server,
									  chunk_from_thing(this->client_random),
									  chunk_from_thing(this->server_random)))
	{
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}

	public = find_public_key(this);
	if (!public)
	{
		DBG1(DBG_TLS, "no TLS public key found for server '%Y'", this->server);
		this->alert->add(this->alert, TLS_FATAL, TLS_CERTIFICATE_UNKNOWN);
		return NEED_MORE;
	}
	if (!public->encrypt(public, ENCRYPT_RSA_PKCS1,
						 chunk_from_thing(premaster), &encrypted))
	{
		public->destroy(public);
		DBG1(DBG_TLS, "encrypting TLS premaster secret failed");
		this->alert->add(this->alert, TLS_FATAL, TLS_BAD_CERTIFICATE);
		return NEED_MORE;
	}
	public->destroy(public);

	writer->write_data16(writer, encrypted);
	free(encrypted.ptr);

	*type = TLS_CLIENT_KEY_EXCHANGE;
	this->state = STATE_KEY_EXCHANGE_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send client key exchange, using DHE exchange
 */
static status_t send_key_exchange_dhe(private_tls_peer_t *this,
							tls_handshake_type_t *type, bio_writer_t *writer)
{
	chunk_t premaster, pub;

	if (!this->dh->get_shared_secret(this->dh, &premaster))
	{
		DBG1(DBG_TLS, "calculating premaster from DH failed");
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}
	if (!this->crypto->derive_secrets(this->crypto, premaster,
									  this->session, this->server,
									  chunk_from_thing(this->client_random),
									  chunk_from_thing(this->server_random)))
	{
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		chunk_clear(&premaster);
		return NEED_MORE;
	}
	chunk_clear(&premaster);

	if (!this->dh->get_my_public_value(this->dh, &pub))
	{
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}
	if (this->dh->get_dh_group(this->dh) == MODP_CUSTOM)
	{
		writer->write_data16(writer, pub);
	}
	else
	{	/* ECP uses 8bit length header only, but a point format */
		writer->write_uint8(writer, pub.len + 1);
		writer->write_uint8(writer, TLS_ANSI_UNCOMPRESSED);
		writer->write_data(writer, pub);
	}
	free(pub.ptr);

	*type = TLS_CLIENT_KEY_EXCHANGE;
	this->state = STATE_KEY_EXCHANGE_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send client key exchange, depending on suite
 */
static status_t send_key_exchange(private_tls_peer_t *this,
							tls_handshake_type_t *type, bio_writer_t *writer)
{
	if (this->dh)
	{
		return send_key_exchange_dhe(this, type, writer);
	}
	return send_key_exchange_encrypt(this, type, writer);
}

/**
 * Send certificate verify
 */
static status_t send_certificate_verify(private_tls_peer_t *this,
							tls_handshake_type_t *type, bio_writer_t *writer)
{
	if (!this->private ||
		!this->crypto->sign_handshake(this->crypto, this->private,
									  writer, this->hashsig))
	{
		DBG1(DBG_TLS, "creating TLS Certificate Verify signature failed");
		this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
		return NEED_MORE;
	}

	*type = TLS_CERTIFICATE_VERIFY;
	this->state = STATE_VERIFY_SENT;
	this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	return NEED_MORE;
}

/**
 * Send Finished
 */
static status_t send_finished(private_tls_peer_t *this,
							  tls_handshake_type_t *type, bio_writer_t *writer)
{
	chunk_t verify_data;

	*type = TLS_FINISHED;

	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		char buf[12];

		if (!this->crypto->calculate_finished(this->crypto, "client finished", buf))
		{
			DBG1(DBG_TLS, "calculating client finished data failed");
			this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
			return NEED_MORE;
		}

		writer->write_data(writer, chunk_from_thing(buf));
		this->crypto->append_handshake(this->crypto, *type, writer->get_buf(writer));
	}
	else
	{
		if (!this->crypto->calculate_finished_tls13(this->crypto, false,
		   &verify_data))
		{
			DBG1(DBG_TLS, "calculating client finished data failed");
			this->alert->add(this->alert, TLS_FATAL, TLS_INTERNAL_ERROR);
			return NEED_MORE;
		}

		writer->write_data(writer, verify_data);
	}

	this->state = STATE_FINISHED_SENT;
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_peer_t *this, tls_handshake_type_t *type, bio_writer_t *writer)
{
	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		switch (this->state)
		{
			case STATE_INIT:
				return send_client_hello(this, type, writer);
			case STATE_HELLO_DONE:
				if (this->peer)
				{
					return send_certificate(this, type, writer);
				}
				/* otherwise fall through to next state */
			case STATE_CERT_SENT:
				return send_key_exchange(this, type, writer);
			case STATE_KEY_EXCHANGE_SENT:
				if (this->peer)
				{
					return send_certificate_verify(this, type, writer);
				}
				else
				{
					return INVALID_STATE;
				}
			case STATE_CIPHERSPEC_CHANGED_OUT:
				return send_finished(this, type, writer);
			default:
				return INVALID_STATE;
		}
	}
	else
	{
		switch (this->state)
		{
			case STATE_INIT:
				return send_client_hello(this, type, writer);
			case STATE_HELLO_DONE:
				/* otherwise fall through to next state */
			case STATE_CIPHERSPEC_CHANGED_OUT:
			case STATE_FINISHED_RECEIVED:
				/* fall through since legacy TLS and TLS 1.3
				* expect the same message */
				return send_finished(this, type, writer);
			case STATE_FINISHED_SENT:
				this->crypto->derive_app_secret(this->crypto);
				this->crypto->change_cipher(this->crypto, TRUE);
				this->crypto->change_cipher(this->crypto, FALSE);
				this->state = STATE_FINISHED_SENT_KEY_SWITCHED;
				return SUCCESS;
			case STATE_FINISHED_SENT_KEY_SWITCHED:
				return SUCCESS;
			default:
				return INVALID_STATE;
		}
	}

}

METHOD(tls_handshake_t, cipherspec_changed, bool,
	private_tls_peer_t *this, bool inbound)
{
	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		if (inbound)
		{
			if (this->resume)
			{
				return this->state == STATE_HELLO_RECEIVED;
			}
			return this->state == STATE_FINISHED_SENT;
		}
		else
		{
			if (this->resume)
			{
				return this->state == STATE_FINISHED_RECEIVED;
			}
			if (this->peer)
			{
				return this->state == STATE_VERIFY_SENT;
			}
			return this->state == STATE_KEY_EXCHANGE_SENT;

		}
	}
	else
	{
		if (inbound)
		{
			return this->state == STATE_HELLO_RECEIVED;
		}
		else
		{
			return FALSE;
		}
	}

}

METHOD(tls_handshake_t, change_cipherspec, void,
	private_tls_peer_t *this, bool inbound)
{
	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		this->crypto->change_cipher(this->crypto, inbound);
	}

	if (inbound)
	{
		this->state = STATE_CIPHERSPEC_CHANGED_IN;
	}
	else
	{
		this->state = STATE_CIPHERSPEC_CHANGED_OUT;
	}
}

METHOD(tls_handshake_t, finished, bool,
	private_tls_peer_t *this)
{
	if (this->tls->get_version_max(this->tls) < TLS_1_3)
	{
		if (this->resume)
		{
		return this->state == STATE_FINISHED_SENT;
		}

		return this->state == STATE_FINISHED_RECEIVED;
	}
	else
	{
		return this->state == STATE_FINISHED_SENT_KEY_SWITCHED;
	}
}

METHOD(tls_handshake_t, get_peer_id, identification_t*,
	private_tls_peer_t *this)
{
	return this->peer;
}

METHOD(tls_handshake_t, get_server_id, identification_t*,
	private_tls_peer_t *this)
{
	return this->server;
}

METHOD(tls_handshake_t, get_auth, auth_cfg_t*,
	private_tls_peer_t *this)
{
	return this->server_auth;
}

METHOD(tls_handshake_t, destroy, void,
	private_tls_peer_t *this)
{
	DESTROY_IF(this->private);
	DESTROY_IF(this->dh);
	DESTROY_IF(this->peer);
	this->server->destroy(this->server);
	this->peer_auth->destroy(this->peer_auth);
	this->server_auth->destroy(this->server_auth);
	free(this->hashsig.ptr);
	free(this->cert_types.ptr);
	free(this->session.ptr);
	free(this);
}

/**
 * See header
 */
tls_peer_t *tls_peer_create(tls_t *tls, tls_crypto_t *crypto, tls_alert_t *alert,
							identification_t *peer, identification_t *server)
{
	private_tls_peer_t *this;

	INIT(this,
		.public = {
			.handshake = {
				.process = _process,
				.build = _build,
				.cipherspec_changed = _cipherspec_changed,
				.change_cipherspec = _change_cipherspec,
				.finished = _finished,
				.get_peer_id = _get_peer_id,
				.get_server_id = _get_server_id,
				.get_auth = _get_auth,
				.destroy = _destroy,
			},
		},
		.state = STATE_INIT,
		.tls = tls,
		.crypto = crypto,
		.alert = alert,
		.peer = peer ? peer->clone(peer) : NULL,
		.server = server->clone(server),
		.peer_auth = auth_cfg_create(),
		.server_auth = auth_cfg_create(),
	);

	return &this->public;
}
