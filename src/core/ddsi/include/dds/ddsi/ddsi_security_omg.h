/*
 * Copyright(c) 2006 to 2018 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#ifndef DDSI_OMG_SECURITY_H
#define DDSI_OMG_SECURITY_H

#include "dds/ddsi/q_entity.h"
#include "dds/ddsi/q_plist.h"
#include "dds/ddsi/q_globals.h"
#include "dds/ddsi/q_xmsg.h"

#if defined (__cplusplus)
extern "C" {
#endif

#ifdef DDSI_INCLUDE_SECURITY

typedef struct nn_msg_sec_info {
  uint32_t encoded:1;
  uint32_t use_rtps_encoding:1;
  int64_t src_pp_handle;
  int64_t dst_pp_handle;
} nn_msg_sec_info_t;


bool q_omg_security_enabled(void);

/**
 * @brief Check if security is enabled for the participant.
 *
 * @param[in] pp  Participant to check if it is secure.
 *
 * @returns bool
 * @retval true   Participant is secure
 * @retval false  Participant is not secure
 */
bool q_omg_participant_is_secure(const struct participant *pp);

/* TODO: Add header. */
bool q_omg_proxyparticipant_is_authenticated(const struct proxy_participant *proxy_pp);

/* TODO: Add header. */
int64_t q_omg_security_get_local_participant_handle(struct participant *pp);

/* TODO: Add header. */
int64_t q_omg_security_get_remote_participant_handle(struct proxy_participant *proxypp);

/**
 * @brief Get security info flags of the given writer.
 *
 * @param[in]  wr    Writer to get the security info from.
 * @param[out] info  The security info.
 *
 * @returns bool
 * @retval true   Security info set.
 * @retval false  Security info not set (probably unsecure writer).
 */
bool q_omg_get_writer_security_info(const struct writer *wr, nn_security_info_t *info);

/**
 * @brief Get security info flags of the given reader.
 *
 * @param[in]  rd    Reader to get the security info from.
 * @param[out] info  The security info.
 *
 * @returns bool
 * @retval true   Security info set.
 * @retval false  Security info not set (probably unsecure reader).
 */
bool q_omg_get_reader_security_info(const struct reader *rd, nn_security_info_t *info);

/**
 * @brief Return the builtin writer id for this readers' discovery.
 *
 * Return builtin entity id of the writer to use for the subscription
 * discovery information.
 * Depending on whether the discovery is protected or not (for the
 * given reader), either the default writer or protected writer needs
 * to be used.
 *
 * @param[in] rd Reader to determine the subscription writer from.
 *
 * @returns unsigned
 * @retval NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER
 * @retval NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER
 */
unsigned determine_subscription_writer(const struct reader *rd);

/**
 * @brief Return the builtin writer id for this writers' discovery.
 *
 * Return builtin entity id of the writer to use for the publication
 * discovery information.
 * Depending on whether the discovery is protected or not (for the
 * given writer), either the default writer or protected writer needs
 * to be used.
 *
 * @param[in] wr Writer to determine the publication writer from.
 *
 * @returns unsigned
 * @retval NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER
 * @retval NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER
 */
unsigned determine_publication_writer(const struct writer *wr);

/**
 * @brief Determine if the proxy participant is allowed to be deleted
 *        by the given writer.
 *
 * If an proxy participant is authenticated, it is only allowed to
 * to deleted when a dispose is received from the proper protected
 * discovery writer.
 *
 * @param[in] gv           Used for tracing.
 * @param[in] guid         Guid of the proxy participant to be deleted.
 * @param[in] pwr_entityid Writer that send the dispose.
 *
 * @returns bool
 * @retval true   The proxy participant may be deleted.
 * @retval false  The proxy participant may not be deleted by this writer.
 */
bool
allow_proxy_participant_deletion(
  struct q_globals * const gv,
  const struct ddsi_guid *guid,
  const ddsi_entityid_t pwr_entityid);

/* TODO: Add header. */
bool
q_omg_security_is_remote_rtps_protected(
  struct proxy_participant *proxy_pp,
  ddsi_entityid_t entityid);

/* TODO: Add header. */
bool
q_omg_security_is_local_rtps_protected(
  struct participant *pp,
  ddsi_entityid_t entityid);

/* TODO: Add header. */
void
q_omg_get_proxy_participant_security_info(
  struct proxy_participant *prd,
  const nn_plist_t *plist,
  nn_security_info_t *info);

/* TODO: Add header. */
void
q_omg_get_proxy_reader_security_info(
  struct proxy_reader *prd,
  const nn_plist_t *plist,
  nn_security_info_t *info);

/* TODO: Add header. */
void
q_omg_get_proxy_writer_security_info(
  struct proxy_writer *pwr,
  const nn_plist_t *plist,
  nn_security_info_t *info);

/* TODO: Add header. */
bool
q_omg_security_decode_serialized_payload(
  struct proxy_writer *pwr,
  const unsigned char *src_buf,
  const unsigned int   src_len,
  unsigned char     **dst_buf,
  unsigned int       *dst_len);

/* TODO: Add header. */
bool
q_omg_security_decode_submessage(
  const ddsi_guid_prefix_t* const src_prefix,
  const ddsi_guid_prefix_t* const dst_prefix,
  const unsigned char   *src_buf,
  const unsigned int     src_len,
  unsigned char        **dst_buf,
  unsigned int          *dst_len);

/* TODO: Add header. */
bool
q_omg_security_encode_rtps_message(
  int64_t                 src_handle,
  ddsi_guid_t            *src_guid,
  const unsigned char    *src_buf,
  const unsigned int      src_len,
  unsigned char        **dst_buf,
  unsigned int          *dst_len,
  int64_t                dst_handle);

/* TODO: Add header. */
bool
q_omg_security_decode_rtps_message(
  struct proxy_participant *proxypp,
  const unsigned char      *src_buf,
  const unsigned int        src_len,
  unsigned char          **dst_buf,
  unsigned int            *dst_len);

/* This will replace the vec content with encoded data when necessary.
 *
 * encoding(    not needed) -> return( true), vec(untouched), buf(NULL)
 * encoding(needed&success) -> return( true), vec( buf(new))
 * encoding(needed&failure) -> return(false), vec(untouched), buf(NULL)
 */
bool
encode_payload(
  struct writer *wr,
  ddsrt_iovec_t *vec,
  unsigned char **buf);

/* TODO: Add header. */
void
encode_datareader_submsg(
  struct nn_xmsg *msg,
  struct nn_xmsg_marker sm_marker,
  struct proxy_writer *pwr,
  const struct ddsi_guid *rd_guid);

/* TODO: Add header. */
void
encode_datawriter_submsg(
  struct nn_xmsg *msg,
  struct nn_xmsg_marker sm_marker,
  struct writer *wr);


#else /* DDSI_INCLUDE_SECURITY */

#include "dds/ddsi/q_unused.h"

typedef char nn_msg_sec_info_t;

inline bool
q_omg_participant_is_secure(
  UNUSED_ARG(const struct participant *pp))
{
  return false;
}

inline unsigned
determine_subscription_writer(
  UNUSED_ARG(const struct reader *rd))
{
  return NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER;
}

inline unsigned
determine_publication_writer(
  UNUSED_ARG(const struct writer *wr))
{
  return NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER;
}

inline bool
allow_proxy_participant_deletion(
  UNUSED_ARG(struct q_globals * const gv),
  UNUSED_ARG(const struct ddsi_guid *guid),
  UNUSED_ARG(const ddsi_entityid_t pwr_entityid))
{
  return true;
}

#endif /* DDSI_INCLUDE_SECURITY */

#if defined (__cplusplus)
}
#endif

#endif /* DDSI_OMG_SECURITY_H */
