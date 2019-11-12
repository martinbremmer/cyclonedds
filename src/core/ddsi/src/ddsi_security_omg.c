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
#ifdef DDSI_INCLUDE_SECURITY

#include <string.h>

#include "dds/ddsrt/misc.h"
#include "dds/ddsrt/heap.h"

#include "dds/ddsi/q_unused.h"
#include "dds/ddsi/ddsi_security_omg.h"


static bool endpoint_is_DCPSParticipantSecure(const ddsi_guid_t *guid)
{
  return ((guid->entityid.u == NN_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER) ||
          (guid->entityid.u == NN_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_READER) );
}

static bool endpoint_is_DCPSPublicationsSecure(const ddsi_guid_t *guid)
{
  return ((guid->entityid.u == NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER) ||
          (guid->entityid.u == NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_READER) );
}

static bool endpoint_is_DCPSSubscriptionsSecure(const ddsi_guid_t *guid)
{
  return ((guid->entityid.u == NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER) ||
          (guid->entityid.u == NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_READER) );
}

static bool endpoint_is_DCPSParticipantStatelessMessage(const ddsi_guid_t *guid)
{
  return ((guid->entityid.u == NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER) ||
          (guid->entityid.u == NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER) );
}

static bool endpoint_is_DCPSParticipantMessageSecure(const ddsi_guid_t *guid)
{
  return ((guid->entityid.u == NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER) ||
          (guid->entityid.u == NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER) );
}

static bool endpoint_is_DCPSParticipantVolatileMessageSecure(const ddsi_guid_t *guid)
{
#if 1
  /* TODO: volatile endpoint. */
  DDSRT_UNUSED_ARG(guid);
  return false;
#else
  return ((guid->entityid.u == NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER) ||
          (guid->entityid.u == NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_READER) );
#endif
}


bool
q_omg_security_enabled(void)
{
  return false;
}

bool
q_omg_participant_is_secure(
  const struct participant *pp)
{
  /* TODO: Register local participant. */
  DDSRT_UNUSED_ARG(pp);
  return false;
}

static bool
q_omg_writer_is_discovery_protected(
  const struct writer *wr)
{
  /* TODO: Register local writer. */
  DDSRT_UNUSED_ARG(wr);
  return false;
}

static bool
q_omg_reader_is_discovery_protected(
  const struct reader *rd)
{
  /* TODO: Register local reader. */
  DDSRT_UNUSED_ARG(rd);
  return false;
}

bool
q_omg_get_writer_security_info(
  const struct writer *wr,
  nn_security_info_t *info)
{
  assert(wr);
  assert(info);
  /* TODO: Register local writer. */
  DDSRT_UNUSED_ARG(wr);
  info->plugin_security_attributes = 0;
  info->security_attributes = 0;
  return false;
}

bool
q_omg_get_reader_security_info(
  const struct reader *rd,
  nn_security_info_t *info)
{
  assert(rd);
  assert(info);
  /* TODO: Register local reader. */
  DDSRT_UNUSED_ARG(rd);
  info->plugin_security_attributes = 0;
  info->security_attributes = 0;
  return false;
}

bool
q_omg_proxyparticipant_is_authenticated(
  const struct proxy_participant *proxy_pp)
{
  /* TODO: Handshake */
  DDSRT_UNUSED_ARG(proxy_pp);
  return false;
}

int64_t
q_omg_security_get_local_participant_handle(struct participant *pp)
{
  /* TODO: Local registration */
  DDSRT_UNUSED_ARG(pp);
  return 0;
}

unsigned
determine_subscription_writer(
  const struct reader *rd)
{
  if (q_omg_reader_is_discovery_protected(rd))
  {
    return NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER;
  }
  return NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER;
}

unsigned
determine_publication_writer(
  const struct writer *wr)
{
  if (q_omg_writer_is_discovery_protected(wr))
  {
    return NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER;
  }
  return NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER;
}

bool
allow_proxy_participant_deletion(
  struct q_globals * const gv,
  const struct ddsi_guid *guid,
  const ddsi_entityid_t pwr_entityid)
{
  struct proxy_participant *proxypp;

  assert(gv);
  assert(guid);

  /* Always allow deletion from a secure proxy writer. */
  if (pwr_entityid.u == NN_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER)
    return true;

  /* Not from a secure proxy writer.
   * Only allow deletion when proxy participant is not authenticated. */
  proxypp = ephash_lookup_proxy_participant_guid(gv->guid_hash, guid);
  if (!proxypp)
  {
    GVLOGDISC (" unknown");
    return false;
  }
  return (!q_omg_proxyparticipant_is_authenticated(proxypp));
}

bool
q_omg_security_is_remote_rtps_protected(
  struct proxy_participant *proxy_pp,
  ddsi_entityid_t entityid)
{
  /* TODO: Handshake */
  DDSRT_UNUSED_ARG(proxy_pp);
  DDSRT_UNUSED_ARG(entityid);
  return false;
}

bool
q_omg_security_is_local_rtps_protected(
  struct participant *pp,
  ddsi_entityid_t entityid)
{
  /* TODO: Handshake */
  DDSRT_UNUSED_ARG(pp);
  DDSRT_UNUSED_ARG(entityid);
  return false;
}

void
q_omg_get_proxy_participant_security_info(
  struct proxy_participant *proxypp,
  const nn_plist_t *plist,
  nn_security_info_t *info)
{
  DDSRT_UNUSED_ARG(proxypp);
  assert(plist);
  assert(info);
  if (plist->present & PP_PARTICIPANT_SECURITY_INFO) {
    info->security_attributes = plist->participant_security_info.security_attributes;
    info->plugin_security_attributes = plist->participant_security_info.plugin_security_attributes;
  } else {
    info->security_attributes = 0;
    info->plugin_security_attributes = 0;
  }
}

static void
q_omg_get_proxy_endpoint_security_info(
  const struct entity_common *entity,
  nn_security_info_t *proxypp_sec_info,
  const nn_plist_t *plist,
  nn_security_info_t *info)
{
  bool proxypp_info_available;

  assert(proxypp_sec_info);
  assert(entity);
  assert(plist);
  assert(info);

  proxypp_info_available = (proxypp_sec_info->security_attributes != 0) ||
                           (proxypp_sec_info->plugin_security_attributes != 0);

  /*
   * If Security info is present, use that.
   * Otherwise, use the specified values for the secure builtin endpoints.
   *      (Table 20 – EndpointSecurityAttributes for all "Builtin Security Endpoints")
   * Otherwise, reset.
   */
  if (plist->present & PP_ENDPOINT_SECURITY_INFO)
  {
    info->security_attributes = plist->endpoint_security_info.security_attributes;
    info->plugin_security_attributes = plist->endpoint_security_info.plugin_security_attributes;
  }
  else if (endpoint_is_DCPSParticipantSecure(&(entity->guid)) ||
           endpoint_is_DCPSPublicationsSecure(&(entity->guid)) ||
           endpoint_is_DCPSSubscriptionsSecure(&(entity->guid)) )
  {
    info->plugin_security_attributes = NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID;
    info->security_attributes = NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID;
    if (proxypp_info_available)
    {
      if (proxypp_sec_info->security_attributes & NN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED)
      {
        info->security_attributes |= NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED;
      }
      if (proxypp_sec_info->plugin_security_attributes & NN_PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_ENCRYPTED)
      {
        info->plugin_security_attributes |= NN_PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED;
      }
      if (proxypp_sec_info->plugin_security_attributes & NN_PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_AUTHENTICATED)
      {
        info->plugin_security_attributes |= NN_PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ORIGIN_AUTHENTICATED;
      }
    }
    else
    {
      /* No participant info: assume hardcoded OpenSplice V6.10.0 values. */
      info->security_attributes |= NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED;
      info->plugin_security_attributes |= NN_PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED;
    }
  }
  else if (endpoint_is_DCPSParticipantMessageSecure(&(entity->guid)))
  {
    info->plugin_security_attributes = NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID;
    info->security_attributes = NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID;
    if (proxypp_info_available)
    {
      if (proxypp_sec_info->security_attributes & NN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED)
      {
        info->security_attributes |= NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED;
      }
      if (proxypp_sec_info->plugin_security_attributes & NN_PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_ENCRYPTED)
      {
        info->plugin_security_attributes |= NN_PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED;
      }
      if (proxypp_sec_info->plugin_security_attributes & NN_PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_AUTHENTICATED)
      {
        info->plugin_security_attributes |= NN_PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ORIGIN_AUTHENTICATED;
      }
    }
    else
    {
      /* No participant info: assume hardcoded OpenSplice V6.10.0 values. */
      info->security_attributes |= NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED;
      info->plugin_security_attributes |= NN_PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED;
    }
  }
  else if (endpoint_is_DCPSParticipantStatelessMessage(&(entity->guid)))
  {
    info->security_attributes = NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID;
    info->plugin_security_attributes = 0;
  }
  else if (endpoint_is_DCPSParticipantVolatileMessageSecure(&(entity->guid)))
  {
    info->security_attributes = NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID |
                                NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED;
    info->plugin_security_attributes = 0;
  }
  else
  {
    info->security_attributes = 0;
    info->plugin_security_attributes = 0;
  }
}

void
q_omg_get_proxy_reader_security_info(
  struct proxy_reader *prd,
  const nn_plist_t *plist,
  nn_security_info_t *info)
{
    assert(prd);
    assert(prd->c.proxypp);
    q_omg_get_proxy_endpoint_security_info(&(prd->e),
                                           &(prd->c.proxypp->security_info),
                                           plist,
                                           info);
}

void
q_omg_get_proxy_writer_security_info(
  struct proxy_writer *pwr,
  const nn_plist_t *plist,
  nn_security_info_t *info)
{
    assert(pwr);
    assert(pwr->c.proxypp);
    q_omg_get_proxy_endpoint_security_info(&(pwr->e),
                                           &(pwr->c.proxypp->security_info),
                                           plist,
                                           info);
}


static bool
q_omg_security_encode_datareader_submessage(
  struct reader            *rd,
  const ddsi_guid_prefix_t *dst_prefix,
  const unsigned char      *src_buf,
  const unsigned int        src_len,
  unsigned char           **dst_buf,
  unsigned int             *dst_len)
{
  /* TODO: Use proper keys to actually encode (need key-exchange). */
  DDSRT_UNUSED_ARG(rd);
  DDSRT_UNUSED_ARG(dst_prefix);
  DDSRT_UNUSED_ARG(src_buf);
  DDSRT_UNUSED_ARG(src_len);

  *dst_buf = NULL;
  *dst_len = 0;

  return false;
}

static bool
q_omg_security_encode_datawriter_submessage(
  struct writer            *wr,
  const ddsi_guid_prefix_t *dst_prefix,
  const unsigned char      *src_buf,
  const unsigned int        src_len,
  unsigned char           **dst_buf,
  unsigned int             *dst_len)
{
  /* TODO: Use proper keys to actually encode (need key-exchange). */
  DDSRT_UNUSED_ARG(wr);
  DDSRT_UNUSED_ARG(dst_prefix);
  DDSRT_UNUSED_ARG(src_buf);
  DDSRT_UNUSED_ARG(src_len);

  *dst_buf = NULL;
  *dst_len = 0;

  return false;
}

bool
q_omg_security_decode_submessage(
  const ddsi_guid_prefix_t* const src_prefix,
  const ddsi_guid_prefix_t* const dst_prefix,
  const unsigned char   *src_buf,
  const unsigned int     src_len,
  unsigned char        **dst_buf,
  unsigned int          *dst_len)
{
  /* TODO: Use proper keys to actually decode (need key-exchange). */
  DDSRT_UNUSED_ARG(src_prefix);
  DDSRT_UNUSED_ARG(dst_prefix);
  DDSRT_UNUSED_ARG(src_buf);
  DDSRT_UNUSED_ARG(src_len);

  *dst_buf = NULL;
  *dst_len = 0;

  return false;
}

static bool
q_omg_security_encode_serialized_payload(
  const struct writer *wr,
  const unsigned char *src_buf,
  const unsigned int   src_len,
  unsigned char     **dst_buf,
  unsigned int       *dst_len)
{
  /* TODO: Use proper keys to actually encode (need key-exchange). */
  DDSRT_UNUSED_ARG(wr);
  DDSRT_UNUSED_ARG(src_buf);
  DDSRT_UNUSED_ARG(src_len);

  *dst_buf = NULL;
  *dst_len = 0;

  return false;
}

bool
q_omg_security_decode_serialized_payload(
  struct proxy_writer *pwr,
  const unsigned char *src_buf,
  const unsigned int   src_len,
  unsigned char     **dst_buf,
  unsigned int       *dst_len)
{
  /* TODO: Use proper keys to actually decode (need key-exchange). */
  DDSRT_UNUSED_ARG(pwr);
  DDSRT_UNUSED_ARG(src_buf);
  DDSRT_UNUSED_ARG(src_len);

  *dst_buf = NULL;
  *dst_len = 0;

  return false;
}

bool
q_omg_security_encode_rtps_message(
  int64_t                 src_handle,
  ddsi_guid_t            *src_guid,
  const unsigned char    *src_buf,
  const unsigned int      src_len,
  unsigned char        **dst_buf,
  unsigned int          *dst_len,
  int64_t                dst_handle)
{
  /* TODO: Use proper keys to actually encode (need key-exchange). */
  DDSRT_UNUSED_ARG(src_handle);
  DDSRT_UNUSED_ARG(src_guid);
  DDSRT_UNUSED_ARG(src_buf);
  DDSRT_UNUSED_ARG(src_len);
  DDSRT_UNUSED_ARG(dst_handle);

  *dst_buf = NULL;
  *dst_len = 0;

  return false;
}

bool
q_omg_security_decode_rtps_message(
  struct proxy_participant *proxypp,
  const unsigned char      *src_buf,
  const unsigned int        src_len,
  unsigned char          **dst_buf,
  unsigned int            *dst_len)
{
  /* TODO: Use proper keys to actually decode (need key-exchange). */
  DDSRT_UNUSED_ARG(proxypp);
  DDSRT_UNUSED_ARG(src_buf);
  DDSRT_UNUSED_ARG(src_len);

  *dst_buf = NULL;
  *dst_len = 0;

  return false;
}

static bool
q_omg_writer_is_payload_protected(
  struct writer *wr)
{
  /* TODO: Local registration. */
  DDSRT_UNUSED_ARG(wr);
  return false;
}

static bool
q_omg_writer_is_submessage_protected(
  struct writer *wr)
{
  DDSRT_UNUSED_ARG(wr);
  return false;
}

static bool
q_omg_reader_is_submessage_protected(
  struct reader *rd)
{
  DDSRT_UNUSED_ARG(rd);
  return false;
}

bool
encode_payload(
  struct writer *wr,
  ddsrt_iovec_t *vec,
  unsigned char **buf)
{
  bool ok = true;
  *buf = NULL;
  if (q_omg_writer_is_payload_protected(wr))
  {
    /* Encrypt the data. */
    unsigned char *enc_buf;
    unsigned int   enc_len;
    ok = q_omg_security_encode_serialized_payload(
                    wr,
                    vec->iov_base,
                    (unsigned int)vec->iov_len,
                    &enc_buf,
                    &enc_len);
    if (ok)
    {
      /* Replace the iov buffer. */
      vec->iov_base = (char *)enc_buf;
      vec->iov_len = enc_len;
      /* Remember the pointer to be able to free it. */
      *buf = enc_buf;
    }
  }
  return ok;
}


void encode_datareader_submsg(struct nn_xmsg *msg, struct nn_xmsg_marker sm_marker, struct proxy_writer *pwr, const struct ddsi_guid *rd_guid)
{
  /* Only encode when needed. */
  if (q_omg_security_enabled())
  {
    struct reader *rd = ephash_lookup_reader_guid(pwr->e.gv->guid_hash, rd_guid);
    if (rd)
    {
      if (q_omg_reader_is_submessage_protected(rd))
      {
        unsigned char *src_buf;
        unsigned int   src_len;
        unsigned char *dst_buf;
        unsigned int   dst_len;
        ddsi_guid_prefix_t dst_guid_prefix;
        ddsi_guid_prefix_t *dst = NULL;

        /* Make one blob of the current sub-message by appending the serialized payload. */
        nn_xmsg_submsg_append_refd_payload(msg, sm_marker);

        /* Get the sub-message buffer. */
        src_buf = (unsigned char*)nn_xmsg_submsg_from_marker(msg, sm_marker);
        src_len = (unsigned int)nn_xmsg_submsg_size(msg, sm_marker);

        if (nn_xmsg_getdst1prefix(msg, &dst_guid_prefix))
        {
          dst = &dst_guid_prefix;
        }

        /* Do the actual encryption. */
        if (q_omg_security_encode_datareader_submessage(rd, dst, src_buf, src_len, &dst_buf, &dst_len))
        {
          /* Replace the old sub-message with the new encoded one(s). */
          nn_xmsg_submsg_replace(msg, sm_marker, dst_buf, dst_len);
          nn_xmsg_set_encoded(msg, true);
          ddsrt_free(dst_buf);
        }
        else
        {
          /* The sub-message should have been encoded, which failed.
           * Remove it to prevent it from being send. */
          nn_xmsg_submsg_remove(msg, sm_marker);
        }
      }
    }
  }
}


void encode_datawriter_submsg(struct nn_xmsg *msg, struct nn_xmsg_marker sm_marker, struct writer *wr)
{
  /* Only encode when needed. */
  if (q_omg_security_enabled())
  {
    if (q_omg_writer_is_submessage_protected(wr))
    {
      unsigned char *src_buf;
      unsigned int   src_len;
      unsigned char *dst_buf;
      unsigned int   dst_len;
      ddsi_guid_prefix_t dst_guid_prefix;
      ddsi_guid_prefix_t *dst = NULL;

      /* Make one blob of the current sub-message by appending the serialized payload. */
      nn_xmsg_submsg_append_refd_payload(msg, sm_marker);

      /* Get the sub-message buffer. */
      src_buf = (unsigned char*)nn_xmsg_submsg_from_marker(msg, sm_marker);
      src_len = (unsigned int)nn_xmsg_submsg_size(msg, sm_marker);

      if (nn_xmsg_getdst1prefix(msg, &dst_guid_prefix))
      {
        dst = &dst_guid_prefix;
      }

      /* Do the actual encryption. */
      if (q_omg_security_encode_datawriter_submessage(wr, dst, src_buf, src_len, &dst_buf, &dst_len))
      {
        /* Replace the old sub-message with the new encoded one(s). */
        nn_xmsg_submsg_replace(msg, sm_marker, dst_buf, dst_len);
        nn_xmsg_set_encoded(msg, true);
        ddsrt_free(dst_buf);
      }
      else
      {
        /* The sub-message should have been encoded, which failed.
         * Remove it to prevent it from being send. */
        nn_xmsg_submsg_remove(msg, sm_marker);
      }
    }
  }
}


#else /* DDSI_INCLUDE_SECURITY */

#include "dds/ddsi/ddsi_security_omg.h"

extern inline bool q_omg_participant_is_secure(UNUSED_ARG(const struct participant *pp));

extern inline unsigned determine_subscription_writer(UNUSED_ARG(const struct reader *rd));
extern inline unsigned determine_publication_writer(UNUSED_ARG(const struct writer *wr));

extern inline bool allow_proxy_participant_deletion(
  UNUSED_ARG(struct q_globals * const gv),
  UNUSED_ARG(const struct ddsi_guid *guid),
  UNUSED_ARG(const ddsi_entityid_t pwr_entityid));

#endif /* DDSI_INCLUDE_SECURITY */
