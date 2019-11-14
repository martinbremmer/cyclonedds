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
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/process.h"

#include "dds/ddsi/q_unused.h"
#include "dds/ddsi/ddsi_security_omg.h"
#include "dds/ddsi/ddsi_sertopic.h"


#define MOCK_PAYLOAD
#define MOCK_SUBMSG
#define MOCK_RTPS

//#define MOCK_DECODE_FAILURE
//#define MOCK_ENCODE_FAILURE

//#define MOCK_TRACE


#define SEC_BODY_SMID       0x30
#define SEC_PREFIX_SMID     0x31
#define SEC_POSTFIX_SMID    0x32
#define SRTPS_PREFIX_SMID   0x33
#define SRTPS_POSTFIX_SMID  0x34



#define PAYLOAD_PREFIX_DUMMY { 1, 2, 3, 4 }



#define SUBMSG_PREFIX_MOCK { SEC_PREFIX_SMID,                                      \
                             0x01,         /* endianess */                         \
                             0x10, 0x00,   /* payload size */                      \
                             0x00,         /* payload: origin indication */        \
                             0x00,         /* payload: original SMID */            \
                             0x00,         /* payload: original len (<256) */      \
                             0x00,         /* payload: original prefix[ 0] */      \
                             0x00,         /* payload: original prefix[ 1] */      \
                             0x00,         /* payload: original prefix[ 2] */      \
                             0x00,         /* payload: original prefix[ 3] */      \
                             0x00,         /* payload: original prefix[ 4] */      \
                             0x00,         /* payload: original prefix[ 5] */      \
                             0x00,         /* payload: original prefix[ 6] */      \
                             0x00,         /* payload: original prefix[ 7] */      \
                             0x00,         /* payload: original prefix[ 8] */      \
                             0x00,         /* payload: original prefix[ 9] */      \
                             0x00,         /* payload: original prefix[10] */      \
                             0x00,         /* payload: original prefix[11] */      \
                             0x00}         /* payload: padding */

#define SUBMSG_PREFIX_ORIGIN_DATAWRITER  0x01
#define SUBMSG_PREFIX_ORIGIN_DATAREADER  0x02

#define SUBMSG_PREFIX_SET_ORIGIN(submsg, origin) submsg[4] = origin
#define SUBMSG_PREFIX_GET_ORIGIN(submsg)         submsg[4]

#define SUBMSG_PREFIX_SET_SMID(submsg, smid)     submsg[5] = smid
#define SUBMSG_PREFIX_GET_SMID(submsg)           submsg[5]

#define SUBMSG_PREFIX_SET_LEN(submsg, len)       submsg[6] = (unsigned char)len
#define SUBMSG_PREFIX_GET_LEN(submsg)            submsg[6]

#define SUBMSG_PREFIX_SET_PREFIX(submsg, s)      submsg[ 7] = s[ 0]; \
                                                 submsg[ 8] = s[ 1]; \
                                                 submsg[ 9] = s[ 2]; \
                                                 submsg[10] = s[ 3]; \
                                                 submsg[11] = s[ 4]; \
                                                 submsg[12] = s[ 5]; \
                                                 submsg[13] = s[ 6]; \
                                                 submsg[14] = s[ 7]; \
                                                 submsg[15] = s[ 8]; \
                                                 submsg[16] = s[ 9]; \
                                                 submsg[17] = s[10]; \
                                                 submsg[18] = s[11];

#define SUBMSG_PREFIX_END(submsg)                &(submsg[20])

#define SUBMSG_POSTFIX_MOCK { SEC_POSTFIX_SMID,                                     \
                              0x01,         /* endianess */                         \
                              0x04, 0x00,   /* payload size */                      \
                              0x00, 0x00,   /* payload: dummy */                    \
                              0x00, 0x00 }  /* payload: dummy */

#define SUBMSG_GET_SIZE(submsg) (unsigned short)((((unsigned short)submsg[3]) << 8) + ((unsigned short)submsg[2]) + 4)


#define RTPS_HEADER_MOCK   { SRTPS_PREFIX_SMID,                                    \
                             0x01,         /* endianess */                         \
                             0x04, 0x00,   /* payload size */                      \
                             0x02,         /* payload: origin indication */        \
                             0x00,         /* payload: original SMID */            \
                             0x00, 0x00 }  /* payload: padding */

#define RTPS_PREFIX_MOCK   { SRTPS_PREFIX_SMID,                                    \
                             0x01,         /* endianess */                         \
                             0x00, 0x00 }  /* payload size */

#define RTPS_POSTFIX_MOCK  { SRTPS_POSTFIX_SMID,                                   \
                             0x01,         /* endianess */                         \
                             0x00, 0x00 }  /* payload size */


static void
mock_rtps_encoding(
  const unsigned char  *src_buf,
  const unsigned int    src_len,
  unsigned char       **dst_buf,
  unsigned int         *dst_len)
{
  unsigned char prefix_hdr[] = RTPS_PREFIX_MOCK;
  unsigned char postfix[]    = RTPS_POSTFIX_MOCK;
  unsigned char *ptr;

  /* Prepare dest buffer. */
  *dst_len = (unsigned int)(sizeof(Header_t) + sizeof(prefix_hdr) + src_len + sizeof(postfix));
  *dst_buf = ddsrt_malloc(*dst_len);

  /* Fill dest buffer. */
  ptr = *dst_buf;
  /* RTPS Header. */
  memcpy(ptr, src_buf, sizeof(Header_t));
  ptr += sizeof(Header_t);
  /* Prefix that includes the original message. */
  prefix_hdr[2] = (unsigned char)(src_len & 0xFF);
  prefix_hdr[3] = (unsigned char)((src_len & 0xFF00) >> 8);
  memcpy(ptr, prefix_hdr, sizeof(prefix_hdr));
  ptr += sizeof(prefix_hdr);
  memcpy(ptr, src_buf, src_len);
  ptr += src_len;
  /* Postfix */
  memcpy(ptr, postfix, sizeof(postfix));
}

static void
mock_rtps_decoding(
  const unsigned char  *src_buf,
  const unsigned int    src_len,
  unsigned char       **dst_buf,
  unsigned int         *dst_len)
{
  const unsigned char *prefix = &(src_buf[sizeof(Header_t)]);
  (void)src_len;

  /* Get original message buffer. */
  *dst_len = (unsigned int)((int)(prefix[2]) | ((int)(prefix[3]) << 8));
  *dst_buf = ddsrt_memdup(&(prefix[4]), *dst_len);
}

static void
mock_submessage_encoding(
  const ddsi_guid_prefix_t *dst_prefix,
  const unsigned char  *src_buf,
  const unsigned int    src_len,
  unsigned char       **dst_buf,
  unsigned int         *dst_len,
  unsigned char         origin)
{
  unsigned char postfix [] = SUBMSG_POSTFIX_MOCK;

  /* Prepare the prefix. */
  unsigned char prefix  [] = SUBMSG_PREFIX_MOCK;
  SUBMSG_PREFIX_SET_ORIGIN(prefix, origin);
  SUBMSG_PREFIX_SET_SMID(prefix, src_buf[0]);
  SUBMSG_PREFIX_SET_LEN(prefix, src_len);
  if (dst_prefix)
  {
    SUBMSG_PREFIX_SET_PREFIX(prefix, dst_prefix->s);
  }

  /* Prepare destination buffer. */
  *dst_len = (unsigned int)(sizeof(prefix) + src_len + sizeof(postfix));
  *dst_buf = ddsrt_malloc(*dst_len);

  /* Add prefix. */
  memcpy(*dst_buf, prefix, sizeof(prefix));

  /* Copy/transform data into body. */
  memcpy(&((*dst_buf)[sizeof(prefix)]), src_buf, src_len);
  (*dst_buf)[sizeof(prefix)] = SEC_BODY_SMID;

  /* Add postfix. */
  memcpy(&((*dst_buf)[(*dst_len) - sizeof(postfix)]), postfix, sizeof(postfix));
}

static void
mock_submessage_decoding(
  const unsigned char  *src_buf,
  const unsigned int    src_len,
  unsigned char       **dst_buf,
  unsigned int         *dst_len)
{
  const unsigned char *data = SUBMSG_PREFIX_END(src_buf);
  unsigned short size = SUBMSG_GET_SIZE(data);

  (void)src_len;

  /* Prepare buffer. */
  *dst_buf = ddsrt_malloc(size);
  *dst_len = size;

  /* Copy/transform data into body. */
  memcpy(*dst_buf, data, size);
  (*dst_buf)[0] = SUBMSG_PREFIX_GET_SMID(src_buf);
}

static void
mock_payload_encoding(
  const unsigned char  *src_buf,
  const unsigned int    src_len,
  unsigned char       **dst_buf,
  unsigned int         *dst_len)
{
  unsigned char dummyhdr [] = PAYLOAD_PREFIX_DUMMY;

  /* Prepare destination buffer. */
  *dst_len = (unsigned int)(sizeof(dummyhdr) + src_len);
  *dst_buf = ddsrt_malloc(*dst_len);

  /* Add prefix. */
  memcpy(*dst_buf, dummyhdr, sizeof(dummyhdr));

  /* Copy payload. */
  memcpy(&((*dst_buf)[sizeof(dummyhdr)]), src_buf, src_len);
}

static void
mock_payload_decoding(
  const unsigned char  *src_buf,
  const unsigned int    src_len,
  unsigned char       **dst_buf,
  unsigned int         *dst_len)
{
  unsigned char dummyhdr [] = PAYLOAD_PREFIX_DUMMY;

  /* Prepare destination buffer. */
  *dst_len = (unsigned int)(src_len - sizeof(dummyhdr));
  *dst_buf = ddsrt_malloc(*dst_len);

  /* Get payload. */
  memcpy(*dst_buf, &(src_buf[sizeof(dummyhdr)]), *dst_len);
}

#if 0
static void
print_submsg(const unsigned char *buf, unsigned int len)
{
  unsigned short i;
  unsigned short size = SUBMSG_GET_SIZE(buf);
  printf("[%u] print_submsg(%p, %u)\n", (unsigned)ddsrt_getpid(), buf, len);
  printf("[%u] Header:  0x%02x\n", (unsigned)ddsrt_getpid(), buf[0]);
  printf("[%u] Flags:   0x%02x\n", (unsigned)ddsrt_getpid(), buf[1]);
  printf("[%u] Length:  0x%02x%02x (%u)\n", (unsigned)ddsrt_getpid(), buf[2], buf[3], size - 4);
  printf("[%u] Payload:", (unsigned)ddsrt_getpid());
  for (i = 4; i < size; i++)
  {
    printf(" %02x", buf[i]);
  }
  printf("\n");
  if (size < len)
  {
    print_submsg(&(buf[size]), len - size);
  }
  printf("\n");
}
#endif

static bool
q_omg_writer_is_payload_protected(
    const struct writer *wr);

static bool
maybe_rtps_protected(
  ddsi_entityid_t entityid)
{
  bool result = false;

  if (!is_builtin_entityid(entityid, NN_VENDORID_ECLIPSE))
  {
    //printf("maybe_rtps_protected(0x%x): not builtin\n", entityid.u);
    result = true;
  }
  else
  {
    switch (entityid.u)
    {
      case NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER:
      case NN_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_READER:
      case NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER:
      case NN_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_READER:
      case NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER:
      case NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER:
      case NN_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER:
      case NN_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_READER:
        //printf("maybe_rtps_protected(0x%x): secure builtin\n", entityid.u);
        result = false /* true */;
        break;
      default:
        //printf("maybe_rtps_protected(0x%x): builtin\n", entityid.u);
        result = false;
        break;
    }
  }
  return result;
}


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
  return true;
}

bool
q_omg_participant_is_secure(
  const struct participant *pp)
{
  /* TODO: Register local participant. */
  DDSRT_UNUSED_ARG(pp);
  return true;
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
  if (q_omg_writer_is_payload_protected(wr))
  {
    info->security_attributes = NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID|
                                NN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED;
  }
  else
  {
    info->security_attributes = 0;
  }
  return true;
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
  return true;
}

int64_t
q_omg_security_get_local_participant_handle(
  struct participant *pp)
{
  /* TODO: Local registration */
  DDSRT_UNUSED_ARG(pp);
  return 1;
}

int64_t
q_omg_security_get_remote_participant_handle(
  struct proxy_participant *proxypp)
{
  /* TODO: Handshake */
  DDSRT_UNUSED_ARG(proxypp);
  return 1;
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
  bool ret = maybe_rtps_protected(entityid);
  /* TODO: Handshake */
  DDSRT_UNUSED_ARG(proxy_pp);
  DDSRT_UNUSED_ARG(entityid);
#ifdef MOCK_RTPS
  //printf("q_omg_security_is_remote_rtps_protected: %s\n", ret ? "yes" : "no");
#else
  ret = false;
#endif
  return ret;
}

bool
q_omg_security_is_local_rtps_protected(
  struct participant *pp,
  ddsi_entityid_t entityid)
{
  bool ret = maybe_rtps_protected(entityid);
  /* TODO: Handshake */
  DDSRT_UNUSED_ARG(pp);
  DDSRT_UNUSED_ARG(entityid);
#ifdef MOCK_RTPS
  //printf("q_omg_security_is_local_rtps_protected: %s\n", ret ? "yes" : "no");
#else
  ret = false;
#endif
  return ret;
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
  DDSRT_UNUSED_ARG(dst_buf);
  DDSRT_UNUSED_ARG(dst_len);
#ifdef MOCK_ENCODE_FAILURE
  printf("%s: force failure\n", __FUNCTION__);
  return false;
#else
  mock_submessage_encoding(dst_prefix, src_buf, src_len, dst_buf, dst_len, SUBMSG_PREFIX_ORIGIN_DATAREADER);
#ifdef MOCK_TRACE
  printf("%s: src_len(%d)->dst_len(%d)\n", __FUNCTION__, (int)src_len, (int)*dst_len);
#endif
  return true;
#endif
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
  DDSRT_UNUSED_ARG(dst_buf);
  DDSRT_UNUSED_ARG(dst_len);
#ifdef MOCK_ENCODE_FAILURE
  printf("%s: force failure\n", __FUNCTION__);
  return false;
#else
  mock_submessage_encoding(dst_prefix, src_buf, src_len, dst_buf, dst_len, SUBMSG_PREFIX_ORIGIN_DATAWRITER);
#if 0
  printf("[%u] q_omg_security_encode_datawriter_submessage Source\n", (unsigned)ddsrt_getpid());
  print_submsg(src_buf, src_len);
  printf("[%u] q_omg_security_encode_datawriter_submessage Destination\n", (unsigned)ddsrt_getpid());
  print_submsg(*dst_buf, *dst_len);
#endif
#ifdef MOCK_TRACE
  printf("%s: src_len(%d)->dst_len(%d)\n", __FUNCTION__, (int)src_len, (int)*dst_len);
#endif
  return true;
#endif
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
  DDSRT_UNUSED_ARG(dst_buf);
  DDSRT_UNUSED_ARG(dst_len);
#ifdef MOCK_DECODE_FAILURE
  printf("%s: force failure\n", __FUNCTION__);
  return false;
#else
  mock_submessage_decoding(src_buf, src_len, dst_buf, dst_len);
#if 0
  printf("[%u] q_omg_security_decode_submessage Source\n", (unsigned)ddsrt_getpid());
  print_submsg(src_buf, src_len);
  printf("[%u] q_omg_security_decode_submessage Destination\n", (unsigned)ddsrt_getpid());
  print_submsg(*dst_buf, *dst_len);
#endif
#ifdef MOCK_TRACE
  printf("%s: src_len(%d)->dst_len(%d)\n", __FUNCTION__, (int)src_len, (int)*dst_len);
#endif
  return true;
#endif
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
  DDSRT_UNUSED_ARG(dst_buf);
  DDSRT_UNUSED_ARG(dst_len);
#ifdef MOCK_ENCODE_FAILURE
  printf("%s: force failure\n", __FUNCTION__);
  return false;
#else
  mock_payload_encoding(src_buf, src_len, dst_buf, dst_len);
#ifdef MOCK_TRACE
  printf("%s: src_len(%d)->dst_len(%d)\n", __FUNCTION__, (int)src_len, (int)*dst_len);
#endif
  return true;
#endif
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
  DDSRT_UNUSED_ARG(dst_buf);
  DDSRT_UNUSED_ARG(dst_len);
#ifdef MOCK_DECODE_FAILURE
  printf("%s: force failure\n", __FUNCTION__);
  return false;
#else
  mock_payload_decoding(src_buf, src_len, dst_buf, dst_len);
#ifdef MOCK_TRACE
  printf("%s: src_len(%d)->dst_len(%d)\n", __FUNCTION__, (int)src_len, (int)*dst_len);
#endif
  return true;
#endif
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
  DDSRT_UNUSED_ARG(dst_buf);
  DDSRT_UNUSED_ARG(dst_len);
  DDSRT_UNUSED_ARG(dst_handle);
#ifdef MOCK_ENCODE_FAILURE
  printf("%s: force failure\n", __FUNCTION__);
  return false;
#else
  mock_rtps_encoding(src_buf, src_len, dst_buf, dst_len);
#ifdef MOCK_TRACE
  printf("%s: src_len(%d)->dst_len(%d)\n", __FUNCTION__, (int)src_len, (int)*dst_len);
#endif
  return true;
#endif
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
  DDSRT_UNUSED_ARG(dst_buf);
  DDSRT_UNUSED_ARG(dst_len);
#ifdef MOCK_DECODE_FAILURE
  printf("%s: force failure\n", __FUNCTION__);
  return false;
#else
  mock_rtps_decoding(src_buf, src_len, dst_buf, dst_len);
#ifdef MOCK_TRACE
  printf("%s: src_len(%d)->dst_len(%d)\n", __FUNCTION__, (int)src_len, (int)*dst_len);
#endif
  return true;
#endif
}

static bool
q_omg_writer_is_payload_protected(
  const struct writer *wr)
{
  bool ret = false;
  /* TODO: Local registration. */
  DDSRT_UNUSED_ARG(wr);
#ifdef MOCK_PAYLOAD
  const char *name = "no_topic";
  if (wr->topic)
  {
    if (wr->topic->name)
    {
      name = wr->topic->name;
      ret = true;
    }
    else
    {
      name = "no_name";
    }
  }
  (void)name;
  //printf("%s(%s:%s)\n", __FUNCTION__, name, ret ? "protected" : "plain");
#endif
  return ret;
}

static bool
q_omg_writer_is_submessage_protected(
  struct writer *wr)
{
  /* TODO: Local registration. */
  DDSRT_UNUSED_ARG(wr);
#ifdef MOCK_SUBMSG
  //printf("%s(yes)\n", __FUNCTION__);
  return true;
#else
  return false;
#endif
}

static bool
q_omg_reader_is_submessage_protected(
  struct reader *rd)
{
  /* TODO: Local registration. */
  DDSRT_UNUSED_ARG(rd);
#ifdef MOCK_SUBMSG
  //printf("%s(yes)\n", __FUNCTION__);
  return true;
#else
  return false;
#endif
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
