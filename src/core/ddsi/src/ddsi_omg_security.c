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
#include <string.h>

#include "dds/ddsrt/misc.h"
#include "dds/ddsrt/sync.h"

#include "dds/ddsi/q_unused.h"
#include "dds/ddsi/ddsi_omg_security.h"

static ddsrt_mutex_t security_lock;

/* TODO: Replace with a proper enabled check. */
static bool enabled_tmp_bool = false;

static bool
qos_contains_sec_settings(const dds_qos_t *xqos)
{
  if (xqos->present & QP_PROPERTY_LIST)
  {
    const dds_propertyseq_t *properties = &(xqos->property.value);
    for (uint32_t i = 0; i < properties->n; i++)
    {
      if (strncmp (properties->props[i].name, "dds.sec.", strlen ("dds.sec.")) == 0)
      {
        return true;
      }
    }
  }
  return false;
}

void
q_omg_security_init(void)
{
  ddsrt_mutex_init(&security_lock);
}

void
q_omg_security_deinit(void)
{
  ddsrt_mutex_destroy(&security_lock);
}

bool
q_omg_security_load(const dds_qos_t *xqos)
{
  ddsrt_mutex_lock(&security_lock);
  /* TODO: Replace with proper libraries loading and checks. */
  enabled_tmp_bool = qos_contains_sec_settings(xqos);
  ddsrt_mutex_unlock(&security_lock);
  return true;
}

bool
q_omg_security_enabled(void)
{
  return enabled_tmp_bool;
}

bool
q_omg_participant_is_secure(
  struct participant *pp)
{
  /* TODO: Register local participant. */
  DDSRT_UNUSED_ARG(pp);
  return false;
}

bool
q_omg_writer_is_discovery_protected(
  const struct writer *wr)
{
  /* TODO: Register local writer. */
  DDSRT_UNUSED_ARG(wr);
  return false;
}

bool
q_omg_reader_is_discovery_protected(
  const struct reader *rd)
{
  /* TODO: Register local reader. */
  DDSRT_UNUSED_ARG(rd);
  return false;
}

bool
q_omg_security_match_remote_writer_enabled(
  struct reader *rd,
  struct proxy_writer *pwr)
{
  /* TODO: Register remote writer */
  DDSRT_UNUSED_ARG(rd);
  DDSRT_UNUSED_ARG(pwr);
  return true;
}

bool
q_omg_security_match_remote_reader_enabled(
  struct writer *wr,
  struct proxy_reader *prd)
{
  /* TODO: Register remote reader */
  DDSRT_UNUSED_ARG(wr);
  DDSRT_UNUSED_ARG(prd);
  return true;
}

bool
q_omg_get_writer_security_info(
  struct writer *wr,
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
  struct reader *rd,
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
  struct proxy_participant *proxypp)
{
  /* TODO: Handshake */
  DDSRT_UNUSED_ARG(proxypp);
  return false;
}

