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


#if defined (__cplusplus)
extern "C" {
#endif

void
q_omg_security_init(void);

void
q_omg_security_deinit(void);

bool
q_omg_security_load(const dds_qos_t *xqos);

bool
q_omg_security_enabled(void);

bool
q_omg_participant_is_secure(
  struct participant *pp);

bool
q_omg_writer_is_discovery_protected(
  const struct writer *wr);

bool
q_omg_reader_is_discovery_protected(
  const struct reader *rd);

bool
q_omg_proxyparticipant_is_authenticated(
  struct proxy_participant *proxypp);

bool
q_omg_get_writer_security_info(
  struct writer *wr,
  nn_security_info_t *info);

bool
q_omg_get_reader_security_info(
  struct reader *rd,
  nn_security_info_t *info);

bool
q_omg_security_match_remote_writer_enabled(
  struct reader *rd,
  struct proxy_writer *pwr);

bool
q_omg_security_match_remote_reader_enabled(
  struct writer *wr,
  struct proxy_reader *prd);

#if defined (__cplusplus)
}
#endif

#endif /* DDSI_OMG_SECURITY_H */
