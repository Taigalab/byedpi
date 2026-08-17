// SPDX-License-Identifier: Apache-2.0
/*
 * iptables.h - Firewall rule installation/removal and environment detection.
 */

#ifndef BYEDPI_IPTABLES_H
#define BYEDPI_IPTABLES_H

#include "byedpi.h"

/* Insert the NFQUEUE OUTPUT rules (IPv4 always, IPv6 when cfg->ipv6). Returns
 * 0 if all required rules were installed, -1 otherwise. On partial failure any
 * rules that were installed are rolled back. */
int  bd_iptables_apply(const bd_config *cfg);

/* Remove exactly the rules installed by bd_iptables_apply(). Safe to call even
 * if apply() was never run or partially failed. */
void bd_iptables_revert(const bd_config *cfg);

/* Environment probes used to warn the user before touching the firewall. */
bool bd_service_active(const char *unit);       /* systemctl is-active */
bool bd_systemd_resolved_active(void);          /* stub resolver on :53 */

#endif /* BYEDPI_IPTABLES_H */
