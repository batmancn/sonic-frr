/*
 * Static NHT code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "vrf.h"
#include "nexthop.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"

void static_nht_update(struct prefix *p, uint32_t nh_num,
		       afi_t afi, vrf_id_t vrf_id)
{
	struct route_table *stable;
	struct static_route *si;
	struct static_vrf *svrf;
	struct route_node *rn;
	struct vrf *vrf;
	bool orig;
	bool reinstall;

	vrf = vrf_lookup_by_id(vrf_id);

	if (!vrf || !vrf->info)
		return;

	svrf = vrf->info;
	stable = static_vrf_static_table(afi, SAFI_UNICAST, svrf);
	if (!stable)
		return;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		reinstall = false;
		for (si = rn->info; si; si = si->next) {
			if (si->type != STATIC_IPV4_GATEWAY &&
			    si->type != STATIC_IPV4_GATEWAY_IFNAME &&
			    si->type != STATIC_IPV6_GATEWAY &&
			    si->type != STATIC_IPV6_GATEWAY_IFNAME)
				continue;

			orig = si->nh_valid;
			if (p->family == AF_INET &&
			    p->u.prefix4.s_addr == si->addr.ipv4.s_addr)
				si->nh_valid = !!nh_num;

			if (p->family == AF_INET6 &&
			    memcmp(&p->u.prefix6, &si->addr.ipv6, 16) == 0)
				si->nh_valid = !!nh_num;

			if (orig != si->nh_valid)
				reinstall = true;

			if (reinstall) {
				static_zebra_route_add(rn, si, vrf_id,
						       SAFI_UNICAST, true);
				reinstall = false;
			}
		}
	}
}
