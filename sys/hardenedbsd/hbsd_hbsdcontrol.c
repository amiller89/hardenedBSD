/*-
 * Copyright (c) 2015 Oliver Pinter <oliver.pinter@HardenedBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_pax.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

FEATURE(hbsdcontrol, "HardenedBSD's FS-EA based control subsystem.");

static int pax_hbsdcontrol_status = PAX_FEATURE_SIMPLE_ENABLED;
TUNABLE_INT("hardening.hbsdcontrol.status", &pax_hbsdcontrol_status);

#ifdef PAX_SYSCTLS
SYSCTL_DECL(_hardening_pax);

SYSCTL_NODE(_hardening_pax, OID_AUTO, hbsdcontrol, CTLFLAG_RD, 0,
    "FS-EA based control subsystem.");

SYSCTL_INT(_hardening_pax_hbsdcontrol, OID_AUTO, status,
    CTLFLAG_RDTUN|CTLFLAG_SECURE,
    &pax_hbsdcontrol_status, 0,
    "status: "
    "0 - disabled, "
    "1 - enabled");
#endif

static void
pax_hbsdcontrol_sysinit(void)
{

	switch (pax_hbsdcontrol_status) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		break;
	default:
		printf("[HBSD CONTROL] WARNING, invalid settings in loader.conf!"
		    " (pax_hbsdcontrol_status = %d)\n", pax_hbsdcontrol_status);
		pax_hbsdcontrol_status = PAX_FEATURE_SIMPLE_ENABLED;
		break;
	}
	printf("[HBSD CONTROL] status: %s\n", pax_status_str[pax_hbsdcontrol_status]);
}
SYSINIT(pax_hbsdcontrol, SI_SUB_PAX, SI_ORDER_FIRST, pax_hbsdcontrol_sysinit, NULL);

