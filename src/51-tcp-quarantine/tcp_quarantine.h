/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCP_QUARANTINE_H
#define __TCP_QUARANTINE_H

struct quarantine_stats {
	unsigned long long scanned;
	unsigned long long established;
	unsigned long long matched;
	unsigned long long destroyed;
	unsigned long long failed;
};

#endif /* __TCP_QUARANTINE_H */
