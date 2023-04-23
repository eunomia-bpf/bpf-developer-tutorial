/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPRTT_H
#define __TCPRTT_H

#define MAX_SLOTS	27

struct hist {
	unsigned long long latency;
	unsigned long long cnt;
	unsigned int slots[MAX_SLOTS];
};

#endif /* __TCPRTT_H */
