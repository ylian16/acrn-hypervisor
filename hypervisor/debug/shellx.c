/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <types.h>
#include <errno.h>
#include <asm/lib/bits.h>
#include <logmsg.h>
#include <rtl.h>
#include <sprintf.h>
#include <board_info.h>
#include <asm/notify.h>
#include <asm/msr.h>
#include <asm/vm_config.h>
#include <asm/guest/vm.h>
#include <asm/guest/ept.h>

#define SHELL_LOG_BUF_SIZE (4096U * MAX_PCPU_NUM / 2U)
extern char shell_log_buf[];
extern void shell_puts(const char *);

#define BIT(n) (1UL << (n))
#define BITS(val, p1, p2)   	                                            \
	(((p1) < (p2)) ? (((val) >> (p1)) & (BIT((p2) - (p1) + 1) - 1))	    \
	 : (((val) >> (p2)) & (BIT((p1) - (p2) + 1) - 1)))

typedef struct buffer {
	char *buf;
	size_t size;
} buffer_t;

/*
 * "lapic" command
 */
static void dump_lapic_info(char *buf, size_t bufsize)
{

	snprintf(buf, bufsize,
		   "LDR=%08x SVR=%08x\n"
		   "ISR=%08x%08x%08x%08x%08x%08x%08x%08x\n"
		   "TMR=%08x%08x%08x%08x%08x%08x%08x%08x\n"
		   "IRR=%08x%08x%08x%08x%08x%08x%08x%08x\n"
		   "ESR=%08x CMCI=%%08x ICR=%016lx\n"
		   "LVT[0-6]=%08x %08x %08x %08x %08x %08x\n"
		   "TMR: ICR=%08x CCR=%08x DCR=%08x\n",
		   (uint32_t)msr_read(MSR_IA32_EXT_XAPICID),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_VERSION),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TPR),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_PPR),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_LDR),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_SIVR),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR7),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR6),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR5),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR4),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR3),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR2),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR1),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ISR0),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR7),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR6),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR5),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR4),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR3),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR2),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR1),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_TMR0),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR7),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR6),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR5),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR4),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR3),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR2),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR1),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_IRR0),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_ESR),
		   //(uint32)rdmsr(MSR_IA32_EXT_APIC_LVT_CMCI),
		   msr_read(MSR_IA32_EXT_APIC_ICR),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_LVT_TIMER),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_LVT_THERMAL),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_LVT_PMI),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_LVT_LINT0),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_LVT_LINT1),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_LVT_ERROR),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_INIT_COUNT),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_CUR_COUNT),
		   (uint32_t)msr_read(MSR_IA32_EXT_APIC_DIV_CONF));
}

static void smpcall_dump_pcpu_lapic_info(void *data)
{
	buffer_t *buf = (buffer_t *)data;
	dump_lapic_info(buf->buf, buf->size);
}

static void dump_pcpu_lapic_info(uint16_t pcpu_id, char *buf, size_t bufsize)
{
	if (pcpu_id == get_pcpu_id()) {
		dump_lapic_info(buf, bufsize);
	} else {
		uint64_t mask = 0UL;
		buffer_t buff = { .buf = buf, .size = bufsize };
		bitmap_set_nolock(pcpu_id, &mask);
		smp_call_function(mask, smpcall_dump_pcpu_lapic_info, &buff);
	}
}

int32_t shell_lapic_info(int32_t argc, char **argv)
{
	uint16_t pcpu_id;

	if (argc == 1) {
		pcpu_id = get_pcpu_id();
	} else if (argc == 2) {
		pcpu_id = (uint16_t)strtol_deci(argv[1]);
	} else {
		shell_puts("Usage: lapic [<pcpu_id>]\r\n");
		return -EINVAL;
	}

	if (pcpu_id >= get_pcpu_nums()) {
		printf("invalid pcpu_id %d\n", pcpu_id);
		return -EINVAL;
	}

	dump_pcpu_lapic_info(pcpu_id, shell_log_buf, SHELL_LOG_BUF_SIZE);

	shell_puts(shell_log_buf);
	return 0;
}

/*
 * "vlapic" command
 */

static void dump_vlapic_info(struct acrn_vcpu *vcpu, char *buf, size_t bufsize)
{
	const struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);
	const struct lapic_regs *regs = &(vlapic->apic_page);

	snprintf(buf, bufsize,
		 "vapic id = %08x\n"
		 "ID =%08x VER=%08x TPR=%08x APR=%08x PPR=%08x\n"
		 "RRD=%08x LDR=%08x DFR=%08x SVR=%08x\n"
		 "ISR=%08x%08x%08x%08x%08x%08x%08x%08x\n"
		 "TMR=%08x%08x%08x%08x%08x%08x%08x%08x\n"
		 "IRR=%08x%08x%08x%08x%08x%08x%08x%08x\n"
		 "ESR=%08x CMCI=%08x\n"
		 "ICR (full)=%016lx\n"
		 "LVT[0-6]=%08x %08x %08x %08x %08x %08x\n"
		 "TMR: ICR=%08x CCR=%08x DCR=%08x\n",
		 vlapic->vapic_id,
		 regs->id.v, regs->version.v, regs->tpr.v, regs->apr.v,
		 regs->ppr.v, regs->rrd.v, regs->ldr.v,
		 regs->dfr.v, regs->svr.v,
		 regs->isr[7].v, regs->isr[6].v, regs->isr[5].v,
		 regs->isr[4].v, regs->isr[3].v, regs->isr[2].v,
		 regs->isr[1].v, regs->isr[0].v,
		 regs->tmr[7].v, regs->tmr[6].v, regs->tmr[5].v,
		 regs->tmr[4].v, regs->tmr[3].v, regs->tmr[2].v,
		 regs->tmr[1].v, regs->tmr[0].v,
		 regs->irr[7].v, regs->irr[6].v, regs->irr[5].v,
		 regs->irr[4].v, regs->irr[3].v, regs->irr[2].v,
		 regs->irr[1].v, regs->irr[0].v,
		 regs->esr.v, regs->lvt_cmci.v,
		 ((uint64_t)regs->icr_hi.v << 32) | regs->icr_lo.v,
		 regs->lvt[0].v, regs->lvt[1].v, regs->lvt[2].v,
		 regs->lvt[3].v, regs->lvt[4].v, regs->lvt[5].v,
		 regs->icr_timer.v, regs->ccr_timer.v, regs->dcr_timer.v);
}

int32_t shell_vlapic_info(int32_t argc, char **argv)
{
	uint16_t vmid;
	uint16_t vcpuid;

	if (argc != 3) {
		shell_puts("Usage: vlapic <vm_id> <vcpu_id>\r\n");
		return -EINVAL;
	}

	vmid = (uint16_t)strtol_deci(argv[1]);
	vcpuid = (uint16_t)strtol_deci(argv[2]);

	if (vmid >= CONFIG_MAX_VM_NUM) {
		return -EINVAL;
	} else {
		struct acrn_vm *vm = get_vm_from_vmid(vmid);

		if (!is_poweroff_vm(vm)) {
			uint16_t idx;
			struct acrn_vcpu *vcpu;

			foreach_vcpu(idx, vm, vcpu) {
				if (vcpu->vcpu_id == vcpuid) {
					dump_vlapic_info(vcpu, shell_log_buf, SHELL_LOG_BUF_SIZE);
					shell_puts(shell_log_buf);
				}
			}
		}
	}

	return 0;
}

/*
 * "memory-map" command
 */

#define PGTABLE_BASE_HPA(v) (hpa2hva(BITS((v), 51, 12) << 12))

/* Human readable size */
typedef struct hr_size {
	uint64_t val;
	char unit;			     /* G/M/K */
} hr_size_t;

hr_size_t hr_size(uint64_t size)
{
	if ((size & (0x40000000UL - 1)) == 0)
		return (hr_size_t){ . val = size >> 30, .unit = 'G' };

	if ((size & (0x100000UL - 1)) == 0)
		return (hr_size_t){ . val = size >> 20, .unit = 'M' };

	return (hr_size_t){ . val = size >> 10, .unit = 'K' };
}

typedef struct mmap {
	int shift;
	uint64_t la;
	uint64_t pa;
	uint64_t size;
	uint64_t attr;
} mmap_t;

typedef void (*mmap_fn_t)(mmap_t *);

typedef union pml4e {
	uint64_t v;
	struct {
		uint64_t p : 1;		     /* 0 (Present) */
		uint64_t rw : 1;	     /* 1 (R/W) */
		uint64_t us : 1;	     /* 2 (U/S) */
		uint64_t pwt : 1;	     /* 3 page-level write-through */
		uint64_t pcd : 1;	     /* 4 page-level cache disable */
		uint64_t a : 1;		     /* 5 accessed */
		uint64_t ignored : 1;	     /* 6 ignored */
		uint64_t reserved : 1;	     /* 7 must be 0*/
		uint64_t ignored2 : 4;	     /* 11:8 ignored */
		uint64_t ppa : 40;	     /* 51:12 physical address*/
		uint64_t ignored3 : 11;	     /* 62:52 ignored */
		uint64_t xd : 1;	     /* 63 XD */
	} s;
} pml4e_t;

typedef union pdpte {
	uint64_t v;
	struct {
		uint64_t p : 1;		     /* 0 (Present) */
		uint64_t rw : 1;	     /* 1 (R/W) */
		uint64_t us : 1;	     /* 2 (U/S) */
		uint64_t pwt : 1;	     /* 3 page-level write-through */
		uint64_t pcd : 1;	     /* 4 page-level cache disable */
		uint64_t a : 1;		     /* 5 accessed */
		uint64_t d : 1;		     /* 6 dirty */
		uint64_t ps : 1;	     /* 7 page size, must be 0*/
		uint64_t ignored : 4;	     /* 11:8 ignored */
		uint64_t ppa : 40;	     /* 51:12 physical address */
		uint64_t ignored2 : 10;	     /* 62:53 ignored */
		uint64_t xd : 1;	     /* 63 XD */
	} p;
	struct {
		uint64_t p : 1;		     /* 0 (Present) */
		uint64_t rw : 1;	     /* 1 (R/W) */
		uint64_t us : 1;	     /* 2 (U/S) */
		uint64_t pwt : 1;	     /* 3 page-level write-through */
		uint64_t pcd : 1;	     /* 4 page-level cache disable */
		uint64_t a : 1;		     /* 5 accessed */
		uint64_t d : 1;		     /* 6 dirty */
		uint64_t ps : 1;	     /* 7 page size, must be 1 */
		uint64_t g : 1;		     /* 8 global*/
		uint64_t ignored : 3;	     /* 11:9 */
		uint64_t pat : 1;	     /* 12 PAT */
		uint64_t reserved : 17;	     /* 29:13 must be 0 */
		uint64_t pa_1g : 12;	     /* 51:30 1G physical address*/
		uint64_t ignored2 : 7;	     /* 58:52 ignored */
		uint64_t prot : 4;	     /* 62:59 protection key */
		uint64_t xd : 1;	     /* 63 XD */
	} m;
} pdpte_t;

typedef union pdte {
	uint64_t v;
	struct {
		uint64_t p : 1;		     /* 0 (Present) */
		uint64_t rw : 1;	     /* 1 (R/W) */
		uint64_t us : 1;	     /* 2 (U/S) */
		uint64_t pwt : 1;	     /* 3 page-level write-through */
		uint64_t pcd : 1;	     /* 4 page-level cache disable */
		uint64_t a : 1;		     /* 5 accessed */
		uint64_t d : 1;		     /* 6 dirty */
		uint64_t ps : 1;	     /* 7 page size must be 0*/
		uint64_t ignored : 4;	     /* 11:8 ignored */
		uint64_t ppa : 40;	     /* 51:12 physical address */
		uint64_t ignored2 : 10;	     /* 62:53 ignored */
		uint64_t xd : 1;	     /* 63 XD */
	} p;
	struct {
		uint64_t p : 1;		     /* 0 (Present) */
		uint64_t rw : 1;	     /* 1 (R/W) */
		uint64_t us : 1;	     /* 2 (U/S) */
		uint64_t pwt : 1;	     /* 3 page-level write-through */
		uint64_t pcd : 1;	     /* 4 page-level cache disable */
		uint64_t a : 1;		     /* 5 accessed */
		uint64_t d : 1;		     /* 6 dirty */
		uint64_t ps : 1;	     /* 7 page size must be 1 */
		uint64_t g : 1;		     /* 8 global*/
		uint64_t ignored : 3;	     /* 11:9 */
		uint64_t pat : 1;	     /* 12 PAT */
		uint64_t reserved : 8;	     /* 20:13 must be 0 */
		uint64_t pa_2m : 12;	     /* 51:21 2M physical address*/
		uint64_t ignored2 : 7;	     /* 58:52 ignored */
		uint64_t prot : 4;	     /* 62:59 protection key */
		uint64_t xd : 1;	     /* 63 XD */
	} m;
} pdte_t;

typedef union pte {
	uint64_t v;
	struct {
		uint64_t p : 1;		     /* 0 (Present) */
		uint64_t rw : 1;	     /* 1 (R/W) */
		uint64_t us : 1;	     /* 2 (U/S) */
		uint64_t pwt : 1;	     /* 3 page-level write-through */
		uint64_t pcd : 1;	     /* 4 page-level cache disable */
		uint64_t a : 1;		     /* 5 accessed */
		uint64_t d : 1;		     /* 6 dirty */
		uint64_t pat : 1;	     /* 7 PAT */
		uint64_t g : 1;		     /* 8 global*/
		uint64_t ignored : 3;	     /* 11:9 */
		uint64_t pa_4k : 40;	     /* 51:12 4K physical address*/
		uint64_t ignored2 : 7;	     /* 58:52 ignored */
		uint64_t prot : 4;	     /* 62:59 protection key */
		uint64_t xd : 1;	     /* 63 XD */
	} s;
} pte_t;

_Static_assert(sizeof(pml4e_t) == sizeof(uint64_t), "");
_Static_assert(sizeof(pdpte_t) == sizeof(uint64_t), "");
_Static_assert(sizeof(pdte_t) == sizeof(uint64_t), "");
_Static_assert(sizeof(pte_t) == sizeof(uint64_t), "");

static bool is_valid_pml4e(pml4e_t *pml4e)
{
	return pml4e && pml4e->s.p && pml4e->s.reserved == 0;
}

static bool is_valid_pdpte(pdpte_t *pdpte)
{
	return (pdpte && pdpte->p.p
		&& ((pdpte->p.ps == 0)
		    || (pdpte->m.reserved == 0)));
}

static bool is_valid_pdte(pdte_t *pdte)
{
	return (pdte && pdte->p.p
		&& ((pdte->p.ps == 0)
		    || (pdte->m.reserved == 0)));
}

static bool is_valid_pte(pte_t *pte)
{
	return (pte && pte->s.p != 0);
}

/* SDM 4.5
   A logical processor uses 4-level paging if CR0.PG = 1, CR4.PAE = 1,
   IA32_EFER.LME = 1, and CR4.LA57 = 0.
*/
static void walk_l4_pgtable(pml4e_t *pml4e,
			    void (*fn)(void *data, int shift, uint64_t entry, uint64_t base),
			    void *fn_data)
{
	for (uint64_t i = 0; i < 512; i++, pml4e++) {
		if (!is_valid_pml4e(pml4e))
			continue;

		(*fn)(fn_data, 39, pml4e->v, i << 39);

		/* descendent to PDPT */
		pdpte_t *pdpte = PGTABLE_BASE_HPA(pml4e->v);
		for (uint64_t j = 0; j < 512; j++, pdpte++) {
			if (!is_valid_pdpte(pdpte))
				continue;

			(*fn)(fn_data, 30, pdpte->v, i << 39 | j << 30);

			if (pdpte->p.ps)
				continue;

			/* descendent to PDT */
			pdte_t *pdte = PGTABLE_BASE_HPA(pdpte->v);
			for (uint64_t k = 0; k < 512; k++, pdte++) {
				if (!is_valid_pdte(pdte))
					continue;

				(*fn)(fn_data, 21, pdte->v,
				      i << 39 | j << 30 | k << 21);

				if (pdte->p.ps)
					continue;

				/* descendent to PT */
				pte_t *pte = PGTABLE_BASE_HPA(pdte->v);
				for (uint64_t m = 0; m < 512; m++, pte++) {
					if (is_valid_pte(pte))
						(*fn)(fn_data, 12, pte->v,
						      i << 39 | j << 30
						      | k << 21 | m << 12);
				}
			}
		}
	}
}

/*
 * data structure and routines for page table information collection
 */

typedef struct l4_pgtable_walk_data {
	uint64_t cr3;
	size_t pml4e_p;
	size_t pdpte_ps, pdpte_p;
	size_t pdte_ps, pdte_p;
	size_t pte_p;

	mmap_t last;

	mmap_fn_t mmap_fn;
} l4_pgtable_walk_data_t;

typedef struct l4_pgtable_info {
	uint64_t root;
	size_t pml4_pages;
	size_t pdpt_pages;
	size_t pdt_pages;
	size_t pt_pages;
	size_t mem_1g_pages;
	size_t mem_2m_pages;
	size_t mem_4k_pages;
} l4_pgtable_info_t;


l4_pgtable_info_t l4_pgtable_info_from_data(const l4_pgtable_walk_data_t *data)
{
	l4_pgtable_info_t ret;

	ret.root = data->cr3 & ~(BIT(12) - 1);
	ret.pml4_pages = 1;
	ret.pdpt_pages = data->pml4e_p;
	ret.pdt_pages = data->pdpte_p - data->pdpte_ps;
	ret.pt_pages = data->pdte_p - data->pdte_ps;
	ret.mem_1g_pages = data->pdpte_ps;
	ret.mem_2m_pages = data->pdte_ps;
	ret.mem_4k_pages = data->pte_p;

	return ret;
}

static void dump_mmap1(mmap_t *mmap)
{
	ASSERT(mmap->size != 0);

	hr_size_t sz = hr_size(mmap->size);

	/* pte could be pte.s, pdte.m or pdpte.m */
	pte_t *pte = (void *)&mmap->attr;

	char str[256];

	snprintf(str, sizeof str,
		 "[%016lx-%016lx] : [%016lx-%016lx] %5ld%c (%s)"
		 " %c%c%c%c%c%c%c%c%c\n",
		 mmap->la, mmap->la + mmap->size - 1,
		 mmap->pa, mmap->pa + mmap->size - 1,
		 sz.val, sz.unit,
		 (mmap->shift == 30 ? "1G" :
		  mmap->shift == 21 ? "2M" : "4K"),
		 pte->s.xd ? '-' : 'X',
		 pte->s.g ? 'G' : '-',
		 pte->s.pat ? 'P' : '-',
		 pte->s.d ? 'D' : '-',
		 pte->s.a ? 'A' : '-',
		 pte->s.pcd ? '-' : 'C',
		 pte->s.pwt ? 'T' : 'B',
		 pte->s.us ? 'U' : 'S',
		 pte->s.us ? 'R' : 'W'
		);
	shell_puts(str);

	/* reset range */
	mmap->size = 0;
}

static void update_mmap(int shift, mmap_t *last, uint64_t la, uint64_t pa, uint64_t attr,
			mmap_fn_t fn)
{
	if ((last->shift == shift)
	    && (last->la + last->size == la)
	    && (last->pa + last->size == pa)
	    && (last->attr == attr)) {
		/* tack together */
		last->size += 1UL << shift;
	} else {
		if (last->size != 0 && fn) {
			fn(last);
		}
		last->shift = shift;
		last->la = la;
		last->pa = pa;
		last->attr = attr;
		last->size = 1UL << shift;
	}
}

static void l4_pgtable_walk_fn(void *cb_data, int shift, uint64_t ent, uint64_t la)
{
	l4_pgtable_walk_data_t *data = cb_data;

	if (shift == 39) {
		data->pml4e_p++;
	} else if (shift == 30) {
		data->pdpte_p++;

		if ((ent & BIT(7)) == 0)
			return;

		data->pdpte_ps++;

		uint64_t pa = ent & ((BIT(52) - 1) >> 30 << 30);
		uint64_t attr = ent & ~((BIT(52) - 1) >> 30 << 30);
		mmap_t *last = &data->last;

		update_mmap(shift, last, la, pa, attr, data->mmap_fn);

	} else if (shift == 21) {
		data->pdte_p++;

		if ((ent & BIT(7)) == 0)
			return;

		data->pdte_ps++;

		uint64_t pa = ent & ((BIT(52) - 1) >> 21 << 21);
		uint64_t attr = ent & ~((BIT(52) - 1) >> 21 << 21);
		mmap_t *last = &data->last;

		update_mmap(shift, last, la, pa, attr, data->mmap_fn);
	} else if (shift == 12) {
		data->pte_p++;

		uint64_t pa = ent & ((BIT(52) - 1) >> 12 << 12);
		uint64_t attr = ent & ~((BIT(52) - 1) >> 12 << 12);
		mmap_t *last = &data->last;

		update_mmap(shift, last, la, pa, attr, data->mmap_fn);
	} else
		ASSERT(0);
}

static l4_pgtable_info_t scan_l4_pgtable(pml4e_t *base, mmap_fn_t fn)
{
	l4_pgtable_walk_data_t data = {
		.mmap_fn = fn
	};

	walk_l4_pgtable(base, l4_pgtable_walk_fn, &data);
	if (data.last.size && fn)
		fn(&data.last);

	return l4_pgtable_info_from_data(&data);
}

static void dump_l4_pgtable_info(const l4_pgtable_info_t *info, void *root, char *buf, size_t bufsize)
{
	snprintf(buf, bufsize,
		 "%16s : 0x%016lx\n"
		 "%16s : %d\n"
		 "%16s : %d\n"
		 "%16s : %d\n"
		 "%16s : %d\n"
		 "%16s : %d\n"
		 "%16s : %d\n"
		 "%16s : %d\n",
		 "Root pointer", (uint64_t)root,
		 "PML4 pages", info->pml4_pages,
		 "PDPT pages", info->pdpt_pages,
		 "PDT pages", info->pdt_pages,
		 "PT pages", info->pt_pages,
		 "1G pages", info->mem_1g_pages,
		 "2M pages", info->mem_2m_pages,
		 "4K pages", info->mem_4k_pages);
}

static void dump_hv_memory_map(char *buf, size_t bufsize)
{
	uint64_t cr3;
	pml4e_t *base;
	l4_pgtable_info_t info;

 	CPU_CR_READ(cr3, &cr3);
	base = PGTABLE_BASE_HPA(cr3);

	info = scan_l4_pgtable(base, dump_mmap1);
	dump_l4_pgtable_info(&info, base, buf, bufsize);
}

int32_t shell_memory_map(int32_t argc, __unused char **argv)
{
	if (argc != 1) {
		return -EINVAL;
	} else {
		dump_hv_memory_map(shell_log_buf, SHELL_LOG_BUF_SIZE);
		shell_puts(shell_log_buf);
		return 0;
	}
}


/*
 * "dump-ept" command
 */

static bool is_valid_ept_entry(unsigned int shift, uint64_t ent)
{
	if (BITS(ent, 2, 0) == 0)
		return false;

	if (shift == 12) {
		return true;
	} else if (shift == 21) {
		return ((ent & BIT(7)) == 0) ? BITS(ent, 7, 3) == 0
			: BITS(ent, 20, 12) == 0;
	} else if (shift == 30) {
		return ((ent & BIT(7)) == 0) ? BITS(ent, 7, 3) == 0
			: BITS(ent, 29, 12) == 0;
	} else if (shift == 39)
		return BITS(ent, 7, 3) == 0;

	ASSERT(0);
	return false;
}

static void walk_ept_pgtable(uint64_t *pml4,
			     void (*fn)(void *data, int shift, uint64_t entry, uint64_t base),
			     void *fn_data)
{
	for (uint64_t i = 0; i < 512; i++) {
		uint64_t pml4e = *(pml4 + i);
		if (!is_valid_ept_entry(39, pml4e))
			continue;

		(*fn)(fn_data, 39, pml4e, i << 39);

		/* descendent to PDPT */
		uint64_t *pdpt = PGTABLE_BASE_HPA(pml4e);
		for (uint64_t j = 0; j < 512; j++) {
			uint64_t pdpte = *(pdpt + j);
			if (!is_valid_ept_entry(30, pdpte))
				continue;

			(*fn)(fn_data, 30, pdpte, i << 39 | j << 30);

			if ((pdpte & BIT(7)) != 0)
				continue;

			/* descendent to PDT */
			uint64_t *pdt = PGTABLE_BASE_HPA(pdpte);
			for (uint64_t k = 0; k < 512; k++) {
				uint64_t pdte = *(pdt + k);
				if (!is_valid_ept_entry(21, pdte))
					continue;

				(*fn)(fn_data, 21, pdte,
				      i << 39 | j << 30 | k << 21);

				if ((pdte & BIT(7)) != 0)
					continue;

				/* descendent to PT */
				uint64_t *pt = PGTABLE_BASE_HPA(pdte);
				for (uint64_t m = 0; m < 512; m++) {
					uint64_t pte = *(pt + m);
					if (is_valid_ept_entry(12, pte))
						(*fn)(fn_data, 12, pte,
						      i << 39 | j << 30
						      | k << 21 | m << 12);
				}
			}
		}
	}
}

static l4_pgtable_info_t scan_ept_pgtable(uint64_t *pml4e, mmap_fn_t fn)
{
	l4_pgtable_walk_data_t data = {
		.mmap_fn = fn
	};

	walk_ept_pgtable(pml4e, l4_pgtable_walk_fn, &data);
	if (data.last.size && fn)
		fn(&data.last);

	return l4_pgtable_info_from_data(&data);
}

static void dump_ept_mmap1(mmap_t *mmap)
{
	ASSERT(mmap->size != 0);

	hr_size_t sz = hr_size(mmap->size);
	uint64_t attr = mmap->attr;
	uint32_t mt = BITS(attr, 5, 3);
	char str[256];

	snprintf(str, sizeof str,
		 "[%016lx-%016lx] : [%016lx-%016lx] %5ld%c (%s)"
		 " %s [%1lx%03lx]\n",
		 mmap->la, mmap->la + mmap->size - 1,
		 mmap->pa, mmap->pa + mmap->size - 1,
		 sz.val, sz.unit,
		 mmap->shift == 30 ? "1G" : mmap->shift == 21 ? "2M" : "4K",
		 mt == 0 ? "UC" : mt == 1 ? "WC" : mt == 4 ? "WT" :
		 mt == 5 ? "WP" : mt == 6 ? "WB" : "--",
		 BITS(attr, 63, 60),
		 BITS(attr, 11, 0));

	shell_puts(str);

	/* reset range */
	mmap->size = 0;
}

static void dump_vm_ept(struct acrn_vm *vm, char *buf, size_t bufsize)
{
	uint64_t *pml4 = (uint64_t*)get_ept_entry(vm);
	l4_pgtable_info_t info = scan_ept_pgtable(pml4, dump_ept_mmap1);

	dump_l4_pgtable_info(&info, pml4, buf, bufsize);
}

int32_t shell_dump_ept(int32_t argc, char **argv)
{
	if (argc == 2) {
		uint16_t vmid = (uint16_t)strtol_deci(argv[1]);

		if (vmid < CONFIG_MAX_VM_NUM) {
			struct acrn_vm *vm = get_vm_from_vmid(vmid);
			if (!is_poweroff_vm(vm)) {
				dump_vm_ept(vm, shell_log_buf, SHELL_LOG_BUF_SIZE);
				shell_puts(shell_log_buf);
				return 0;
			}
		}
	}

	return -EINVAL;
}

/*
 * "show-guest-mmap" command
 */

#define PGTABLE_BASE_GPA(v) (gpa2hva(vm, BITS((v), 51, 12) << 12))

static void
walk_vm_pgtable(struct acrn_vcpu *vcpu, uint64_t root,
		void (*fn)(void *data, int shift, uint64_t entry, uint64_t base),
		void *fn_data)
{
	struct acrn_vm *vm = vcpu->vm;
	pml4e_t *pml4e = PGTABLE_BASE_GPA(root);

	stac();
	for (uint64_t i = 0; i < 512; i++, pml4e++) {
		if (!is_valid_pml4e(pml4e))
			continue;

		(*fn)(fn_data, 39, pml4e->v, i << 39);

		/* descendent to PDPT */
		pdpte_t *pdpte = PGTABLE_BASE_GPA(pml4e->v);
		for (uint64_t j = 0; j < 512; j++, pdpte++) {
			if (!is_valid_pdpte(pdpte))
				continue;

			(*fn)(fn_data, 30, pdpte->v, i << 39 | j << 30);

			if (pdpte->p.ps)
				continue;

			/* descendent to PDT */
			pdte_t *pdte = PGTABLE_BASE_GPA(pdpte->v);
			for (uint64_t k = 0; k < 512; k++, pdte++) {
				if (!is_valid_pdte(pdte))
					continue;

				(*fn)(fn_data, 21, pdte->v,
				      i << 39 | j << 30 | k << 21);

				if (pdte->p.ps)
					continue;

				/* descendent to PT */
				pte_t *pte = PGTABLE_BASE_GPA(pdte->v);
				for (uint64_t m = 0; m < 512; m++, pte++) {
					if (is_valid_pte(pte))
						(*fn)(fn_data, 12, pte->v,
						      i << 39 | j << 30
						      | k << 21 | m << 12);
				}
			}
		}
	}
	clac();
}

static l4_pgtable_info_t scan_vm_pgtable(struct acrn_vcpu *vcpu, uint64_t gpa, mmap_fn_t fn)
{
	l4_pgtable_walk_data_t data = {
		.mmap_fn = fn
	};

	walk_vm_pgtable(vcpu, gpa, l4_pgtable_walk_fn, &data);
	if (data.last.size && fn)
		fn(&data.last);

	return l4_pgtable_info_from_data(&data);
}

static bool local_show_guest_mmap(struct acrn_vm *vm, struct acrn_vcpu *vcpu, char *buf, size_t bufsize)
{
	if (get_vcpu_mode(vcpu) == CPU_MODE_64BIT) {
		uint64_t cr3 = exec_vmread(VMX_GUEST_CR3);
		l4_pgtable_info_t info = scan_vm_pgtable(vcpu, cr3, dump_mmap1);

		dump_l4_pgtable_info(&info, PGTABLE_BASE_GPA(cr3), buf, bufsize);
		return true;
	}

	return false;
}

struct smpcall_show_guest_mmap_params {
	struct acrn_vm *vm;
	struct acrn_vcpu *vcpu;
	char *buf;
	size_t bufsize;
	bool ret;
};

__unused static void smpcall_show_guest_mmap(void *params)
{
	struct smpcall_show_guest_mmap_params *p = params;

	p->ret = local_show_guest_mmap(p->vm, p->vcpu, p->buf, p->bufsize);
}

static bool show_guest_mmap(struct acrn_vm *vm, struct acrn_vcpu *vcpu, char *buf, size_t bufsize)
{
	uint16_t pcpu_id = pcpuid_from_vcpu(vcpu);

	if (pcpu_id == get_pcpu_id()) {
		return local_show_guest_mmap(vm, vcpu, buf, bufsize);
	} else {
		uint64_t mask = 0UL;
		struct smpcall_show_guest_mmap_params params = {
			.vm = vm,
			.vcpu = vcpu,
			.buf = buf,
			.bufsize = bufsize,
			.ret = false
		};
		bitmap_set_nolock(pcpu_id, &mask);
		smp_call_function(mask, smpcall_show_guest_mmap, &params);
		return params.ret;
	}
}

int32_t shell_show_guest_mmap(int32_t argc, char **argv)
{
	uint16_t vmid;
	uint16_t vcpuid;

	if (argc != 3) {
		shell_puts("Usage: show-guest-mmap <vm_id> <vcpu_id>\r\n");
		return -EINVAL;
	}

	vmid = (uint16_t)strtol_deci(argv[1]);
	vcpuid = (uint16_t)strtol_deci(argv[2]);

	if (vmid >= CONFIG_MAX_VM_NUM) {
		return -EINVAL;
	} else {
		struct acrn_vm *vm = get_vm_from_vmid(vmid);

		if (!is_poweroff_vm(vm)) {
			uint16_t idx;
			struct acrn_vcpu *vcpu;

			foreach_vcpu(idx, vm, vcpu) {
				if (vcpu->vcpu_id == vcpuid) {
					if (show_guest_mmap(vm, vcpu, shell_log_buf, SHELL_LOG_BUF_SIZE)) {
						shell_puts(shell_log_buf);
					}
				}
			}
		}
	}

	return 0;
}
