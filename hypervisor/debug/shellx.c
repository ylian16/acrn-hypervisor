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

#define SHELL_LOG_BUF_SIZE (4096U * MAX_PCPU_NUM / 2U)
extern char shell_log_buf[];
extern void shell_puts(const char *);

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

static int32_t dump_pcpu_lapic_info(uint16_t pcpu_id)
{
	if (pcpu_id == get_pcpu_id()) {
		dump_lapic_info(shell_log_buf, SHELL_LOG_BUF_SIZE);
	} else {
		uint64_t mask = 0UL;
		buffer_t buf = { .buf = shell_log_buf, .size = SHELL_LOG_BUF_SIZE };
		bitmap_set_nolock(pcpu_id, &mask);
		smp_call_function(mask, smpcall_dump_pcpu_lapic_info, &buf);
	}

	return 0;
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

	return dump_pcpu_lapic_info(pcpu_id);
}

/*
 * "vlapic" command
 */

static int32_t dump_vlapic_info(struct acrn_vcpu *vcpu, char *buf, size_t bufsize)
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

	return 0;
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

	if (vmid < CONFIG_MAX_VM_NUM) {
		return -EINVAL;
	} else {
		struct acrn_vm *vm = get_vm_from_vmid(vmid);

		if (!is_poweroff_vm(vm)) {
			uint16_t idx;
			struct acrn_vcpu *vcpu;

			foreach_vcpu(idx, vm, vcpu) {
				if (vcpu->vcpu_id == vcpuid) {
					dump_vlapic_info(vcpu, shell_log_buf, SHELL_LOG_BUF_SIZE);
				}
			}
		}
	}

	return 0;
}
