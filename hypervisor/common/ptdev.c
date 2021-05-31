/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <asm/per_cpu.h>
#include <asm/guest/vm.h>
#include <softirq.h>
#include <ptdev.h>
#include <irq.h>
#include <logmsg.h>
#include <asm/vtd.h>
#include <ticks.h>

#define PTIRQ_BITMAP_ARRAY_SIZE	INT_DIV_ROUNDUP(CONFIG_MAX_PT_IRQ_ENTRIES, 64U)
struct ptdev_entry ptdev_entries[CONFIG_MAX_PT_IRQ_ENTRIES];
static uint64_t ptdev_entry_bitmaps[PTIRQ_BITMAP_ARRAY_SIZE];
spinlock_t ptdev_lock = { .head = 0U, .tail = 0U, };

static inline uint16_t ptdev_alloc_entry_id(void)
{
	uint16_t id = (uint16_t)ffz64_ex(ptdev_entry_bitmaps, CONFIG_MAX_PT_IRQ_ENTRIES);

	while (id < CONFIG_MAX_PT_IRQ_ENTRIES) {
		if (!bitmap_test_and_set_lock((id & 0x3FU), &ptdev_entry_bitmaps[id >> 6U])) {
			break;
		}
		id = (uint16_t)ffz64_ex(ptdev_entry_bitmaps, CONFIG_MAX_PT_IRQ_ENTRIES);
	}

	return (id < CONFIG_MAX_PT_IRQ_ENTRIES) ? id: INVALID_PTDEV_ENTRY_ID;
}

static void ptdev_enqueue_softirq(struct ptdev_entry *entry)
{
	uint64_t rflags;

	/* enqueue request in order, SOFTIRQ_PTDEV will pickup */
	CPU_INT_ALL_DISABLE(&rflags);

	/* avoid adding recursively */
	list_del(&entry->softirq_node);
	/* TODO: assert if entry already in list */
	list_add_tail(&entry->softirq_node, &get_cpu_var(softirq_dev_entry_list));
	CPU_INT_ALL_RESTORE(rflags);
	fire_softirq(SOFTIRQ_PTDEV);
}

static void ptdev_intr_delay_callback(void *data)
{
	struct ptdev_entry *entry = (struct ptdev_entry *) data;

	ptdev_enqueue_softirq(entry);
}

struct ptdev_entry *ptdev_dequeue_softirq(uint16_t pcpu_id)
{
	uint64_t rflags;
	struct ptdev_entry *entry = NULL;

	CPU_INT_ALL_DISABLE(&rflags);

	while (!list_empty(&get_cpu_var(softirq_dev_entry_list))) {
		entry = get_first_item(&per_cpu(softirq_dev_entry_list, pcpu_id), struct ptdev_entry, softirq_node);

		list_del_init(&entry->softirq_node);

		/* if sos vm, just dequeue, if uos, check delay timer */
		if (is_sos_vm(entry->vm) || timer_expired(&entry->intr_delay_timer, cpu_ticks(), NULL)) {
			break;
		} else {
			/* add it into timer list; dequeue next one */
			(void)add_timer(&entry->intr_delay_timer);
			entry = NULL;
		}
	}

	CPU_INT_ALL_RESTORE(rflags);
	return entry;
}

struct ptdev_entry *ptdev_alloc_entry(struct acrn_vm *vm, uint32_t intr_type)
{
	struct ptdev_entry *entry = NULL;
	uint16_t ptdev_id = ptdev_alloc_entry_id();

	if (ptdev_id < CONFIG_MAX_PT_IRQ_ENTRIES) {
		entry = &ptdev_entries[ptdev_id];
		(void)memset((void *)entry, 0U, sizeof(struct ptdev_entry));
		entry->ptdev_entry_id = ptdev_id;
		entry->vm = vm;

		INIT_LIST_HEAD(&entry->softirq_node);

		initialize_timer(&entry->intr_delay_timer, ptdev_intr_delay_callback, entry, 0UL, 0UL);
		initialize_ptirq_remapping_info(remapping_info_of_ptdev(entry), intr_type);
	} else {
		pr_err("Alloc ptdev irq entry failed");
	}

	return entry;
}

void ptdev_release_entry(struct ptdev_entry *entry)
{
	uint64_t rflags;

	CPU_INT_ALL_DISABLE(&rflags);
	list_del_init(&entry->softirq_node);
	del_timer(&entry->intr_delay_timer);
	CPU_INT_ALL_RESTORE(rflags);

	bitmap_clear_lock((entry->ptdev_entry_id) & 0x3FU, &ptdev_entry_bitmaps[entry->ptdev_entry_id >> 6U]);

	ptirq_release_remapping_info(remapping_info_of_ptdev(entry));

	(void)memset((void *)entry, 0U, sizeof(struct ptdev_entry));
}

/* interrupt context */
static void ptdev_interrupt_handler(__unused uint32_t irq, void *data)
{
	struct ptdev_entry *entry = (struct ptdev_entry *) data;
	bool to_enqueue = true;

	/*
	 * "interrupt storm" detection & delay intr injection just for UOS
	 * pass-thru devices, collect its data and delay injection if needed
	 */
	if (!is_sos_vm(entry->vm)) {
		entry->intr_count++;

		/* if delta > 0, set the delay TSC, dequeue to handle */
		if (entry->vm->intr_inject_delay_delta > 0UL) {

			/* if the timer started (entry is in timer-list), not need enqueue again */
			if (timer_is_started(&entry->intr_delay_timer)) {
				to_enqueue = false;
			} else {
				update_timer(&entry->intr_delay_timer,
					     cpu_ticks() + entry->vm->intr_inject_delay_delta, 0UL);
			}
		} else {
			update_timer(&entry->intr_delay_timer, 0UL, 0UL);
		}
	}

	if (to_enqueue) {
		ptdev_enqueue_softirq(entry);
	}
}

/* active intr with irq registering */
int32_t ptdev_activate_entry(struct ptdev_entry *entry, uint32_t phys_irq)
{
	int32_t retval;

	/* register and allocate host vector/irq */
	retval = request_irq(phys_irq, ptdev_interrupt_handler, (void *)entry, IRQF_PT);

	if (retval < 0) {
		pr_err("request irq failed, please check!, phys-irq=%d", phys_irq);
	} else {
		entry->allocated_pirq = (uint32_t)retval;
		ptirq_activate_remapping_info(remapping_info_of_ptdev(entry));
		entry->active = true;
	}

	return retval;
}

void ptdev_deactivate_entry(struct ptdev_entry *entry)
{
	ptirq_deactivate_remapping_info(remapping_info_of_ptdev(entry));
	entry->active = false;
	free_irq(entry->allocated_pirq);
}

void ptdev_init(void)
{
	if (get_pcpu_id() == BSP_CPU_ID) {
		register_softirq(SOFTIRQ_PTDEV, ptirq_softirq);
	}
	INIT_LIST_HEAD(&get_cpu_var(softirq_dev_entry_list));
}

void ptdev_release_all_entries(const struct acrn_vm *vm)
{
	struct ptdev_entry *entry;
	uint16_t idx;

	/* VM already down */
	for (idx = 0U; idx < CONFIG_MAX_PT_IRQ_ENTRIES; idx++) {
		entry = &ptdev_entries[idx];
		if ((entry->vm == vm) && is_entry_active(entry)) {
			spinlock_obtain(&ptdev_lock);
			struct ptirq_remapping_info *info = remapping_info_of_ptdev(entry);
			if (info->release_cb != NULL) {
				info->release_cb(info);
			}
			ptdev_deactivate_entry(entry);
			ptdev_release_entry(entry);
			spinlock_release(&ptdev_lock);
		}
	}

}

uint32_t ptdev_get_intr_data(const struct acrn_vm *target_vm, uint64_t *buffer, uint32_t buffer_cnt)
{
	uint32_t index = 0U;
	uint16_t i;
	struct ptdev_entry *entry;

	for (i = 0U; i < CONFIG_MAX_PT_IRQ_ENTRIES; i++) {
		entry = &ptdev_entries[i];
		if (!is_entry_active(entry)) {
			continue;
		}
		if (entry->vm == target_vm) {
			buffer[index] = entry->allocated_pirq;
			buffer[index + 1U] = entry->intr_count;

			index += 2U;
			if (index > (buffer_cnt - 2U)) {
				break;
			}
		}
	}

	return index;
}
