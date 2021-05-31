/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PTDEV_H
#define PTDEV_H
#include <util.h>
#include <list.h>
#include <asm/lib/spinlock.h>
#include <timer.h>
#include <asm/guest/ptirq.h>

#define PTDEV_INTR_MSI		(1U << 0U)
#define PTDEV_INTR_INTX		(1U << 1U)

#define INVALID_PTDEV_ENTRY_ID 0xffffU

/* entry per each allocated irq/vector
 * it represents a pass-thru device's remapping data entry which collecting
 * information related with its vm and msi/intx mapping & interaction nodes
 * with interrupt handler and softirq.
 */
struct ptdev_entry {
	uint16_t ptdev_entry_id;
	struct acrn_vm *vm;
	bool active;			     /* true=active, false=inactive*/
	uint32_t allocated_pirq;	     /* valid only when active is true */
	struct list_head softirq_node;

	uint64_t intr_count;
	struct hv_timer intr_delay_timer;    /* used for delay intr injection */

	/* Arch specific IRQ remapping info.
	 * This should be treated as opaque data. It is only for performance
	 * considerations that it is not declared so.
	 */
	struct ptirq_remapping_info remapping_info;
};

static inline struct ptdev_entry *ptdev_of_remapping_info(struct ptirq_remapping_info *info)
{
	return container_of(info, struct ptdev_entry, remapping_info);
}

static inline const struct ptdev_entry *ptdev_of_remapping_info_const(const struct ptirq_remapping_info *info)
{
	return container_of(info, struct ptdev_entry, remapping_info);
}

static inline struct ptirq_remapping_info *remapping_info_of_ptdev(struct ptdev_entry *ptdev)
{
	return &ptdev->remapping_info;
}

static inline const struct ptirq_remapping_info *remapping_info_of_ptdev_const(const struct ptdev_entry *ptdev)
{
	return &ptdev->remapping_info;
}

static inline bool is_entry_active(const struct ptdev_entry *entry)
{
	return entry->active;
}

extern struct ptdev_entry ptdev_entries[CONFIG_MAX_PT_IRQ_ENTRIES];
extern spinlock_t ptdev_lock;

/**
 * @file ptdev.h
 *
 * @brief public APIs for ptdev
 */

/**
 * @brief ptdev
 *
 * @addtogroup acrn_passthrough
 * @{
 */
/**
 * @brief Passthrough device global data structure initialization.
 *
 * During the hypervisor cpu initialization stage, this function:
 * - init global spinlock for ptdev (on BSP)
 * - register SOFTIRQ_PTDEV handler (on BSP)
 * - init the softirq entry list for each CPU
 *
 */
void ptdev_init(void);
/**
 * @brief Deactivate and release all ptirq entries for a VM.
 *
 * This function deactivates and releases all ptirq entries for a VM. The function
 * should only be called after the VM is already down.
 *
 * @param[in]    vm acrn_vm on which the ptirq entries will be released
 *
 * @pre VM is already down
 *
 */
void ptdev_release_all_entries(const struct acrn_vm *vm);

/**
 * @brief Dequeue an entry from per cpu ptdev softirq queue.
 *
 * Dequeue an entry from the ptdev softirq queue on the specific physical cpu.
 *
 * @param[in]    pcpu_id physical cpu id
 *
 * @retval NULL when the queue is empty
 * @retval !NULL when there is available ptirq_remapping_info entry in the queue
 *
 */
struct ptdev_entry *ptdev_dequeue_softirq(uint16_t pcpu_id);
/**
 * @brief Allocate a ptirq_remapping_info entry.
 *
 * Allocate a ptirq_remapping_info entry for hypervisor to store the remapping information.
 * The total number of the entries is statically defined as CONFIG_MAX_PT_IRQ_ENTRIES.
 * Appropriate number should be configured on different platforms.
 *
 * @param[in]    vm acrn_vm that the entry allocated for.
 * @param[in]    intr_type interrupt type: PTDEV_INTR_MSI or PTDEV_INTR_INTX
 *
 * @retval NULL when the number of entries allocated is CONFIG_MAX_PT_IRQ_ENTRIES
 * @retval !NULL when the number of entries allocated is less than CONFIG_MAX_PT_IRQ_ENTRIES
 *
 */
struct ptdev_entry *ptdev_alloc_entry(struct acrn_vm *vm, uint32_t intr_type);
/**
 * @brief Release a ptirq_remapping_info entry.
 *
 * @param[in]    entry the ptirq_remapping_info entry to release.
 *
 */
void ptdev_release_entry(struct ptdev_entry *entry);
/**
 * @brief Activate a irq for the associated passthrough device.
 *
 * After activating the ptirq entry, the physical interrupt irq of passthrough device will be handled
 * by the handler  ptirq_interrupt_handler.
 *
 * @param[in]    entry the ptirq_remapping_info entry that will be associated with the physical irq.
 * @param[in]    phys_irq physical interrupt irq for the entry
 *
 * @retval success when return value >=0
 * @retval failure when return value < 0
 *
 */
int32_t ptdev_activate_entry(struct ptdev_entry *entry, uint32_t phys_irq);
/**
 * @brief De-activate a irq for the associated passthrough device.
 *
 * @param[in]    entry the ptirq_remapping_info entry that will be de-activated.
 *
 */
void ptdev_deactivate_entry(struct ptdev_entry *entry);
/**
 * @brief Get the interrupt information and store to the buffer provided.
 *
 * @param[in]    target_vm the VM to get the interrupt information.
 * @param[out]   buffer where interrupt information is stored.
 * @param[in]    buffer_cnt the size of the buffer.
 *
 * @retval the actual size the buffer filled with the interrupt information
 *
 */
uint32_t ptdev_get_intr_data(const struct acrn_vm *target_vm, uint64_t *buffer, uint32_t buffer_cnt);

/**
  * @}
  */

#endif /* PTDEV_H */
