/*
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ASSIGN_H
#define ASSIGN_H

#include <types.h>
#include <list.h>

enum intx_ctlr {
	INTX_CTLR_IOAPIC	= 0U,
	INTX_CTLR_PIC
};

union irte_index {
	uint16_t index;
	struct {
		uint16_t index_low:15;
		uint16_t index_high:1;
	} bits __packed;
};


union source_id {
	uint64_t value;
	struct {
		uint16_t bdf;
		uint16_t entry_nr;
		uint32_t reserved;
	} msi_id;
	/*
	 * ctlr indicates if the source of interrupt is IO-APIC or PIC
	 * pin indicates the pin number of interrupt controller determined by ctlr
	 */
	struct {
		enum intx_ctlr ctlr;
		uint32_t gsi;
	} intx_id;
};

/*
 * Macros for bits in union msi_addr_reg
 */

#define	MSI_ADDR_BASE			0xfeeUL	/* Base address for MSI messages */
#define	MSI_ADDR_RH			0x1U	/* Redirection Hint */
#define	MSI_ADDR_DESTMODE_LOGICAL	0x1U	/* Destination Mode: Logical*/
#define	MSI_ADDR_DESTMODE_PHYS		0x0U	/* Destination Mode: Physical*/

union msi_addr_reg {
	uint64_t full;
	struct {
		uint32_t rsvd_1:2;
		uint32_t dest_mode:1;
		uint32_t rh:1;
		uint32_t rsvd_2:8;
		uint32_t dest_field:8;
		uint32_t addr_base:12;
		uint32_t hi_32;
	} bits __packed;
	struct {
		uint32_t rsvd_1:2;
		uint32_t intr_index_high:1;
		uint32_t shv:1;
		uint32_t intr_format:1;
		uint32_t intr_index_low:15;
		uint32_t constant:12;
		uint32_t hi_32;
	} ir_bits __packed;

};

/*
 * Macros for bits in union msi_data_reg
 */

#define MSI_DATA_DELMODE_FIXED		0x0U	/* Delivery Mode: Fixed */
#define MSI_DATA_DELMODE_LOPRI		0x1U	/* Delivery Mode: Low Priority */
#define MSI_DATA_TRGRMODE_EDGE		0x0U	/* Trigger Mode: Edge */
#define MSI_DATA_TRGRMODE_LEVEL		0x1U	/* Trigger Mode: Level */

union msi_data_reg {
	uint32_t full;
	struct {
		uint32_t vector:8;
		uint32_t delivery_mode:3;
		uint32_t rsvd_1:3;
		uint32_t level:1;
		uint32_t trigger_mode:1;
		uint32_t rsvd_2:16;
	} bits __packed;
};

struct msi_info {
	union msi_addr_reg addr;
	union msi_data_reg data;
};

struct ptirq_remapping_info {
	uint32_t intr_type;
	union source_id phys_sid;
	union source_id virt_sid;
	uint32_t polarity; /* 0=active high, 1=active low*/
	struct msi_info vmsi;
	struct msi_info pmsi;
	uint16_t irte_idx;

	struct hlist_node phys_link;
	struct hlist_node virt_link;

	void (*release_cb)(const struct ptirq_remapping_info *);
};

struct acrn_vm;

/**
 * @file assign.h
 *
 * @brief public APIs for Passthrough Interrupt Remapping
 */

/**
 * @brief VT-d
 *
 * @defgroup acrn_passthrough ACRN Passthrough
 * @{
 */

/**
 * @brief Acknowledge a virtual interrupt for passthrough device.
 *
 * Acknowledge a virtual legacy interrupt for a passthrough device.
 *
 * @param[in] vm pointer to acrn_vm
 * @param[in] virt_gsi virtual GSI number associated with the passthrough device
 * @param[in] vgsi_ctlr INTX_CTLR_IOAPIC or INTX_CTLR_PIC
 *
 * @return None
 *
 * @pre vm != NULL
 *
 */
void ptirq_intx_ack(struct acrn_vm *vm, uint32_t virt_gsi, enum intx_ctlr vgsi_ctlr);

/**
 * @brief MSI/MSI-x remapping for passthrough device.
 *
 * Main entry for PCI device assignment with MSI and MSI-X.
 * MSI can up to 8 vectors and MSI-X can up to 1024 Vectors.
 *
 * @param[in] vm pointer to acrn_vm
 * @param[in] virt_bdf virtual bdf associated with the passthrough device
 * @param[in] phys_bdf virtual bdf associated with the passthrough device
 * @param[in] entry_nr indicate coming vectors, entry_nr = 0 means first vector
 * @param[in] info structure used for MSI/MSI-x remapping
 * @param[in] irte_idx caller can pass a valid IRTE index, otherwise, use INVALID_IRTE_ID
 *
 * @return
 *    - 0: on success
 *    - \p -ENODEV:
 *      - for SOS, the entry already be held by others
 *      - for UOS, no pre-hold mapping found.
 *
 * @pre vm != NULL
 * @pre info != NULL
 *
 */
int32_t ptirq_prepare_msix_remap(struct acrn_vm *vm, uint16_t virt_bdf,  uint16_t phys_bdf,
				uint16_t entry_nr, struct msi_info *info, uint16_t irte_idx);


/**
 * @brief INTx remapping for passthrough device.
 *
 * Set up the remapping of the given virtual pin for the given vm.
 * This is the main entry for PCI/Legacy device assignment with INTx, calling from vIOAPIC or vPIC.
 *
 * @param[in] vm pointer to acrn_vm
 * @param[in] virt_gsi virtual GSI number associated with the passthrough device
 * @param[in] vgsi_ctlr INTX_CTLR_IOAPIC or INTX_CTLR_PIC
 *
 * @return
 *    - 0: on success
 *    - \p -ENODEV:
 *      - for SOS, the entry already be held by others
 *      - for UOS, no pre-hold mapping found.
 *
 * @pre vm != NULL
 *
 */
int32_t ptirq_intx_pin_remap(struct acrn_vm *vm, uint32_t virt_gsi, enum intx_ctlr vgsi_ctlr);

/**
 * @brief Add an interrupt remapping entry for INTx as pre-hold mapping.
 *
 * Except sos_vm, Device Model should call this function to pre-hold ptdev intx
 * The entry is identified by phys_pin, one entry vs. one phys_pin.
 * Currently, one phys_pin can only be held by one pin source (vPIC or vIOAPIC).
 *
 * @param[in] vm pointer to acrn_vm
 * @param[in] virt_gsi virtual pin number associated with the passthrough device
 * @param[in] phys_gsi physical pin number associated with the passthrough device
 * @param[in] pic_pin true for pic, false for ioapic
 *
 * @return
 *    - 0: on success
 *    - \p -EINVAL: invalid virt_pin value
 *    - \p -ENODEV: failed to add the remapping entry
 *
 * @pre vm != NULL
 *
 */
int32_t ptirq_add_intx_remapping(struct acrn_vm *vm, uint32_t virt_gsi, uint32_t phys_gsi, bool pic_pin);

/**
 * @brief Remove an interrupt remapping entry for INTx.
 *
 * Deactivate & remove mapping entry of the given virt_pin for given vm.
 *
 * @param[in] vm pointer to acrn_vm
 * @param[in] virt_gsi virtual pin number associated with the passthrough device
 * @param[in] pic_pin true for pic, false for ioapic
 *
 * @return None
 *
 * @pre vm != NULL
 *
 */
void ptirq_remove_intx_remapping(const struct acrn_vm *vm, uint32_t virt_gsi, bool pic_pin);

/**
 * @brief Remove interrupt remapping entry/entries for MSI/MSI-x.
 *
 * Remove the mapping of given number of vectors of the given virtual BDF for the given vm.
 *
 * @param[in] vm pointer to acrn_vm
 * @param[in] phys_bdf physical bdf associated with the passthrough device
 * @param[in] vector_count number of vectors
 *
 * @return None
 *
 * @pre vm != NULL
 *
 */
void ptirq_remove_msix_remapping(const struct acrn_vm *vm, uint16_t phys_bdf, uint32_t vector_count);

/**
 * @brief Remove all interrupt remappings for INTx which are defined in VM config.
 *
 * Deactivate & remove all mapping entries of the virt_gsis defined in VM config for given vm.
 *
 * @param[in] vm pointer to acrn_vm
 *
 * @return None
 *
 * @pre vm != NULL
 *
 */
void ptirq_remove_configured_intx_remappings(const struct acrn_vm *vm);

/**
  * @}
  */

/* Interface to ptdev */
void initialize_ptirq_remapping_info(struct ptirq_remapping_info *info, uint32_t intr_type);
void ptirq_release_remapping_info(struct ptirq_remapping_info *info);
void ptirq_activate_remapping_info(struct ptirq_remapping_info *info);
void ptirq_deactivate_remapping_info(struct ptirq_remapping_info *info);

#endif /* ASSIGN_H */
