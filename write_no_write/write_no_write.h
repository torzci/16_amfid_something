#ifndef write_no_write_h
#define write_no_write_h

#include <stdio.h>
#include <mach/mach.h>

// missing prototypes:

kern_return_t mach_vm_allocate
 (
  vm_map_t target,
  mach_vm_address_t *address,
  mach_vm_size_t size,
  int flags
  );

kern_return_t mach_vm_deallocate
 (
  vm_map_t target,
  mach_vm_address_t address,
  mach_vm_size_t size
  );

kern_return_t mach_vm_read_overwrite
 (
  vm_map_read_t target_task,
  mach_vm_address_t address,
  mach_vm_size_t size,
  mach_vm_address_t data,
  mach_vm_size_t *outsize
  );

kern_return_t mach_vm_map
 (
  vm_map_t target_task,
  mach_vm_address_t *address,
  mach_vm_size_t size,
  mach_vm_offset_t mask,
  int flags,
  mem_entry_name_port_t object,
  memory_object_offset_t offset,
  boolean_t copy,
  vm_prot_t cur_protection,
  vm_prot_t max_protection,
  vm_inherit_t inheritance
  );

kern_return_t mach_vm_protect
(
        vm_map_t target_task,
        mach_vm_address_t address,
        mach_vm_size_t size,
        boolean_t set_maximum,
        vm_prot_t new_protection
);

void replace_file_page(char* target_path, uint32_t target_offset, uint8_t* new_page_contents);

#endif /* write_no_write_h */
