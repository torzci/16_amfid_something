#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/vm_page_size.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/fixup-chains.h>

void fail(char* file, int line) {
  printf("check failed in %s on line %d\n", file, line);
  perror("");
  exit(EXIT_FAILURE);
}

#define check(cond) do { \
  if (!(cond)) { \
    fail(__FILE__, __LINE__); \
  } \
} while(0)

/*
 * map it at a 16k boundary to maintain sanity when parsing these files on my intel dev machine...
 */


uint64_t fixup_trunc_page(uint64_t ptr, uint64_t page_size) {
  return ptr & (~(page_size - 1));
}

uint64_t fixup_round_page(uint64_t ptr, uint64_t page_size) {
  return fixup_trunc_page((ptr + (page_size - 1)), page_size);
}

void* map_file(char* path, size_t* size_out) {
  struct stat st = {0};
  int err = stat(path, &st);
  check(err == 0);

  int fd = open(path, O_RDONLY);
  check(fd >= 0);

  mach_vm_size_t overallocate_size = st.st_size + 0x8000;
  mach_vm_address_t addr = 0;
  kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, overallocate_size, VM_FLAGS_ANYWHERE);
  check(kr == KERN_SUCCESS);

  uint64_t fixed_base = fixup_round_page(addr, 0x4000);

  void* base = mmap((void*)fixed_base, round_page(st.st_size), PROT_READ, MAP_FILE | MAP_PRIVATE | MAP_FIXED, fd, 0);
  check(base != NULL);
  check(base == (void*)fixed_base);

  *size_out = st.st_size;
  return base;
}

// need to know libraries first
// they're in two sets of load commands:
// LC_LOAD_WEAK_DYLIB and LC_LOAD_DYLIB
// (also I guess LC_REEXPORT_DYLIB; do any targets use those?)

char** libs = NULL;
uint32_t n_libs = 0;


#define consume(type, var) \
  type* var = (type*) ptr; \
  if (remaining < (sizeof(type))) {\
    check(0); \
  }\
  remaining -= sizeof(type); \
  ptr += sizeof(type);

#define consume_cmd(var)\
  if (remaining < sizeof(struct load_command)) {\
    check(0); \
  } \
  if (remaining < ((struct load_command*)ptr)->cmdsize) { \
    check(0); \
  } \
  var = (typeof(var))ptr; \
  ptr += ((struct load_command*)ptr)->cmdsize;

/*
 * There are 4 types of arm64e chain pointers, differentiated by their 2 upper bits.
 */



void walk_fixup_chain(uint8_t* macho, size_t chain_start_offset, size_t page_size) {
  // this technically depends on the starts_in_segment.pointer_format and can be 1, 4, or 8
  // but for arm64e userspace it's always 8
  uint32_t stride = 8;
  uint8_t* ptr = macho + chain_start_offset;
  uint64_t start_page = fixup_trunc_page((uint64_t)ptr, page_size);

  while (1) {
    struct dyld_chained_ptr_arm64e_rebase* p = (struct dyld_chained_ptr_arm64e_rebase*)ptr;
    int auth = p->auth;
    int bind = p->bind;

    uint32_t next = 0;

    uint64_t vmaddr = ptr - macho;

    if (!auth && !bind) {
      struct dyld_chained_ptr_arm64e_rebase* rb = (struct dyld_chained_ptr_arm64e_rebase*)ptr;
      next = rb->next;
      printf("      0x%llx : 0x%016llx <rebase> target: 0x%llx next: 0x%x\n", vmaddr, *((uint64_t*)ptr), rb->target, rb->next);
    } else if (bind && !auth) {
      struct dyld_chained_ptr_arm64e_bind24* b = (struct dyld_chained_ptr_arm64e_bind24*)ptr;
      next = b->next;
      printf("      0x%llx : 0x%016llx <bind> ordinal: 0x%x addend: 0x%x next: 0x%x\n", vmaddr, *((uint64_t*)ptr), b->ordinal, b->addend, b->next);
    } else if (!bind && auth) {
      struct dyld_chained_ptr_arm64e_auth_rebase* arb = (struct dyld_chained_ptr_arm64e_auth_rebase*)ptr;
      next = arb->next;
      printf("      0x%llx : 0x%016llx <auth+rebase> target: 0x%x diversity: 0x%x addrDiv: %d key:%d next: 0x%x\n", vmaddr, *((uint64_t*)ptr), arb->target, arb->diversity, arb->addrDiv, arb->key, arb->next);
    } else if (bind && auth) {
      struct dyld_chained_ptr_arm64e_auth_bind24* ab = (struct dyld_chained_ptr_arm64e_auth_bind24*)ptr;
      next = ab->next;
      printf("      0x%llx : 0x%016llx <auth+bind> ordinal: 0x%x diversity: 0x%x addrDiv: %d key:%d next: 0x%x\n", vmaddr, *((uint64_t*)ptr), ab->ordinal, ab->diversity, ab->addrDiv, ab->key, ab->next);
    } else {
      check(0);
    }
    if (next == 0) {
      break;
    }
    ptr += (next*stride);
    check(fixup_trunc_page((uint64_t)ptr, page_size) == start_page);
  }
}

void parse_fixups_linkedit(uint8_t* macho, uint8_t* base, size_t size) {
  uint8_t* ptr = base;
  size_t remaining = size;

  consume(struct dyld_chained_fixups_header, hdr);
  printf("fixups_version: %d\n", hdr->fixups_version);  
  printf("starts_offset: %d\n", hdr->starts_offset);
  printf("imports_offset: %d\n", hdr->imports_offset);
  printf("symbols_offset: %d\n", hdr->symbols_offset);
  printf("imports_count: %d\n", hdr->imports_count);
  printf("imports_format: %d\n", hdr->imports_format);
  printf("symbols_format: %d\n", hdr->symbols_format);

  check(hdr->fixups_version == 0);

  check(hdr->symbols_format == 0); // 0 == uncompressed

  // the symbols are null-terminated so actually bounds checking them is more tedious than this
  check(hdr->symbols_offset <= size);
  char* syms = (char*)(base + hdr->symbols_offset);

  /* imports */
  printf("import format: %d\n", hdr->imports_format);
  uint32_t import_link_size = 0;
  switch (hdr->imports_format) {
    case DYLD_CHAINED_IMPORT:
      import_link_size = sizeof(struct dyld_chained_import);
      break;
    case DYLD_CHAINED_IMPORT_ADDEND:
      import_link_size = sizeof(struct dyld_chained_import_addend);
      break;
    case DYLD_CHAINED_IMPORT_ADDEND64:
      import_link_size = sizeof(struct dyld_chained_import_addend64);
      break;
    default:
      check(0);
  }

  check(hdr->imports_offset + (import_link_size * hdr->imports_count) <= size);
  struct dyld_chained_import_addend64* imps = (struct dyld_chained_import_addend64*)(base + hdr->imports_offset);
  for (int i = 0; i < hdr->imports_count; i++) {
    int16_t lib_ordinal = 0; // there are three special value (-1, -2, -3)
    uint32_t weak_import = 0;
    uint32_t name_offset = 0;
    uint64_t addend = 0;

    switch (hdr->imports_format) {
      case DYLD_CHAINED_IMPORT:
      {
        struct dyld_chained_import* imps = (struct dyld_chained_import*)(base + hdr->imports_offset);
        lib_ordinal = (int8_t)imps[i].lib_ordinal; // sign extend
        weak_import = imps[i].weak_import;
        name_offset = imps[i].name_offset;
        addend = 0;
        break;
      }
      case DYLD_CHAINED_IMPORT_ADDEND:
      {
        import_link_size = sizeof(struct dyld_chained_import_addend);
        struct dyld_chained_import_addend* imps = (struct dyld_chained_import_addend*)(base + hdr->imports_offset);
        lib_ordinal = (int8_t)imps[i].lib_ordinal; // sign extend
        weak_import = imps[i].weak_import;
        name_offset = imps[i].name_offset;
        addend = imps[i].addend; // the type here is actually int32 - is that important?
        check(addend < INT_MAX);
        break;
      }
      case DYLD_CHAINED_IMPORT_ADDEND64:
      {
        struct dyld_chained_import_addend64* imps = (struct dyld_chained_import_addend64*)(base + hdr->imports_offset);
        lib_ordinal = (int16_t)imps[i].lib_ordinal;
        weak_import = imps[i].weak_import;
        name_offset = imps[i].name_offset;
        addend = imps[i].addend; // the type here is actually int32 - is that important?
        break;
      }
      default:
        check(0);
    }

    // not bounds checked...
    char* name = &syms[name_offset];
    char* lib_name = "<UNK>";
    switch(lib_ordinal) {
      case BIND_SPECIAL_DYLIB_SELF: // 0
      {
        lib_name = "<bind_special_self>";
        break;
      }
      case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: // -1
      {
        lib_name = "<bind_special_main_executable>";
        break;
      }
      case BIND_SPECIAL_DYLIB_FLAT_LOOKUP: // -2
      {
        lib_name = "<bind_special_dylib_flat_lookup>";
        break;
      }
      case BIND_SPECIAL_DYLIB_WEAK_LOOKUP: // -3
      {
        lib_name = "<bind_special_dylib_weak_lookup>";
        break;
      }
      default:
      {
        uint32_t import_table_offset = lib_ordinal - 1;
        printf("import_table_offset: %d\n", import_table_offset);
        check(import_table_offset < n_libs);
        lib_name = libs[import_table_offset];
        break;
      }
    } 
    printf("  import ordinal 0x%04x: lib_ordinal: 0x%04x lib_path: %s weak: %d name_offset: 0x%x name: %s (sym file offset: 0x%lx) addend: %llx\n", i, lib_ordinal, lib_name, weak_import, name_offset, name, (uint8_t*)name - macho, addend);
  }

  /* fixup chains */
  check(hdr->starts_offset + sizeof(struct dyld_chained_starts_in_image) <= size);

  struct dyld_chained_starts_in_image* starts = (struct dyld_chained_starts_in_image*)(base + hdr->starts_offset);

  printf("start seg_count: %d\n", starts->seg_count);

  check(starts->seg_count > 0);
  check(hdr->starts_offset + sizeof(struct dyld_chained_starts_in_image) + ((starts->seg_count - 1) * sizeof(uint32_t)) <= size);

  for (int i = 0; i < starts->seg_count; i++) {
    // there's one of these per-segment; they're in segment order
    uint32_t info_offset = starts->seg_info_offset[i];
    if (info_offset > 0) {
      printf("segment %d : info_offset: %d\n", i, info_offset);
      
      check(hdr->starts_offset + info_offset + sizeof(struct dyld_chained_starts_in_segment) <= size);
      
      struct dyld_chained_starts_in_segment* seg_starts = (struct dyld_chained_starts_in_segment*)(base + hdr->starts_offset + info_offset);
      printf("  size: %d\n", seg_starts->size);
      printf("  page_size: 0x%x\n", seg_starts->page_size);
      printf("  pointer_format: %d\n", seg_starts->pointer_format);
      printf("  segment_offset: 0x%llx\n", seg_starts->segment_offset); // offset from the base load address
      printf("  max_valid_pointer: 0x%x\n", seg_starts->max_valid_pointer);
      printf("  page_count: %d\n", seg_starts->page_count);
    
      check(seg_starts->page_count > 0);
      check(hdr->starts_offset + info_offset + sizeof(struct dyld_chained_starts_in_segment) + ((seg_starts->page_count-1) * sizeof(uint16_t)) <= size);
      check(seg_starts->pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24);

      for (int j = 0; j < seg_starts->page_count; j++) {
        uint16_t page_start = seg_starts->page_start[j];
        printf("    page[%d] = %d\n", j, page_start);
        
        if (page_start == DYLD_CHAINED_PTR_START_NONE) {
          continue;
        }
        if (page_start == DYLD_CHAINED_PTR_START_MULTI) {
          printf("    encountered multi-start chain - what does that actually mean?\n");
          check(0);
        }

        // lost the context here of how big the macho is to be able to check the page bounds...
        walk_fixup_chain(macho, seg_starts->segment_offset + (seg_starts->page_size * j) + page_start, seg_starts->page_size);
      }
    }
  }
}


void collate_libraries(uint8_t* macho, size_t size) {
  uint8_t* ptr = macho;
  size_t remaining = size;

  consume(struct mach_header_64, hdr);
  check(hdr->magic == MH_MAGIC_64);

  uint32_t ncmds = hdr->ncmds;
  
  // each imported library gets its own lc so just overallocate ncmds:
  libs = calloc(ncmds, sizeof(char*));
  check(libs);
  
  for (uint32_t i = 0; i < ncmds; i++) {
    struct load_command* cmd;
    consume_cmd(cmd);
    check(cmd->cmd != LC_REEXPORT_DYLIB);
    check(cmd->cmd != LC_ID_DYLIB);
    if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB) {
      check(cmd->cmdsize >= sizeof(struct dylib_command));

      struct dylib_command* dc = (struct dylib_command*) cmd;
      check(dc->dylib.name.offset < cmd->cmdsize);
      char* name = (char*)(((uint8_t*)cmd) + dc->dylib.name.offset);
      printf("import ordinal: %d path: %s\n", n_libs, name);
      libs[n_libs++] = strdup(name);
    }
  }

}

void parse_fixups(uint8_t* macho, size_t size) {
  uint8_t* ptr = macho;
  size_t remaining = size;

  consume(struct mach_header_64, hdr);
  check(hdr->magic == MH_MAGIC_64);

  uint32_t ncmds = hdr->ncmds;
  
  for (uint32_t i = 0; i < ncmds; i++) {
    struct load_command* cmd;
    consume_cmd(cmd);
    if (cmd->cmd == LC_DYLD_CHAINED_FIXUPS) {
      printf("got chained fixups; size: %d\n", cmd->cmdsize);
      check(cmd->cmdsize == sizeof(struct linkedit_data_command));

      struct linkedit_data_command* lecmd = (struct linkedit_data_command*)cmd;
      check(lecmd->dataoff + lecmd->datasize <= size);
      parse_fixups_linkedit(macho, macho + lecmd->dataoff, lecmd->datasize);
    }
  }

}

void usage(int argc, char** argv) {
  char* filename = "<BINARY>";
  if (argc != 0) {
    filename = argv[0];
  }
  printf("%s <target>\n", filename);
  return;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    usage(argc, argv);
    exit(EXIT_SUCCESS);
  }

  char* target_path = argv[1];

  size_t target_size = 0;
  void* macho = map_file(target_path, &target_size);

  collate_libraries(macho, target_size);
  parse_fixups(macho, target_size);

  return 0;
}

