#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "elf_helper.h"
#include "self_helper.h"
#include "sbl_helper.h"

#define PAGE_SIZE 0x4000

typedef uint64_t vm_offset_t;

extern void* M_TEMP PAYLOAD_DATA;
extern void* (*real_malloc)(unsigned long size, void* type, int flags) PAYLOAD_DATA;
extern void (*real_free)(void* addr, void* type) PAYLOAD_DATA;

extern void (*real_dealloc)(void*) PAYLOAD_DATA;
extern void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_DATA;
extern void (*real_printf)(const char* fmt, ...) PAYLOAD_DATA;

extern int (*real_sceSblServiceMailbox)(unsigned long service_id, uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE], void* response) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrGetSelfInfo)(struct self_context* ctx, struct self_ex_info** info) PAYLOAD_DATA;
extern void (*real_sceSblAuthMgrSmStart)(void**) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrIsLoadable2)(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_DATA;
extern int (*real_sceSblAuthMgrVerifyHeader)(struct self_context* ctx) PAYLOAD_DATA;

const struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_DATA;
const uint8_t* mini_syscore_self_binary PAYLOAD_DATA;

PAYLOAD_CODE static inline void* alloc(uint32_t size)
{
  return real_malloc(size, M_TEMP, 2);
}

PAYLOAD_CODE static inline void dealloc(void* addr)
{
  real_free(addr, M_TEMP);
}

PAYLOAD_CODE static inline const struct sbl_map_list_entry* sceSblDriverFindMappedPageListByGpuVa(vm_offset_t gpu_va)
{
  const struct sbl_map_list_entry* entry;
  if (!gpu_va)
  {
    return NULL;
  }
  entry = *sbl_driver_mapped_pages;
  while (entry)
  {
    if (entry->gpu_va == gpu_va)
    {
      return entry;
    }
    entry = entry->next;
  }
  return NULL;
}

PAYLOAD_CODE static inline vm_offset_t sceSblDriverGpuVaToCpuVa(vm_offset_t gpu_va, size_t* num_page_groups)
{
  const struct sbl_map_list_entry* entry = sceSblDriverFindMappedPageListByGpuVa(gpu_va);
  if (!entry)
  {
    return 0;
  }
  if (num_page_groups)
  {
    *num_page_groups = entry->num_page_groups;
  }
  return entry->cpu_va;
}

PAYLOAD_CODE static inline int sceSblAuthMgrGetSelfAuthInfoFake(struct self_context* ctx, struct self_auth_info* info)
{
  struct self_header* hdr;
  struct self_fake_auth_info* fake_info;

  if (ctx->format == SELF_FORMAT_SELF)
  {
    hdr = (struct self_header*)ctx->header;
    fake_info = (struct self_fake_auth_info*)(ctx->header + hdr->header_size + hdr->meta_size - 0x100);
    if (fake_info->size == sizeof(fake_info->info))
    {
      real_memcpy(info, &fake_info->info, sizeof(*info));
      return 0;
    }
    return -37;
  }
  else
  {
    return -35;
  }
}

PAYLOAD_CODE static inline int is_fake_self(struct self_context* ctx)
{
  struct self_ex_info* ex_info;
  if (ctx && ctx->format == SELF_FORMAT_SELF)
  {
    if (real_sceSblAuthMgrGetSelfInfo(ctx, &ex_info))
    {
      return 0;
    }
    return ex_info->ptype == SELF_PTYPE_FAKE;
  }
  return 0;
}

PAYLOAD_CODE static inline int sceSblAuthMgrGetElfHeader(struct self_context* ctx, struct elf64_ehdr** ehdr)
{

  struct self_header* self_hdr;
  struct elf64_ehdr* elf_hdr;
  size_t pdata_size;

  if (ctx->format == SELF_FORMAT_ELF)
  {
    elf_hdr = (struct elf64_ehdr*)ctx->header;
    if (ehdr)
    {
      *ehdr = elf_hdr;
    }
    return 0;
  }
  else if (ctx->format == SELF_FORMAT_SELF)
  {
    self_hdr = (struct self_header*)ctx->header;
    pdata_size = self_hdr->header_size - sizeof(struct self_entry) * self_hdr->num_entries - sizeof(struct self_header);
    if (pdata_size >= sizeof(struct elf64_ehdr) && (pdata_size & 0xF) == 0)
    {
      elf_hdr = (struct elf64_ehdr*)((uint8_t*)self_hdr + sizeof(struct self_header) + sizeof(struct self_entry) * self_hdr->num_entries);
      if (ehdr)
      {
        *ehdr = elf_hdr;
      }
      return 0;
    }
    return -37;
  }
  return -35;
}


static const uint8_t s_auth_info_for_exec[] PAYLOAD_RDATA =
{
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0x00, 0x20,
  0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
  0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t s_auth_info_for_dynlib[] PAYLOAD_RDATA =
{
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x00, 0x30,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
  0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};





PAYLOAD_CODE static int build_self_auth_info_fake(struct self_context* ctx, struct self_auth_info* parent_auth_info, struct self_auth_info* auth_info)
{

  struct self_auth_info fake_auth_info;
  struct self_ex_info* ex_info;
  struct elf64_ehdr* ehdr = NULL;
  int result;

  if (!ctx || !parent_auth_info || !auth_info)
  {
    result = EINVAL;
    goto error;
  }

  if (!is_fake_self(ctx))
  {
    result = EINVAL;
    goto error;
  }

  result = real_sceSblAuthMgrGetSelfInfo(ctx, &ex_info);
  if (result)
  {
    goto error;
  }

  result = sceSblAuthMgrGetElfHeader(ctx, &ehdr);
  if (result)
  {
    goto error;
  }

  if (!ehdr)
  {
    result = ESRCH;
    goto error;
  }

  result = sceSblAuthMgrGetSelfAuthInfoFake(ctx, &fake_auth_info);
  if (result)
  {
    switch (ehdr->type)
    {
      case ELF_ET_EXEC:
      case ELF_ET_SCE_EXEC:
      case ELF_ET_SCE_EXEC_ASLR:
      {
        real_memcpy(&fake_auth_info, s_auth_info_for_exec, sizeof(fake_auth_info));
        result = 0;
        break;
      }

      case ELF_ET_SCE_DYNAMIC:
      {
        real_memcpy(&fake_auth_info, s_auth_info_for_dynlib, sizeof(fake_auth_info));
        result = 0;
        break;
      }

      default:
      {
        result = ENOTSUP;
        goto error;
      }
    }

    fake_auth_info.paid = ex_info->paid;

    // TODO: overwrite low bits of PAID with title id number
  }

  if (auth_info)
  {
    real_memcpy(auth_info, &fake_auth_info, sizeof(*auth_info));
  }

error:
  return result;
}

PAYLOAD_CODE int my_sceSblAuthMgrIsLoadable2(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info)
{
	//real_printf("\nentered is loadable 2\n");

  if (ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx))
  {
	  //real_printf("\nfake self\n");
    return build_self_auth_info_fake(ctx, old_auth_info, new_auth_info);
  }
  else
  {
	  //real_printf("\nself\n");
    return real_sceSblAuthMgrIsLoadable2(ctx, old_auth_info, path_id, new_auth_info);
  }
}

static inline int auth_self_header(struct self_context* ctx)
{

  struct self_header* hdr;
  unsigned int old_total_header_size, new_total_header_size;
  int old_format;
  uint8_t* tmp;
  int is_unsigned;
  int result;

  is_unsigned = ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx);
  if (is_unsigned)
  {
    old_format = ctx->format;
    old_total_header_size = ctx->total_header_size;

    /* take a header from mini-syscore.elf */
    hdr = (struct self_header*)mini_syscore_self_binary;

    new_total_header_size = hdr->header_size + hdr->meta_size;

    tmp = (uint8_t*)alloc(new_total_header_size);
    if (!tmp)
    {
      result = ENOMEM;
      goto error;
    }

    /* temporarily swap an our header with a header from a real SELF file */
    real_memcpy(tmp, ctx->header, new_total_header_size);
    real_memcpy(ctx->header, hdr, new_total_header_size);

    /* it's now SELF, not ELF or whatever... */
    ctx->format = SELF_FORMAT_SELF;
    ctx->total_header_size = new_total_header_size;

    /* call the original method using a real SELF file */
    result = real_sceSblAuthMgrVerifyHeader(ctx);

    /* restore everything we did before */
    real_memcpy(ctx->header, tmp, new_total_header_size);
    ctx->format = old_format;
    ctx->total_header_size = old_total_header_size;

    dealloc(tmp);
  }
  else
  {
    result = real_sceSblAuthMgrVerifyHeader(ctx);
  }

error:
  return result;
}

PAYLOAD_CODE int my_sceSblAuthMgrVerifyHeader(struct self_context* ctx)
{
	//real_printf("\nverifying header\n");
  void* dummy;
  real_sceSblAuthMgrSmStart(&dummy);
  return auth_self_header(ctx);
}

PAYLOAD_CODE int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response)
{
  /* getting a stack frame of a parent function */
  //real_printf("\ngetting a stack frame of a parent function\n");
  uint8_t* frame = (uint8_t*)__builtin_frame_address(1);
  /* finding a pointer to a context's structure */
  //real_printf("\nfinding a pointer to a context's structure\n");
  struct self_context* ctx = *(struct self_context**)(frame - 0x100);//4.74
  int is_unsigned = ctx && is_fake_self(ctx);
  if (is_unsigned)
  {
	  //real_printf("\nsetting error field to zero, thus we have no errors\n");
    *(int*)(response + 0x04) = 0; /* setting error field to zero, thus we have no errors */
    return 0;
  }else{
	  //real_printf("\nnot unsigned\n");
  }
  return real_sceSblServiceMailbox(service_id, request, response);
}

PAYLOAD_CODE int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response)
{

  //real_printf("\nentered my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox\n");

  struct self_context* ctx;
  register struct self_context* ctx_reg __asm__("r14");
  vm_offset_t segment_data_gpu_va = *(unsigned long*)(request + 0x08);
  vm_offset_t cur_data_gpu_va = *(unsigned long*)(request + 0x50);
  vm_offset_t cur_data2_gpu_va = *(unsigned long*)(request + 0x58);
  unsigned int data_offset = *(unsigned int*)(request + 0x44);
  unsigned int data_size = *(unsigned int*)(request + 0x48);
  vm_offset_t segment_data_cpu_va, cur_data_cpu_va, cur_data2_cpu_va;
  unsigned int size1;

  ctx = ctx_reg;

  int is_unsigned = ctx && (ctx->format == SELF_FORMAT_ELF || is_fake_self(ctx));
  int result;

  if (is_unsigned)
  {
    /* looking into lists of GPU's mapped memory regions */
	//real_printf("\nlooking into lists of GPU's mapped memory regions\n");
    segment_data_cpu_va = sceSblDriverGpuVaToCpuVa(segment_data_gpu_va, NULL);
    cur_data_cpu_va = sceSblDriverGpuVaToCpuVa(cur_data_gpu_va, NULL);
    cur_data2_cpu_va = cur_data2_gpu_va ? sceSblDriverGpuVaToCpuVa(cur_data2_gpu_va, NULL) : 0;

    if (segment_data_cpu_va && cur_data_cpu_va)
    {
      if (cur_data2_gpu_va && cur_data2_gpu_va != cur_data_gpu_va && data_offset > 0)
      {
        /* data spans two consecutive memory's pages, so we need to copy twice */
		//real_printf("\ndata spans two consecutive memory's pages, so we need to copy twice\n");
        size1 = PAGE_SIZE - data_offset;
        real_memcpy((char*)segment_data_cpu_va, (char*)cur_data_cpu_va + data_offset, size1);
        real_memcpy((char*)segment_data_cpu_va + size1, (char*)cur_data2_cpu_va, data_size - size1);
      }
      else
      {
		  //real_printf("\nmemcpying!\n");
        real_memcpy((char*)segment_data_cpu_va, (char*)cur_data_cpu_va + data_offset, data_size);
      }
    }
    //real_printf("\n setting error field to zero, thus we have no errors \n");
    *(int*)(request + 0x04) = 0; /* setting error field to zero, thus we have no errors */
    result = 0;
  }
  else
  {
	  //real_printf("\n real_sceSblServiceMailbox \n");
    result = real_sceSblServiceMailbox(service_id, request, response);
  }

  return result;
}

