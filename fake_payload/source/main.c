#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "elf_helper.h"
#include "self_helper.h"
#include "sbl_helper.h"
#include "pfs_helper.h"
#include "rif_helper.h"
#include "ccp_helper.h"
#include "amd_helper.h"

typedef uint64_t vm_offset_t;

// real kernel hooks
void* M_TEMP PAYLOAD_DATA;
void* (*real_malloc)(unsigned long size, void* type, int flags) PAYLOAD_DATA;
void (*real_free)(void* addr, void* type) PAYLOAD_DATA;
void (*real_dealloc)(void*) PAYLOAD_DATA;
void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_DATA;
void (*real_printf)(const char* fmt, ...) PAYLOAD_DATA;
int (*real_sceSblServiceMailbox)(unsigned long service_id, uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE], void* response) PAYLOAD_DATA;
int (*real_sceSblAuthMgrGetSelfInfo)(struct self_context* ctx, struct self_ex_info** info) PAYLOAD_DATA;
void (*real_sceSblAuthMgrSmStart)(void**) PAYLOAD_DATA;
int (*real_sceSblAuthMgrIsLoadable2)(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_DATA;
int (*real_sceSblAuthMgrVerifyHeader)(struct self_context* ctx) PAYLOAD_DATA;
int (*real_fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx, uint32_t flags) PAYLOAD_DATA;
int (*real_fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_DATA;
void (*real_Sha256Hmac)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size) PAYLOAD_DATA;
int (*real_AesCbcCfb128Decrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_DATA;
int (*real_RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer* out, struct rsa_buffer* in, struct rsa_key* key) PAYLOAD_DATA;
int (*real_sceSblPfsSetKey)(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_DATA;
int (*real_sceSblServiceCryptAsync)(struct ccp_req* request) PAYLOAD_DATA;
int (*real_sceSblKeymgrSmCallfunc)(union keymgr_payload* payload) PAYLOAD_DATA;
int (*real_sx_xlock)(struct sx *sx, int opts) PAYLOAD_DATA;
int (*real_sx_xunlock)(struct sx *sx) PAYLOAD_DATA;
void* (*real_memcmp)(const void *b1, const void *b2, size_t len) PAYLOAD_DATA;
void* (*real_memset)(void *s, int c, size_t n) PAYLOAD_DATA;
void* (*real_eventhandler_register)(void* list, const char* name, void* func, void* arg, int priority) PAYLOAD_DATA;
void  (*real_sx_destroy)(struct sx *sx) PAYLOAD_DATA;
void  (*real_sx_init_flags)(struct sx *sx, const char *description, int opts) PAYLOAD_DATA;
int (*sceSblPfsKeymgrGenKeys)(union pfs_key_blob* key_blob) PAYLOAD_DATA;
int (*sceSblPfsSetKeys)(uint32_t* ekh, uint32_t* skh, uint8_t* eekpfs, struct ekc* eekc, unsigned int pubkey_ver, unsigned int key_ver, struct pfs_header* hdr, size_t hdr_size, unsigned int type, unsigned int finalized, unsigned int is_disc) PAYLOAD_DATA;
int (*sceSblKeymgrClearKey)(uint32_t kh) PAYLOAD_DATA;
int (*sceSblKeymgrSetKeyForPfs)(union sbl_key_desc* key, unsigned int* handle) PAYLOAD_DATA;
int (*sceSblDriverSendMsg)(struct sbl_msg* msg, size_t size) PAYLOAD_DATA;
int (*AesCbcCfb128Encrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_DATA;

// our hooks
extern int my_sceSblAuthMgrIsLoadable2(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_CODE;
extern int my_sceSblAuthMgrVerifyHeader(struct self_context* ctx) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblPfsSetKey_pfs_sbl_init(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_CODE;
extern int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg(struct sbl_msg* msg, size_t size) PAYLOAD_CODE;
extern int my_mountpfs__sceSblPfsSetKeys(uint32_t* ekh, uint32_t* skh, uint8_t* eekpfs, struct ekc* eekc, unsigned int pubkey_ver, unsigned int key_ver, struct pfs_header* hdr, size_t hdr_size, unsigned int type, unsigned int finalized, unsigned int is_disc) PAYLOAD_CODE;

int (*npdrm_decrypt_rif_new)( int integer, struct rif_key_blob* key_blob, struct rif* rif) PAYLOAD_DATA;

extern const struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_DATA; 
extern const uint8_t* mini_syscore_self_binary PAYLOAD_DATA;
extern const struct sbl_key_rbtree_entry** sbl_keymgr_key_rbtree PAYLOAD_DATA;
void* fpu_ctx PAYLOAD_DATA;
struct sx* sbl_pfs_sx PAYLOAD_DATA;

extern struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS] PAYLOAD_DATA;
extern struct sx s_fake_keys_lock PAYLOAD_DATA;

/*static void debug_pfs_cleanup(void* arg) PAYLOAD_CODE;

static void debug_pfs_cleanup(void* arg) {
	real_sx_destroy(&s_fake_keys_lock);
}*/

PAYLOAD_CODE void my_entrypoint()
{

}

struct real_info
{
  const size_t kernel_offset;
  const void* payload_target;
};

struct cave_info
{
  const size_t kernel_call_offset;
  const size_t kernel_ptr_offset;
  const void* payload_target;
};

struct disp_info
{
  const size_t call_offset;
  const size_t cave_offset;
};

struct real_info real_infos[] PAYLOAD_DATA =
{
  { 0x3F85C0, &real_malloc },
  { 0x3F87A0, &real_free },
  { 0x149D40, &real_memcpy },
  { 0x017F30, &real_printf },
  { 0x244EE0, &real_memcmp },
  { 0x304DD0, &real_memset },
  
  
  { 0x617AB0, &real_sceSblServiceMailbox },
  { 0x629040, &real_sceSblAuthMgrIsLoadable2 },
  { 0x626640, &real_sceSblAuthMgrVerifyHeader },
  { 0x629880, &real_sceSblAuthMgrGetSelfInfo },
  { 0x625410, &real_sceSblAuthMgrSmStart },//
  { 0x199BB80, &M_TEMP },
  { 0x1479558, &mini_syscore_self_binary },
  { 0x2525DD0, &sbl_driver_mapped_pages },
  { 0x2528CC0, &fpu_ctx },
  { 0x2529310, &sbl_pfs_sx },
 
  
   
  { 0x390850, &real_sx_xlock },
  { 0x3909E0, &real_sx_xunlock },
  { 0x2D7E00, &real_Sha256Hmac },
  { 0x179950, &real_AesCbcCfb128Decrypt },
  { 0x390790, &real_sx_destroy },
  
  { 0x60F3E0, &real_sceSblServiceCryptAsync },
  { 0x617AB0, &real_sceSblServiceMailbox },
  { 0x058B60, &real_fpu_kern_enter },
  { 0x058C60, &real_fpu_kern_leave },
  { 0x390720, &real_sx_init_flags },
  { 0x3CA6A0, &real_eventhandler_register },
  
  { 0x610BB0, &real_sceSblPfsSetKey },
  { 0x611530, &real_sceSblKeymgrSmCallfunc },
  { 0x6106E0, &sceSblPfsKeymgrGenKeys },
  { 0x6095E0, &sceSblPfsSetKeys },
  { 0x610D80, &sceSblKeymgrClearKey },
  { 0x6109E0, &sceSblKeymgrSetKeyForPfs},
  { 0x603CA0, &sceSblDriverSendMsg},
  { 0x179720, &AesCbcCfb128Encrypt},
  { 0x3F0070, &real_RsaesPkcs1v15Dec2048CRT },

  { 0, NULL },
};

#define ADJACENT(x) \
  x, x + 6
struct cave_info cave_infos[] PAYLOAD_DATA =
{
  { ADJACENT(0x9700), &my_sceSblAuthMgrIsLoadable2 },
  { ADJACENT(0x1E420), &my_sceSblAuthMgrVerifyHeader },
  { ADJACENT(0x21730), &my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox },
  { ADJACENT(0x22CE0), &my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox },
  
    // Fpkg hooks
  { ADJACENT(0x24B70), &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif },
  { ADJACENT(0x2D1D0), &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new },
  { ADJACENT(0x30920), &my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg },
  { ADJACENT(0x3F4B0), &my_mountpfs__sceSblPfsSetKeys },
  
  { 0, 0, NULL },
};
#undef ADJACENT

struct disp_info disp_infos[] PAYLOAD_DATA =
{
  { 0x62263F, 0x9700  }, // my_sceSblAuthMgrIsLoadable2
  { 0x622D66, 0x1E420 }, // my_sceSblAuthMgrVerifyHeader
  { 0x623989, 0x1E420 }, // my_sceSblAuthMgrVerifyHeader
  { 0x626CAA, 0x21730 }, // my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox
  { 0x6278D1, 0x22CE0 }, // my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox
  
   // Fpkg 
  { 0x6312F0, 0x24B70 },// my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif

  { 0x6320CE, 0x2D1D0 },// my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new

  { 0x609475, 0x30920 },//my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg 
  { 0x6094D3, 0x30920 },//my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg

  { 0x69AFE4, 0x3F4B0 },//my_mountpfs__sceSblPfsSetKeys
  { 0x69B214, 0x3F4B0 },//my_mountpfs__sceSblPfsSetKeys
  
  { 0, 0 },
};

struct
{
  uint64_t signature;
  struct real_info* real_infos;
  struct cave_info* cave_infos;
  struct disp_info* disp_infos;
  void* entrypoint;
}
payload_header PAYLOAD_HEADER =
{
  0x5041594C4F414433ull,
  real_infos,
  cave_infos,
  disp_infos,
  &my_entrypoint,
};

// dummies -- not included in output payload binary

void PAYLOAD_DUMMY dummy()
{
  dummy();
}

int _start()
{
  return 0;
}
