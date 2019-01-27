#ifndef __OFFSETS_H
#define __OFFSETS_H

// 4.74
#define	KERN_XFAST_SYSCALL		0x30B7D0    // 4.74 RIGHT

// data
#define M_TEMP_addr                     0x199BB80    // 4.74 RIGHT
#define fpu_ctx_addr                    0x2528CC0    // 4.74 RIGHT
#define mini_syscore_self_binary_addr   0x1479558    // 4.74 RIGHT
#define sbl_driver_mapped_pages_addr    0x2525DD0    // 4.74 RIGHT
#define sbl_pfs_sx_addr                 0x2529310    // 4.74 RIGHT
#define allproc_addr                    0x1ADF718    // 4.74 RIGHT

// common RIGHT
#define strlen_addr                     0x353720    // 4.74
#define malloc_addr                     0x3F85C0    // 4.74
#define free_addr                       0x3F87A0    // 4.74
#define memcpy_addr                     0x149D40    // 4.74
#define memset_addr                     0x304DD0    // 4.74
#define memcmp_addr                     0x244EE0    // 4.74
#define sx_xlock_addr                   0x390850    // 4.74
#define sx_xunlock_addr                 0x3909E0    // 4.74
#define fpu_kern_enter_addr             0x058B60    // 4.74
#define fpu_kern_leave_addr             0x058C60    // 4.74

// Fself RIGHT
#define sceSblAuthMgrSmStart_addr       0x625410    // 4.74
#define sceSblServiceMailbox_addr       0x617AB0    // 4.74
#define sceSblAuthMgrGetSelfInfo_addr   0x629880    // 4.74
#define sceSblAuthMgrIsLoadable2_addr   0x629040    // 4.74
#define sceSblAuthMgrVerifyHeader_addr  0x626640    // 4.74,fixed

// Fpkg
#define sceSblPfsKeymgrGenKeys_addr     0x6106E0    // 4.74,fixed RIGHT
#define sceSblPfsSetKeys_addr           0x6095E0    // 4.74,fixed RIGHT
#define sceSblKeymgrClearKey_addr       0x610D80    // 4.74 RIGHT like 4.55 (for loop) not 5.05 (while loop) - real name is sceSblKeymgrCleartKey
#define sceSblKeymgrSetKeyForPfs_addr   0x6109E0    // 4.74 RIGHT like 5.05 (similar to old 4.55 sceSblKeymgrSetKey)
#define sceSblKeymgrSmCallfunc_addr     0x611530    // 4.74 RIGHT
#define sceSblDriverSendMsg_addr        0x603CA0    // 4.74 RIGHT
#define RsaesPkcs1v15Dec2048CRT_addr    0x3F0070    // 4.74 RIGHT
#define AesCbcCfb128Encrypt_addr        0x179720    // 4.74 RIGHT
#define AesCbcCfb128Decrypt_addr        0x179950    // 4.74 RIGHT
#define Sha256Hmac_addr                 0x2D7E00    // 4.74 RIGHT

// Patch
#define proc_rwmem_addr                 0x17BDD0    // 4.74 RIGHT
#define vmspace_acquire_ref_addr        0x392D00    // 4.74 RIGHT
#define vmspace_free_addr               0x392B30    // 4.74 RIGHT
#define vm_map_lock_read_addr           0x392ED0    // 4.74 RIGHT looks 4.55 not 5.05
#define vm_map_unlock_read_addr         0x392F20    // 4.74 RIGHT looks 4.55 not 5.05
#define vm_map_lookup_entry_addr        0x393A90    // 4.74 RIGHT looks 4.55 not 5.05

// Fself hooks
#define sceSblAuthMgrIsLoadable2_hook                             0x62263F    // 4.74 RIGHT
#define sceSblAuthMgrVerifyHeader_hook1                           0x622D66    // 4.74 RIGHT points to _sceSblAuthMgrSmVerifyHeader (the wrapper)
#define sceSblAuthMgrVerifyHeader_hook2                           0x623989    // 4.74 RIGHT points to _sceSblAuthMgrSmVerifyHeader (the wrapper)
#define sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox_hook 0x626CAA    // 4.74 RIGHT
#define sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox_hook   0x6278D1    // 4.74 RIGHT

// Fpkg hooks
#define sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif_hook    0x6312F0    // 4.74 RIGHT
#define sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new_hook         0x6320CE    // 4.74 RIGHT
#define sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook1      0x609475    // 4.74 RIGHT
#define sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook2      0x6094D3    // 4.74 RIGHT
#define mountpfs__sceSblPfsSetKeys_hook1                          0x69AFE4    // 4.74 RIGHT
#define mountpfs__sceSblPfsSetKeys_hook2                          0x69B214    // 4.74 RIGHT

// SceShellCore patches

// call sceKernelIsGenuineCEX
#define sceKernelIsGenuineCEX_patch1    0x14BC6B // 4.74 RIGHT
#define sceKernelIsGenuineCEX_patch2    0x6F3C5B // 4.74 RIGHT
#define sceKernelIsGenuineCEX_patch3    0x7278D3 // 4.74,fixed RIGHT
#define sceKernelIsGenuineCEX_patch4    0x86168B // 4.74,fixed RIGHT

// call nidf_libSceDipsw
#define nidf_libSceDipsw_patch1         0x14BC97    // 4.74 RIGHT
#define nidf_libSceDipsw_patch2         0x1FEAA8    // 4.74,fixed RIGHT
#define nidf_libSceDipsw_patch3         0x6F3C87    // 4.74 RIGHT
#define nidf_libSceDipsw_patch4         0x8616B7    // 4.74

// enable fpkg
#define enable_fpkg_patch               0x385032    // 4.74,fixed RIGHT
 
// debug pkg free string
#define fake_free_patch                 0xD50208    // 4.74 RIGHT

#endif
