#ifndef MACROS_H
#define MACROS_H
#include "common.h"

/*
 * Definitions
 */
#define WINRES_ID_MAXLEN (256)
#define ACTION_LIST 				1	/* command: list resources */
#define ACTION_EXTRACT				2	/* command: extract resources */
#define CALLBACK_STOP				0	/* results of ResourceCallback */
#define CALLBACK_CONTINUE			1
#define CALLBACK_CONTINUE_RECURS	2

#define MZ_HEADER(x)	((DOSImageHeader *)(x))
#define NE_HEADER(x)	((OS2ImageHeader *)PE_HEADER(x))
#define NE_TYPEINFO_NEXT(x) ((Win16NETypeInfo *)((uint8_t *)(x) + sizeof(Win16NETypeInfo) + \
((Win16NETypeInfo *)x)->count * sizeof(Win16NENameInfo)))
#define NE_RESOURCE_NAME_IS_NUMERIC (0x8000)
#define RES_TYPE_COUNT ((int)(sizeof(res_types)/sizeof(char *)))

#define CHECK_IF_BAD_POINTER(r, x) \
if (!check_offset(m_data, m_length, m_path.c_str(), &(x), sizeof(x))) { \
    /*printf("bad_pointer in %s:%d\n", __FILE__, __LINE__);*/ \
    return (r); \
}
#define CHECK_IF_BAD_OFFSET(r, x, s) \
if (!check_offset(m_data, m_length, m_path.c_str(), x, s)) { \
    /*printf("bad_offset in %s:%d\n", __FILE__, __LINE__);*/ \
    return (r); \
}

/* Check whether access to a PE_SECTIONS is allowed */
#define CHECK_IF_BAD_PE_SECTIONS(ret, module)                                              \
do {                                                                                    \
    void* pe_sec_;                                                                      \
    CHECK_IF_BAD_POINTER(ret, PE_HEADER(module)->optional_header);                     \
    CHECK_IF_BAD_POINTER(ret, PE_HEADER(module)->file_header.number_of_sections);      \
    pe_sec_ = PE_SECTIONS(module);                                                      \
    CHECK_IF_BAD_OFFSET(ret, pe_sec_, sizeof(Win32ImageSectionHeader)                  \
    * PE_HEADER(module)->file_header.number_of_sections);                           \
} while(0)


#endif // MACROS_H
