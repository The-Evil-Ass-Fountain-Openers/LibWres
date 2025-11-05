#include "winlibrary.h"
#include <algorithm>
#include <inttypes.h>

namespace wres
{

bool WinLibrary::compareResourceId(const WinResource& res, std::string id, WinResource::id_type idType)
{
    return id == res.id() && (idType == WinResource::Any || idType == res.idType());
}

WinResource* WinLibrary::findResource(std::string type, std::string name, std::string language,
                                             WinResource::id_type tType,
                                             WinResource::id_type nType,
                                             WinResource::id_type lType)
{
    auto find_with_resource_array = [&](WinResource* r, std::string str, WinResource::id_type t) -> WinResource*
    {
        auto it = std::find_if(r->children().begin(), r->children().end(), [&](const WinResource &a) { return WinLibrary::compareResourceId(a, str, t); });
        if(it == r->children().end()) return nullptr;
        return &(*it);
    };
    WinResource *wr = &m_root;

    // Search by type first
    if (type == "" || type.empty())
        return nullptr;
    wr = find_with_resource_array(wr, type, tType);
    if (wr == nullptr || !wr->isDirectory())
        return wr;

    // If no further query arguments are provided, return what we got
    if (name == "" || name.empty())
        return wr;
    wr = find_with_resource_array(wr, name, nType);
    if (wr == nullptr || !wr->isDirectory())
        return wr;

    // If no further query arguments are provided, return what we got
    if (language == "" || language.empty())
        return wr;
    wr = find_with_resource_array(wr, language, lType);
    return wr;
}
/* calc_vma_size:
 *   Calculate the total amount of memory needed for a 32-bit Windows
 *   module. Returns -1 if file was too small.
 */
int WinLibrary::calc_vma_size()
{
    Win32ImageSectionHeader *seg;
    size_t c, segcount, size;

    size = 0;
    CHECK_IF_BAD_POINTER(-1, PE_HEADER(m_data)->file_header.number_of_sections);
    segcount = PE_HEADER(m_data)->file_header.number_of_sections;

    /* If there are no segments, just process file like it is.
     * This is (probably) not the right thing to do, but problems
     * will be dealt with later anyway.
     */
    if (segcount == 0)
        return m_length;

    CHECK_IF_BAD_PE_SECTIONS(-1, m_data);
    seg = PE_SECTIONS(m_data);
    CHECK_IF_BAD_POINTER(-1, *seg);

    for (c = 0 ; c < segcount ; c++) {
        CHECK_IF_BAD_POINTER(0, *seg);

        size = std::max(size, static_cast<size_t>(seg->virtual_address + seg->size_of_raw_data));
        /* I have no idea what misc.virtual_size is for... */
        size = std::max(size, static_cast<size_t>(seg->virtual_address + seg->misc.virtual_size));
        seg++;
    }

    return size;
}
Win32ImageDataDirectory* WinLibrary::get_data_directory_entry(unsigned int entry)
{
    Win32ImageNTHeaders *pe_header;
    pe_header = PE_HEADER(m_data);
    CHECK_IF_BAD_POINTER(NULL, pe_header->optional_header.magic);

    if (pe_header->optional_header.magic == OPTIONAL_MAGIC_PE32) {
        Win32ImageOptionalHeader *optional_header = &(pe_header->optional_header);
        CHECK_IF_BAD_POINTER(NULL, optional_header->data_directory[entry]);
        return optional_header->data_directory + entry;
    } else if (pe_header->optional_header.magic == OPTIONAL_MAGIC_PE32_64) {
        Win32ImageOptionalHeader64 *optional_header =
        (Win32ImageOptionalHeader64*)&(pe_header->optional_header);
        CHECK_IF_BAD_POINTER(NULL, optional_header->data_directory[entry]);
        return optional_header->data_directory + entry;
    } else {
        return NULL;
    }
}

/* read_library:
 *
 * Read header and get resource directory offset in a Windows library
 * (AKA module).
 */
bool WinLibrary::read_library()
{
    /* check for DOS header signature `MZ' */
    CHECK_IF_BAD_POINTER(false, MZ_HEADER(m_data)->magic);
    if (MZ_HEADER(m_data)->magic == IMAGE_DOS_SIGNATURE) {
        DOSImageHeader *mz_header = MZ_HEADER(m_data);

        CHECK_IF_BAD_POINTER(false, mz_header->lfanew);
        if (mz_header->lfanew < sizeof (DOSImageHeader)) {
            warn("%s: not a PE library", m_path.c_str());
            return false;
        }

        /* falls through */
    }

    CHECK_IF_BAD_OFFSET(false, MZ_HEADER(m_data), sizeof(Win32ImageNTHeaders));
    /* check for OS2 (Win16) header signature `NE' */
    CHECK_IF_BAD_POINTER(false, NE_HEADER(m_data)->magic);
    if (NE_HEADER(m_data)->magic == IMAGE_OS2_SIGNATURE) {
        OS2ImageHeader *header = NE_HEADER(m_data);
        uint16_t *alignshift;

        CHECK_IF_BAD_POINTER(false, header->rsrctab);
        CHECK_IF_BAD_POINTER(false, header->restab);
        if (header->rsrctab >= header->restab) {
            warn("%s: no resource directory found", m_path.c_str());
            return false;
        }

        m_isPEBinary = false;
        alignshift = (uint16_t*)((uint8_t*)NE_HEADER(m_data) + header->rsrctab);
        m_firstResource = ((uint8_t*)alignshift) + sizeof(uint16_t);
        CHECK_IF_BAD_POINTER(false, *(Win16NETypeInfo*)m_firstResource);

        return false;
    }

    /* check for NT header signature `PE' */
    CHECK_IF_BAD_POINTER(false, PE_HEADER(m_data)->signature);
    if (PE_HEADER(m_data)->signature == IMAGE_NT_SIGNATURE) {
        Win32ImageSectionHeader *pe_sections;
        Win32ImageDataDirectory *dir;
        Win32ImageNTHeaders *pe_header;
        int d;

        /* allocate new memory */
        m_length = this->calc_vma_size();
        if (m_length <= 0) {
            /* calc_vma_size has reported error */
            return false;
        }
        m_data = (char*)realloc(m_data, m_length);

        /* relocate memory, start from last section */
        pe_header = PE_HEADER(m_data);
        CHECK_IF_BAD_PE_SECTIONS(false, m_data);
        pe_sections = PE_SECTIONS(m_data);

        /* we don't need to do OFFSET checking for the sections.
         * calc_vma_size has already done that */
        for (d = pe_header->file_header.number_of_sections - 1; d >= 0 ; d--)
        {
            Win32ImageSectionHeader *pe_sec = pe_sections + d;

            if (pe_sec->characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                continue;

            //if (pe_sec->virtual_address + pe_sec->size_of_raw_data > fi->total_size)

            /* Protect against memory moves overwriting the section table */
            if ((uint8_t*)(m_data + pe_sec->virtual_address)
                < (uint8_t*)(pe_sections + pe_header->file_header.number_of_sections))
            {
                warn("%s: invalid sections layout", m_path.c_str());
                return false;
            }

            CHECK_IF_BAD_OFFSET(0, m_data + pe_sec->virtual_address, pe_sec->size_of_raw_data);
            CHECK_IF_BAD_OFFSET(0, m_data + pe_sec->pointer_to_raw_data, pe_sec->size_of_raw_data);
            if (pe_sec->virtual_address != pe_sec->pointer_to_raw_data)
            {
                memmove(m_data + pe_sec->virtual_address,
                        m_data + pe_sec->pointer_to_raw_data,
                        pe_sec->size_of_raw_data);
            }
        }

        /* find resource directory */
        dir = this->get_data_directory_entry(IMAGE_DIRECTORY_ENTRY_RESOURCE);
        if (dir == NULL) return false;
        if (dir->size == 0) {
            warn("%s: file contains no resources", m_path.c_str());
            return false;
        }

        m_firstResource = ((uint8_t*)m_data) + dir->virtual_address;
        m_isPEBinary = true;
        return true;
    }

    /* other (unknown) header signature was found */
    warn("%s: not a PE or NE library", m_path.c_str());
    return false;
}

WinLibrary::WinLibrary(std::string p)
{
    m_path = p;
    m_length = file_size(p.c_str());
    if(m_length == -1)
    {
        printf("[wres] Failed to get file size of %s!\n", p.c_str());
        return;
    }
    if(m_length == 0)
    {
        printf("[wres] File %s has a size of 0 bytes!\n", p.c_str());
        m_isValid = false;
        return;
    }
    // Try loading the file
    m_fi = fopen(p.c_str(), "rb");
    if(!m_fi)
    {
        printf("[wres] Failed to open file %s!\n", p.c_str());
        m_isValid = false;
        return;
    }

    /* read all of file */
    m_data = (char*)malloc(m_length);
    if (fread(m_data, m_length, 1, m_fi) != 1)
    {
        printf("[wres] Error while reading file %s!\n", p.c_str());
        m_isValid = false;
        return;
    }

    if(!this->read_library())
    {
        printf("[wres] Something went wrong while parsing the library header\n");
        m_isValid = false;
        return;
    }

    m_root.setId("ROOT", WinResource::String);
    m_root.setLevel(-1);
    m_root.setLocation(m_firstResource);
    m_root.setIsDirectory(true);

    // Perform recursive search

    m_isValid = true;

    buildResourceTree(&m_root);
    // Print the whole structure
    printf("Tree:\n");
    for(int i = 0; i < m_root.children().size(); i++)
    {
        auto c = m_root.children()[i];
        printf("Type: %s\n", c.typeAsString().c_str());

        for(int j = 0; j < c.children().size(); j++)
        {
            auto c1 = c.children()[j];
            printf("\tType: %s, Name: %s\n", c1.typeAsString().c_str(), c1.name().c_str());

            for(int k = 0; k < c1.children().size(); k++)
            {
                auto c2 = c1.children()[k];
                printf("\t\tType: %s, Name: %s, Lang: %s ; Offset=0x%x, Size=%zu\n",
                       c2.typeAsString().c_str(), c2.name().c_str(), c2.language().c_str(),
                       (uint32_t)(c2.offset() - m_data), c2.size());
            }
        }

    }

}

void* WinLibrary::set_resource_entry(WinResource *wr)
{
    if (m_isPEBinary)
    {
        Win32ImageResourceDataEntry *dataent;

        dataent = (Win32ImageResourceDataEntry*)(wr->location());
        CHECK_IF_BAD_POINTER(NULL, *dataent);
        size_t size = dataent->size;
        CHECK_IF_BAD_OFFSET(NULL, m_data + dataent->offset_to_data, size);

        wr->setSize(size);
        wr->setOffset(m_data + dataent->offset_to_data);
        return m_data + dataent->offset_to_data;
    }
    else
    {
        Win16NENameInfo *nameinfo;
        int sizeshift;

        nameinfo = (Win16NENameInfo*)(wr->location());
        sizeshift = *((uint16_t *) m_firstResource - 1);
        size_t size = nameinfo->length << sizeshift;
        CHECK_IF_BAD_OFFSET(NULL, m_data + (nameinfo->offset << sizeshift), size);

        wr->setSize(size);
        wr->setOffset(m_data + (nameinfo->offset << sizeshift));
        return m_data + (nameinfo->offset << sizeshift);
    }
}

bool WinLibrary::decode_pe_resource_id(WinResource *wr, uint32_t value)
{
    std::string s_id;
    if (value & IMAGE_RESOURCE_NAME_IS_STRING)
    {
        /* numeric id */
        int c, len;
        uint16_t *mem = (uint16_t *)
          (m_firstResource + (value & ~IMAGE_RESOURCE_NAME_IS_STRING));

        /* copy each char of the string, and terminate it */
        CHECK_IF_BAD_POINTER(false, *mem);
        len = mem[0];
        CHECK_IF_BAD_OFFSET(false, &mem[1], sizeof(uint16_t) * len);

        len = std::min(mem[0], static_cast<uint16_t>(WINRES_ID_MAXLEN));
        char tmp[len+1];
        for (c = 0; c < len; c++)
            tmp[c] = mem[c+1] & 0x00FF;
        tmp[len] = '\0';
        s_id = std::string(tmp);
    }
    else
    {
        /* Unicode string id */
        /* translate id into a string */
        char tmp[WINRES_ID_MAXLEN];
        snprintf(tmp, WINRES_ID_MAXLEN, "%" PRIu32, value);
        s_id = std::string(tmp);
    }

    wr->setId(s_id, (value & IMAGE_RESOURCE_NAME_IS_STRING ? WinResource::String : WinResource::Numeric));
    return true;
}
std::vector<WinResource> WinLibrary::list_pe_resources(WinResource &res)
{
    Win32ImageResourceDirectory *pe_res = (Win32ImageResourceDirectory*)(res.location());
    int level = res.level()+1;
    std::vector<WinResource> result;

    int dirent_c, rescnt;
    Win32ImageResourceDirectoryEntry *dirent = (Win32ImageResourceDirectoryEntry*)(pe_res + 1);

    /* count number of `type' resources */
    CHECK_IF_BAD_POINTER(std::vector<WinResource>(), *dirent);
    rescnt = pe_res->number_of_named_entries + pe_res->number_of_id_entries;
    if (rescnt == 0) return {};

    /* fill in the WinResource's */
    for (dirent_c = 0; dirent_c < rescnt; dirent_c++) {
        CHECK_IF_BAD_POINTER(std::vector<WinResource>(), dirent[dirent_c]);
        // Tracks the parent apparently instead of it being self-referential
        WinResource r;
        r.setParent(&res);
        r.setLevel(level);
        r.setIsDirectory((dirent[dirent_c].u2.s.data_is_directory));

        /* Require data to point somewhere after the directory */
        if (dirent[dirent_c].u2.s.offset_to_directory < sizeof(Win32ImageResourceDirectory))
            continue;
        r.setLocation(m_firstResource + dirent[dirent_c].u2.s.offset_to_directory);

        /* fill in wr->id, wr->numeric_id */
        if(!decode_pe_resource_id(&r, dirent[dirent_c].u1.name))
            continue;
        result.push_back(r);

    }

    return result;
}
std::vector<WinResource> WinLibrary::list_resources(WinResource &res)
{
    if (!res.isDirectory())
        return {};

    if (m_isPEBinary)
    {
        return list_pe_resources(res);
    }
    else
    {
        return {};
    }
}
bool WinLibrary::buildResourceTree(WinResource *res)
{
    res->setChildren(list_resources(*res));
    if(res->children().size() == 0) return false;

    for(int i = 0; i < res->children().size(); i++)
    {
        if (res->children()[i].level() <= res->level() || (res->level() >= 3))
        {
            printf("%s: resource structure malformed\n", m_path.c_str());
            return false;
        }
        switch(res->children()[i].level())
        {
            case 0:
                res->children()[i].setType(res->children()[i].id());
                break;
            case 1: // Inherit type from parent
                if(res->children()[i].parent() == nullptr)
                {
                    printf("Resource with nonzero level has a null parent!\n");
                    return false;
                }
                res->children()[i].setType(res->children()[i].parent()->type());
                res->children()[i].setName(res->children()[i].id());
                break;
            case 2: // Inherit type and name from parent
                if(res->children()[i].parent() == nullptr)
                {
                    printf("Resource with nonzero level has a null parent!\n");
                    return false;
                }
                res->children()[i].setType(res->children()[i].parent()->type());
                res->children()[i].setName(res->children()[i].parent()->name());
                res->children()[i].setLanguage(res->children()[i].id());
                break;
        }
        set_resource_entry(&(res->children()[i]));
        if(res->children()[0].isDirectory())
        {
            buildResourceTree(&(res->children()[i]));
        }
    }

    return true;
}

bool WinLibrary::extractResource(WinResource* res, std::string outpath, bool raw)
{
    auto get_destination_name = [&]() -> std::string
    {
        std::string str(basename(this->m_path.c_str()));
        std::string extension = "";

        if(res->type() != "" && !res->type().empty())
        {
            str += std::string("_") + res->type();
            extension = std::string(get_extract_extension(res->type().c_str()));
        }
        if(res->name() != "" && !res->name().empty())
            str += std::string("_") + res->name();
        if(res->language() != "" && !res->language().empty())
            str += std::string("_") + res->language();

        str += extension;

        return outpath + ((outpath.empty() || outpath == "") ? std::string("") : std::string("/")) + str;
    };

    if(res == nullptr)
    {
        printf("Cannot extract from a null resource.\n");
        return false;
    }
    if(res->isDirectory())
    {
        for(auto r : res->children())
        {
            extractResource(&r, outpath, raw);
        }
    }
    else
    {

        size_t size;
        bool free_it;
        void *memory;
        std::string outname;
        FILE *out;

        memory = extract(res, &size, &free_it, raw);
        if (memory == NULL)
        {
            /* extract resource has printed error */
            return false;
        }

        /* determine where to extract to */
        outname = get_destination_name();
        printf("%s\n\n", outname.c_str());
        if (outname.empty() || outname == "")
        {
            out = stdout;
        }
        else
        {
            out = fopen(outname.c_str(), "wb");
            if (out == NULL)
            {
                warn_errno("%s", outname.c_str());

                if (free_it)
                     free(memory);
                if (out != NULL && out != stdout)
                     fclose(out);
                return false;
            }
        }

        /* write the actual data */
        fwrite(memory, size, 1, out);

        if (free_it)
            free(memory);
        if (out != NULL && out != stdout)
            fclose(out);

    }
    return true;

}
void* WinLibrary::extract(WinResource *res, size_t *size, bool *free_it, bool raw)
{
	int32_t intval;

    if(raw)
    {
        // If raw is defined, or
        /* just return pointer to data if raw i */
        *free_it = false;
        *size = res->size();
        return res->offset();
    }
	/* find out how to extract */
	if((res->type() != "" && !res->type().empty()) && parse_int32(res->type().c_str(), &intval))
	{
        switch(intval)
        {
            case RT_BITMAP:
                *free_it = true;
                return extract_bitmap_resource(res, size);
            case RT_GROUP_ICON:
                *free_it = true;
                return extract_group_icon_cursor_resource(res, size, true);
            case RT_GROUP_CURSOR:
                *free_it = true;
                return extract_group_icon_cursor_resource(res, size, false);
            default:
                *free_it = false;
                *size = res->size();
                return res->offset();
        }
	}
	return nullptr;
}

/* extract_group_icon_resource:
 *   Create a complete RT_GROUP_ICON resource, that can be written to
 *   an `.ico' file without modifications. Returns an allocated
 *   memory block that should be freed with free() once used.
 *
 *   `root' is the offset in file that specifies the resource.
 *   `base' is the offset that string pointers are calculated from.
 *   `ressize' should point to an integer variable where the size of
 *   the returned memory block will be placed.
 *   `is_icon' indicates whether resource to be extracted is icon
 *   or cursor group.
 */
void* WinLibrary::extract_group_icon_cursor_resource(WinResource *res, size_t *ressize, bool is_icon)
{
    Win32CursorIconDir *icondir;
    Win32CursorIconFileDir *fileicondir;
    char *memory;
    int offset, skipped;
    size_t size = res->size();

    /* get resource data and size */
    icondir = (Win32CursorIconDir*)(res->offset());
    if (icondir == nullptr)
    {
        /* get_resource_entry will print error */
        return nullptr;
    }

    /* calculate total size of output file */
    CHECK_IF_BAD_POINTER(nullptr, icondir->count);
    skipped = 0;
    for (int c = 0 ; c < icondir->count ; c++)
    {
        size_t iconsize;
        char name[14];

        CHECK_IF_BAD_POINTER(nullptr, icondir->entries[c]);
        /*printf("%d. bytes_in_res=%d width=%d height=%d planes=%d bit_count=%d\n", c,
         *			icondir->entries[c].bytes_in_res,
         *			(is_icon ? icondir->entries[c].res_info.icon.width : icondir->entries[c].res_info.cursor.width),
         *			(is_icon ? icondir->entries[c].res_info.icon.height : icondir->entries[c].res_info.cursor.height),
         *			icondir->entries[c].plane_count,
         *			icondir->entries[c].bit_count);*/

        /* find the corresponding icon resource */
        snprintf(name, sizeof(name)/sizeof(char), "%d", icondir->entries[c].res_id);
        WinResource *fwr = this->findResource((is_icon ? std::string("3") : std::string("1")), std::string(name), res->language(),
                                                     WinResource::Numeric);
        if (fwr == nullptr) {
            warn("%s: could not find `%s' in `%s' resource.",
                 m_path, name, (is_icon ? "group_icon" : "group_cursor"));
            return nullptr;
        }

        if (fwr->offset() != nullptr)
        {
            if (fwr->size() == 0)
            {
                warn("%s: icon resource `%s' is empty, skipping", m_path, name);
                skipped++;
                continue;
            }
            if (fwr->size() != icondir->entries[c].bytes_in_res)
            {
                warn("%s: mismatch of size in icon resource `%s' and group (%d vs %d)", m_path, name, fwr->size(), icondir->entries[c].bytes_in_res);
            }
            size += fwr->size() < icondir->entries[c].bytes_in_res ? icondir->entries[c].bytes_in_res : fwr->size();

            /* cursor resources have two additional WORDs that contain
             * hotspot info */
            if (!is_icon)
                size -= sizeof(uint16_t)*2;
        }
    }
    offset = sizeof(Win32CursorIconFileDir) + (icondir->count-skipped) * sizeof(Win32CursorIconFileDirEntry);
    size += offset;
    *ressize = size;

    /* allocate that much memory */
    memory = (char*)malloc(size);
    fileicondir = (Win32CursorIconFileDir *) memory;

    /* transfer Win32CursorIconDir structure members */
    fileicondir->reserved = icondir->reserved;
    fileicondir->type = icondir->type;
    fileicondir->count = icondir->count - skipped;

    /* transfer each cursor/icon: Win32CursorIconDirEntry and data */
    skipped = 0;
    for (int c = 0 ; c < icondir->count ; c++) {
        char name[14];
        char *data;

        /* find the corresponding icon resource */
        snprintf(name, sizeof(name)/sizeof(char), "%d", icondir->entries[c].res_id);
        WinResource *fwr = this->findResource((is_icon ? std::string("3") : std::string("1")), std::string(name), res->language(),
                                                     WinResource::Numeric);
        if (fwr == nullptr)
        {
            warn("%s: could not find `%s' in `%s' resource.",
                 m_path, name, (is_icon ? "group_icon" : "group_cursor"));
            return nullptr;
        }

        /* get data and size of that resource */
        data = (char*)(fwr->offset());
        if (data == nullptr)
        {
            /* get_resource_entry has printed error */
            return nullptr;
        }
        if (fwr->size() == 0)
        {
            skipped++;
            continue;
        }

        /* copy ICONDIRENTRY (not including last dwImageOffset) */
        memcpy(&fileicondir->entries[c-skipped], &icondir->entries[c],
               sizeof(Win32CursorIconFileDirEntry)-sizeof(uint32_t));

        /* special treatment for cursors */
        if (!is_icon) {
            fileicondir->entries[c-skipped].width = icondir->entries[c].res_info.cursor.width;
            fileicondir->entries[c-skipped].height = icondir->entries[c].res_info.cursor.height / 2;
            fileicondir->entries[c-skipped].color_count = 0;
            fileicondir->entries[c-skipped].reserved = 0;
        }

        /* set image offset and increase it */
        fileicondir->entries[c-skipped].dib_offset = offset;

        /* transfer resource into file memory */
        if (size > icondir->entries[c-skipped].bytes_in_res)
            size = icondir->entries[c-skipped].bytes_in_res;
        if (is_icon)
        {
            memcpy(&memory[offset], data, fwr->size());
        }
        else if (fwr->size() >= sizeof(uint16_t)*2)
        {
            fileicondir->entries[c-skipped].hotspot_x = ((uint16_t *) data)[0];
            fileicondir->entries[c-skipped].hotspot_y = ((uint16_t *) data)[1];
            memcpy(&memory[offset], data+sizeof(uint16_t)*2,
                   fwr->size()-sizeof(uint16_t)*2);
            offset -= sizeof(uint16_t)*2;
        }

        /* increase the offset pointer */
        offset += icondir->entries[c].bytes_in_res;
    }

    return (void*)memory;
}

void* WinLibrary::extract_bitmap_resource(WinResource *res, size_t *ressize)
{
    Win32BitmapInfoHeader info;
    uint8_t *result;
    uint8_t *resentry;
    uint32_t offbits;
    size_t size = res->size();

    resentry=(uint8_t*)(res->offset());
    if (!resentry)
        return nullptr;

    /* Bitmap file consists of:
     * 1) File header (14 bytes)
     * 2) Bitmap header (40 bytes)
     * 3) Colormap (size depends on a few things)
     * 4) Pixels data
     *
     * parts 2-4 are present in the resource data, we need just
     * to add a file header, which contains file size and offset
     * from file beginning to pixels data.
     */

    /* Get the bitmap info */
    memcpy(&info,resentry,sizeof(info));
    fix_win32_bitmap_info_header_endian(&info);

    /* offbits - offset from file start to the beginning
     *           of the first pixel data */
    offbits = info.size+14;

    /* In 24-bit bitmaps there's no colormap
     * The size of an entry in colormap is 4
     */
    if (info.bit_count!=24) {

        /* 0 value of clr_used means that all possible color
        * entries are used */
       if (info.clr_used == 0)
       {
           switch (info.bit_count)
           {
               case 1:    /* Monochrome bitmap */
                   offbits += 8;
                   break;
               case 4:    /* 16 colors bitmap */
                   offbits += 64;
                   break;
               case 8:    /* 256 colors bitmap */
                  offbits += 1024;
           }
       }
       else
       {
           offbits += 4 * info.clr_used;
       }
    }

    /* The file will consist of the resource data and
     * 14 bytes long file header */
    *ressize = 14+size;
    result = (uint8_t *)malloc(*ressize);

    /* Filling the file header with data */
    result[0] = 'B';   /* Magic char #1 */
    result[1] = 'M';   /* Magic char #2 */
    result[2] = (*ressize & 0x000000ff);      /* file size, little-endian */
    result[3] = (*ressize & 0x0000ff00)>>8;
    result[4] = (*ressize & 0x00ff0000)>>16;
    result[5] = (*ressize & 0xff000000)>>24;
    result[6] = 0; /* Reserved */
    result[7] = 0;
    result[8] = 0;
    result[9] = 0;
    result[10] = (offbits & 0x000000ff);  /* offset to pixels, little-endian */
    result[11] = (offbits & 0x0000ff00)>>8;
    result[12] = (offbits & 0x00ff0000)>>16;
    result[13] = (offbits & 0xff000000)>>24;

    /* The rest of the file is the resource entry */
    memcpy(result+14,resentry,size);

    return result;
}


WinLibrary::~WinLibrary()
{
    if(m_data != nullptr)
    {
        delete m_data;
    }

}
bool WinLibrary::isLoaded() const
{
    return m_length != -1;
}

bool WinLibrary::isValid() const
{
    return m_isValid;
}

std::string WinLibrary::path() const
{
    return m_path;
}
char* WinLibrary::data() const
{
    return m_data;
}
int WinLibrary::length() const
{
    return m_length;
}
bool WinLibrary::isPEBinary() const
{
    return m_isPEBinary;
}
uint8_t* WinLibrary::firstResource() const
{
    return m_firstResource;
}
WinResource& WinLibrary::root()
{
    return m_root;
}

}
