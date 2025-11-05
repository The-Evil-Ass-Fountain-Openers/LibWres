#ifndef WINLIBRARY_H
#define WINLIBRARY_H
#include <string>
#include <stdint.h>
#include "io-utils.h"
#include "intutil.h"
#include "error.h"
#include "win32.h"
#include "win32-endian.h"
#include "wresutil.h"

#include "winresource.h"

namespace wres
{

class WinLibrary
{
public:
    /*
     * WinLibrary represents the file itself which can be a PE or NE executable.
     * Upon loading the file, its memory contents can be viewed directly via
     * data(). The beginning contents of the file consists of the executable
     * header, so firstResource() can be used to skip the header.
     *
     * To make resource reading easier, one should use WinResources to search
     * for the appropriate resources and inspect their metadata. The root()
     * method will return the tree structure that's constructed on initialization
     * of the WinLibrary instance.
     *
     */
    WinLibrary(std::string p);
    ~WinLibrary();
    /*
     * Returns the path of the file being loaded into memory.
     */
    std::string path() const;
    /*
     * Returns the raw contents of the file.
     */
    char* data() const;
    /*
     * Returns the file size, which is equivalent to the length of the data array.
     */
    int length() const;
    /*
     * Returns true if the file is a PE executable, false if the file is a NE
     * executable.
     */
    bool isPEBinary() const;
    /*
     * Returns true if the file is valid. If the value is false, it can mean one
     * of the following:
     *  - The file is 0 bytes long
     *  - Opening the file failed
     *  - Reading the file failed
     *  - The file format is invalid and does not represent a PE/NE executable
     */
    bool isValid() const;
    /*
     * Returns true if the file has been loaded into memory.
     */
    bool isLoaded() const;
    /*
     * Returns the first byte in the data sequence that points to the first
     * resource.
     */
    uint8_t* firstResource() const;
    /*
     * Returns the root of the resource tree structure.
     */
    WinResource& root();
    /*
     * Extracts the contents of the resource onto the filesystem. The raw
     * parameter can be used to tell the procedure to simply dump the raw
     * contents of the resource instead of trying to parse it first.
     */
    bool extractResource(WinResource* res, std::string outpath, bool raw);

    /*
     * Builds the resource tree structure which can be traversed by accessing
     * the root of the tree, its children, and so on. Alternatively, resources
     * can be searched for by using the find_resource method. This method is
     * called by the constructor.
     */

    bool buildResourceTree(WinResource *res);

    static bool compareResourceId(const WinResource& res, std::string id, WinResource::id_type idType);

    WinResource *findResource(std::string type, std::string name, std::string language,
                                     WinResource::id_type tType = WinResource::Any,
                                     WinResource::id_type nType = WinResource::Any,
                                     WinResource::id_type lType = WinResource::Any);


private:
    std::string m_path;
    char* m_data = nullptr;
    int m_length;
    bool m_isPEBinary = false;
    bool m_isValid = false;
    uint8_t* m_firstResource = nullptr;
    WinResource m_root;
    FILE* m_fi;

    // mostly retained functions from wrestool
    int calc_vma_size();
    bool read_library();
    Win32ImageDataDirectory* get_data_directory_entry(unsigned int entry);
    std::vector<WinResource> list_resources(WinResource &res);
    std::vector<WinResource> list_pe_resources(WinResource &res);
    void* set_resource_entry(WinResource *wr);
    bool decode_pe_resource_id(WinResource *wr, uint32_t value);

    void* extract(WinResource *wr, size_t *size,
                  bool *free_it, bool raw);

    void* extract_group_icon_cursor_resource(WinResource *res, size_t *ressize, bool is_icon);
    void* extract_bitmap_resource(WinResource *res, size_t *ressize);

};

}

#endif // WINLIBRARY_H
