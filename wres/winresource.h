#ifndef WINRESOURCE_H
#define WINRESOURCE_H
#include <string>
#include <stdint.h>
#include <vector>
#include "wresutil.h"

namespace wres
{

class WinResource
{
public:
    /*
     * A Windows resource is an element of the underlying
     * tree structure in the PE executable format.
     * A resource can be a directory that holds other
     * resources, or it can contain actual data.
     */
    WinResource();
    /*
     * ID Type indicates how the ID should be treated.
     * A resource ID can be either numeric or a regular
     * string. The Any type is used when searching to
     * indicate that the ID type doesn't matter.
     */
    enum id_type { Numeric, String, Any=-1 };
    /*
     * Returns the ID and ID type of the resource.
     */
    std::string id() const;
    id_type idType() const;
    /*
     * Resources have three main attributes:
     *  - Type: Indicates the type of data the resource
     *          holds.
     *  - Name: Indicates the name of the resource.
     *  - Language: Indicates the language/MUI that
     *              should be used with the PE file.
     *
     * As PE files have a tree structure, a resource is
     * located in it at some depth level. By convention,
     * the maximum level is 3.
     *
     * All three values should be defined for every
     * resource. A single resource item will only have
     * one of these values defined initially (as it is
     * its own ID), while other values are inherited
     * from its parent(s).
     */
    std::string type() const;
    std::string name() const;
    std::string language() const;
    /*
     * Returns the resource type in its human readable
     * string representation, if possible. Otherwise
     * returns the same value as type().
     */
    std::string typeAsString() const;
    /*
     * Returns the level of the resource. Valid level
     * values according to the PE format are [0, 2].
     *
     * If the resource is a root resource that holds
     * all other resources, this returns -1.
     */
    int level() const;
    /*
     * Returns true if the resource is a directory.
     * Directories do not contain any valid data with
     * offset().
     */
    bool isDirectory() const;
    /*
     * Returns the parent resource in the tree structure.
     * If this is a root resource, this returns nullptr.
     */
    WinResource* parent() const;
    /*
     * Returns the children of the resource according to
     * the tree structure. This will be an empty vector if
     * the resource item is not a directory.
     */
    std::vector<WinResource>& children();
    /*
     * Returns the location (first byte) of the resource
     * in the PE file's memory representation. Usually not
     * used for actual data reading, which is done by
     * using offset() instead.
     */
    uint8_t* location() const;
    /*
     * Returns the offset location and size of the actual
     * relevant data that belongs to the resource.
     *
     * The offset returns the first byte of what would be
     * extracted by libwres (raw). The location this
     * pointer points to is effectively:
     *
     * WinLibrary::m_data + first_byte_of_resource_data
     *
     * wres::check_offset can be used to check the validity
     * of this location to prevent illegal memory access.
     */
    char* offset() const;
    size_t size() const;

    void addChild(WinResource res);
    bool setId(std::string i, id_type t);
    void setType(std::string t);
    void setLanguage(std::string lang);
    void setName(std::string n);
    bool setLevel(int l);
    void setIsDirectory(bool isDir);
    void setParent(WinResource *res);
    void setLocation(uint8_t* loc);
    void setOffset(char* o);
    void setSize(size_t s);
    void setChildren(std::vector<WinResource> res);

    std::string getExtractExtension() const;

private:
    std::string m_id = "";
    id_type m_idType;
    std::string m_type = "";
    std::string m_language = "";
    std::string m_name = "";
    int m_level = -1;
    bool m_isDirectory = true;
    WinResource* m_parent = nullptr;
    uint8_t* m_location = nullptr;
    size_t m_size = 0;
    std::vector<WinResource> m_children;
    char* m_offset = nullptr;
};

}

#endif // WINRESOURCE_H
