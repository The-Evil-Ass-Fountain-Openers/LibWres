#include "winresource.h"
#include "macros.h"
#include "wresutil.h"
#include "intutil.h"
#include <stdexcept>

namespace wres
{

WinResource::WinResource() {}

bool WinResource::setId(std::string i, id_type t)
{
    if(i.size() > WINRES_ID_MAXLEN)
    {
        printf("[wres] Can't set resource ID longer than %d characters!\n", WINRES_ID_MAXLEN);
        return false;
    }
    m_id = i;
    m_idType = t;
    return true;
}

void WinResource::setType(std::string t)
{
    m_type = t;
}
void WinResource::setLanguage(std::string lang)
{
    m_language = lang;
}
void WinResource::setName(std::string n)
{
    m_name = n;
}
bool WinResource::setLevel(int l)
{
    if(l >= 3)
    {
        printf("[wres] Level provided (%d) is higher than the maximum allowed value of 2.\n", l);
        return false;
    }
    m_level = l;
    return true;
}
void WinResource::setIsDirectory(bool isDir)
{
    m_isDirectory = isDir;
}
void WinResource::setParent(WinResource *res)
{
    m_parent = res;
}
void WinResource::setLocation(uint8_t* loc)
{
    m_location = loc;
}
void WinResource::setSize(size_t s)
{
    m_size = s;
}
std::string WinResource::id() const
{
    return m_id;
}
WinResource::id_type WinResource::idType() const
{
    return m_idType;
}
std::string WinResource::type() const
{
    return m_type;
}
std::string WinResource::language() const
{
    return m_language;
}
std::string WinResource::name() const
{
    return m_name;
}
std::string WinResource::typeAsString() const
{
    if(m_idType == WinResource::Numeric)
    {
        try
        {
            int numid = std::stoi(m_type);
            auto str = res_type_id_to_string(numid);
            if(str)
            {
                return std::string(str);
            }
            return m_type;
        }
        catch (const std::invalid_argument& e)
        {
            return m_type;
        }
        catch (const std::out_of_range& e)
        {
            return m_type;
        }
    }
    else
    {
        return m_type;
    }
}
/*
 * getExtractExtension:
 * Return extension for files of a certain resource type
 */
std::string WinResource::getExtractExtension() const
{
    if(m_type.empty() || m_type == "") return "";
    uint16_t value;
    auto type_c = res_type_string_to_id(m_type.c_str());
    if (parse_uint16(type_c, &value))
    {
        if (value == 2)
            return ".bmp";
        if (value == 14)
            return ".ico";
        if (value == 12)
            return ".cur";
    }

    // Try recognizing if the resource is a PNG image
    if(m_size > 8 && m_offset != nullptr)
    {
        if(memcmp((uint8_t*)m_offset, png_signature, 8) == 0)
        {
            return ".png";
        }
    }
    // Try recognizing if the resource is a JPG image
    if(m_size > 3 && m_offset != nullptr)
    {
        if(memcmp((uint8_t*)m_offset, jpg_signature, 3) == 0)
        {
            return ".jpg";
        }
    }

    // Otherwise, return no extension
    return "";
}


int WinResource::level() const
{
    return m_level;
}
bool WinResource::isDirectory() const
{
    return m_isDirectory;
}
WinResource* WinResource::parent() const
{
    return m_parent;
}
uint8_t* WinResource::location() const
{
    return m_location;
}
size_t WinResource::size() const
{
    return m_size;
}
char* WinResource::offset() const
{
    if(m_isDirectory) return nullptr;
    return m_offset;
}
std::vector<WinResource>& WinResource::children()
{
    return m_children;
}
void WinResource::setChildren(std::vector<WinResource> res)
{
    m_children = res;
}
void WinResource::addChild(WinResource res)
{
    m_children.push_back(res);
}
void WinResource::setOffset(char* o)
{
    m_offset = o;
}


}
