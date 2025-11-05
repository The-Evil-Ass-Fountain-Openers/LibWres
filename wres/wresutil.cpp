/* restable.c - Decoding PE and NE resource tables
 *
 * Copyright (C) 1998 Oskar Liljeblad
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <inttypes.h>
#include <algorithm>
#include "intutil.h"
#include "error.h"
#include "wresutil.h"

namespace wres
{

/* check_offset:
 *   Check if a chunk of data (determined by offset and size)
 *   is within the bounds of the WinLibrary file.
 *   Usually not called directly.
 */
bool check_offset(const char *memory, size_t total_size,
				  const char *name, const void *offset, size_t size)
{
	const char* memory_end = memory + total_size;
	const char* block = (const char*) offset;
	const char* block_end = block + size;

	/*debug("check_offset: size=%x vs %x offset=%x size=%x\n",
		need_size, total_size, (char *) offset - memory, size);*/

	if (((memory > memory_end) || (block > block_end))
		|| (block < memory) || (block >= memory_end) || (block_end > memory_end)) {
		warn("%s: premature end", name);
		return false;
	}

	return true;
}

/* res_type_id_to_string:
 *   Translate a numeric resource type to it's corresponding string type.
 *   (For informative-ness.)
 */
const char *res_type_id_to_string (int id)
{
    if (id == 241)
        return "toolbar";
    if (id > 0 && id <= RES_TYPE_COUNT)
        return res_types[id-1];
    return NULL;
}

/* res_type_string_to_id:
 *   Translate a resource type string to integer.
 *   (Used to convert the --type option.)
 */
const char *res_type_string_to_id (const char *type)
{
    int c;

    if (type == NULL)
        return NULL;

    for (c = 0 ; c < RES_TYPE_COUNT ; c++)
    {
        if (res_types[c] != NULL && !strcasecmp(type, res_types[c]))
            return res_type_ids[c];
    }

    return type;
}

}

