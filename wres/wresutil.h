/* wresutil.h - Common definitions for libwres
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

#ifndef WRESUTIL_H
#define WRESUTIL_H

#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "win32.h"
#include "common.h"
#include "macros.h"

namespace wres
{

bool check_offset(const char *, size_t, const char *, const void *, size_t);

// Resource types represented as human readable strings
static const char *res_types[] =
{
	/* 0x01: */
	"cursor", "bitmap", "icon", "menu", "dialog", "string",
	"fontdir", "font", "accelerator", "rcdata", "messagelist",
	"group_cursor", NULL, "group_icon", NULL,
	/* the following are not defined in winbase.h, but found in wrc. */
	/* 0x10: */
	"version", "dlginclude", NULL, "plugplay", "vxd",
	"anicursor", "aniicon"
};
// Resource types represented as numeric IDs
static const char *res_type_ids[] =
{
	"1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
	"11", "12", NULL, "14", NULL, "16", "17", NULL, "19",
	"20", "21", "22"
};

// Conversion functions between string and numeric types
const char *res_type_id_to_string(int);
const char *res_type_string_to_id (const char*);

// PNG and JPG header signatures, used to attach the respective extensions to extracted files
static const uint8_t png_signature[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
static const uint8_t jpg_signature[] = { 0xFF, 0xD8, 0xFF };

}

#endif
