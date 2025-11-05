/* intutil.c - Integer utility functions.
 *
 * Copyright (C) 2001 Oskar Liljeblad
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

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "intutil.h"

#define INT_STR_FUNC(n,t,m) \
    char * \
    n(t value) \
    { \
	sprintf(intstr, "%" m, value); \
	return intstr; \
    }

/* Why 23 characters? */
/* 2^64-1 in octal is 22 chars + null byte = 23 */
static char intstr[23];

INT_STR_FUNC(uint64_str, uint64_t, PRIu64);
INT_STR_FUNC(uint32_str, uint32_t, PRIu32);
INT_STR_FUNC(uint16_str, uint16_t, PRIu16);
INT_STR_FUNC(uint8_str, uint8_t, PRIu8);
INT_STR_FUNC(int32_str, int32_t, PRIi32);
INT_STR_FUNC(int64_str, int64_t, PRIi64);
INT_STR_FUNC(int16_str, int16_t, PRIi16);
INT_STR_FUNC(int8_str, int8_t, PRIi8);

bool
parse_int8(const char *instr, int8_t *outint)
{
	int8_t value = 0;

	if (*instr == '-') {
		if (instr[1] == '\0')
			return false;
		for (instr++; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value < INT8_MIN/10 || (value == INT8_MIN/10 && c > -(INT8_MIN%10)))
				return false;
			value = value*10 - c;
		}
	} else {
		if (*instr == '\0')
			return false;
		for (; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value > INT8_MAX/10 || (value == INT8_MAX/10 && c > INT8_MAX%10))
				return false;
			value = value*10 + c;
		}
	}
	*outint = value;

	return true;
}

bool
parse_int16(const char *instr, int16_t *outint)
{
	int16_t value = 0;

	if (*instr == '-') {
		if (instr[1] == '\0')
			return false;
		for (instr++; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value < INT16_MIN/10 || (value == INT16_MIN/10 && c > -(INT16_MIN%10)))
				return false;
			value = value*10 - c;
		}
	} else {
		if (*instr == '\0')
			return false;
		for (; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value > INT16_MAX/10 || (value == INT16_MAX/10 && c > INT16_MAX%10))
				return false;
			value = value*10 + c;
		}
	}
	*outint = value;

	return true;
}

bool
parse_int32(const char *instr, int32_t *outint)
{
	int32_t value = 0;

	if (*instr == '-') {
		if (instr[1] == '\0')
			return false;
		for (instr++; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value < INT32_MIN/10L || (value == INT32_MIN/10L && c > -(INT32_MIN%10L)))
				return false;
			value = value*10L - c;
		}
	} else {
		if (*instr == '\0')
			return false;
		for (; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value > INT32_MAX/10L || (value == INT32_MAX/10L && c > INT32_MAX%10L))
				return false;
			value = value*10L + c;
		}
	}
	*outint = value;

	return true;
}

bool
parse_int64(const char *instr, int64_t *outint)
{
	int64_t value = 0;

	if (*instr == '-') {
		if (instr[1] == '\0')
			return false;
		for (instr++; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value < INT64_MIN/10LL || (value == INT64_MIN/10LL && c > -(INT64_MIN%10LL)))
				return false;
			value = value*10LL - c;
		}
	} else {
		if (*instr == '\0')
			return false;
		for (; *instr != '\0'; instr++) {
			int8_t c = *instr - '0';
			if (c < 0 || c > 9)
				return false;
			if (value > INT64_MAX/10LL || (value == INT64_MAX/10LL && c > INT64_MAX%10LL))
				return false;
			value = value*10LL + c;
		}
	}
	*outint = value;

	return true;
}

bool
parse_uint8(const char *instr, uint8_t *outint)
{
	uint8_t value = 0;

	for (; *instr != '\0'; instr++) {
		uint8_t c = *instr - '0';
		if (c > 9)
			return false;
		if (value > UINT8_MAX/10 || (value == UINT8_MAX/10 && c > UINT8_MAX%10))
			return false;
		value = value*10 + c;
	}
	*outint = value;

	return true;
}

bool
parse_uint16(const char *instr, uint16_t *outint)
{
	uint16_t value = 0;

	for (; *instr != '\0'; instr++) {
		uint8_t c = *instr - '0';
		if (c > 9)
			return false;
		if (value > UINT16_MAX/10 || (value == UINT16_MAX/10 && c > UINT16_MAX%10))
			return false;
		value = value*10 + c;
	}
	*outint = value;

	return true;
}

bool
parse_uint32(const char *instr, uint32_t *outint)
{
	uint32_t value = 0;

	for (; *instr != '\0'; instr++) {
		uint8_t c = *instr - '0';
		if (c > 9)
			return false;
		if (value > UINT32_MAX/10L || (value == UINT32_MAX/10L && c > UINT32_MAX%10))
			return false;
		value = value*10L + c;
	}
	*outint = value;

	return true;
}

bool
parse_uint64(const char *instr, uint64_t *outint)
{
	uint64_t value = 0;

	for (; *instr != '\0'; instr++) {
		uint8_t c = *instr - '0';
		if (c > 9)
			return false;
		if (value > UINT64_MAX/10LL || (value == UINT64_MAX/10LL && c > UINT64_MAX%10LL))
			return false;
		value = value*10LL + c;
	}
	*outint = value;

	return true;
}
