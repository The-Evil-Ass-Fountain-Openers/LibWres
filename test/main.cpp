/* main.c - Main routine for wrestool
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

#include <filesystem>
#include <string.h>
#include "../wres/wresutil.h"
#include "../wres/winlibrary.h"
#include "../wres/winresource.h"

int main (int argc, char **argv)
{

	auto printStats = [](const wres::WinLibrary &a)
	{
		printf("Path: %s\nIs PE Executable: %s\nFile size: %d\nValid: %s\nLoaded: %s\nFirst res: %llu\n",
		   a.path().c_str(), a.isPEBinary() ? "true" : "false", a.length(),
		   a.isValid() ? "true" : "false", a.isLoaded() ? "true" : "false", a.firstResource());

	};
	printf("Opening winemine...\n");
	wres::WinLibrary testfi(std::string("../../test/pe/winemine.exe"));
	printf("Testing C++ WinLibrary...\n");
	printStats(testfi);

	printf("Print resource tree\n");

	testfi.printResourceTree();

	printf("Searching tests\n");

	std::vector<wres::WinResource*> results =
	{
		testfi.findResource(std::string("4"), std::string("1"), std::string("")), // Should return a directory
		testfi.findResource(std::string("4"), std::string("1"), std::string("3")), // Should return a resource
		testfi.findResource(std::string("3"), std::string("1"), std::string("")), // Should return a directory
		testfi.findResource(std::string("3"), std::string("2"), std::string("0")), // Should return a resource
		testfi.findResource(std::string("3"), std::string("2"), std::string("1")), // Should fail
		testfi.findResource(std::string("25"), std::string("2"), std::string("1")), // Should fail
		testfi.findResource(std::string("3"), std::string("5"), std::string("0"), wres::WinResource::Any, wres::WinResource::Any, wres::WinResource::String), // Should fail
		testfi.findResource(std::string("3"), std::string("5"), std::string("0"), wres::WinResource::Any, wres::WinResource::Any, wres::WinResource::Numeric), // Should return a resource
		testfi.findResource(std::string("3"), std::string("5"), std::string("0"), wres::WinResource::Any, wres::WinResource::String, wres::WinResource::Numeric), // Should fail
	};

	auto printSearchResults = [&](const wres::WinLibrary &a)
	{
		for(int i = 0; i < results.size(); i++)
		{
			printf("%d. ", i);
			auto result = results[i];
			if(result)
			{
				printf("Is Directory: %s, Offset=0x%x, Size=%zu\n\n", result->isDirectory() ? "true" : "false", (uint32_t)(result->offset() - a.data()), result->size());
			}
			else
			{
				printf("Not found!\n");
			}
		}

	};
	printSearchResults(testfi);

	printf("\n\n");
	printf("Opening shell32.dll\n");
	wres::WinLibrary shell(std::string("../../test/pe/shell32.dll"));
	printStats(shell);

	printf("Searching tests\n");

	results =
	{
		shell.findResource(std::string("WINE_REGISTRY"), std::string(""), std::string("")), // Should return a directory
		shell.findResource(std::string("WINE_REGISTRY"), std::string("DLLS/SHELL32/X86_64-WINDOWS/SHELL32_TLB_T.RES"), std::string("0")), // Should return a resource
	};

	printSearchResults(shell);

	printf("Extracting bitmaps test:\n");

	auto bmp = shell.findResource(std::string("2"), std::string("214"), std::string("0")); // Should return a resource

	if(shell.extractResource(bmp, "./", false))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	printf("Extracting icon groups test:\n");

	auto groupicon = testfi.findResource(std::string("14"), std::string("1"), std::string("0"));

	if(testfi.extractResource(groupicon, "."))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	printf("Extracting raw resource test:\n");

	auto str = testfi.findResource(std::string("6"), std::string("66"), std::string("7"));
	if(testfi.extractResource(str, "."))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	printf("Loading msstyles theme:\n");
	wres::WinLibrary theme(std::string("../../test/pe/aero11_seven.msstyles"));
	printStats(theme);
	printf("Extracting PNG resource test:\n");

	auto stream = theme.findResource(std::string("STREAM"), std::string("1342"), std::string("0"));
	if(theme.extractResource(stream, "."))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}
	printf("Extracting JPG resource test:\n");
	auto jpg = shell.findResource(std::string("IMAGE"), std::string("DUSTER"), std::string("0"));
	if(shell.extractResource(jpg, "."))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	printf("Extracting resources from a directory test:\n");

	std::filesystem::create_directories("./images");
	auto images = theme.findResource(std::string("IMAGE"), std::string(""), std::string(""));
	if(theme.extractResource(images, "./images/"))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	/*

	printf("Extracting raw data test:\n");
	auto stream = testfi.findResource(std::string("STREAM"), std::string("971"), std::string("1033"));

	if(testfi.extractResource(stream, "output/", true))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	printf("Extracting entire msstyles test:\n");
	if(testfi.extractResource(&testfi.root(), "output", true))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}


	wres::WinLibrary bitmaptest(std::string("pe/authui.dll"));
	printf("Extracting bitmaps data test:\n");
	stream = bitmaptest.findResource(std::string("2"), std::string("12238"), std::string("1033"));
	if(bitmaptest.extractResource(stream, "output/", false))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	wres::WinLibrary groupicons(std::string("pe/pnidui.dll"));
	printf("Extracting group icons data test:\n");

	stream = groupicons.findResource(std::string("14"), std::string("40407"), std::string("1033"));

	if(groupicons.extractResource(stream, "output/", false))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}
	stream = groupicons.findResource(std::string("3"), std::string("604"), std::string("1033"));
	printf("Extracting singular icon test:\n");
	if(groupicons.extractResource(stream, "output/", false))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}

	wres::WinLibrary jpgtest(std::string("pe/imageres.dll"));
	printf("Test extracting jpg files\n");
	stream = jpgtest.findResource(std::string("IMAGE"), std::string(""), std::string(""));
	if(stream)
	{
		printf("%s found, %d children, dir: %s\n", stream->type().c_str(), stream->children().size(), stream->isDirectory() ? "true" : "false");
	}
	if(jpgtest.extractResource(stream, "output/", false))
	{
		printf("Extraction success!\n");
	}
	else
	{
		printf("Extraction failure!\n");
	}*/

	return 0;
}
