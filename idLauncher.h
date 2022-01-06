#pragma once

// Windows includes
#include <stdio.h>
#include <string>
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <Psapi.h>
#include <tlhelp32.h>

// internal includes
#include "INIReader.h"

// library includes
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
namespace fs = boost::filesystem;
namespace po = boost::program_options;

using namespace std;

enum ProcessState {
	PROCESS_STATE_SLEEP,
	PROCESS_STATE_WAKE
};

// color codes
/*
Name            FG  BG
Black           30  40
Red             31  41
Green           32  42
Yellow          33  43
Blue            34  44
Magenta         35  45
Cyan            36  46
White           37  47
Bright Black    90  100
Bright Red      91  101
Bright Green    92  102
Bright Yellow   93  103
Bright Blue     94  104
Bright Magenta  95  105
Bright Cyan     96  106
Bright White    97  107
*/

#define COLOR_BLACK_FG 30
#define COLOR_BLACK_BG (COLOR_BLACK_FG + 0x10)

#define COLOR_RED_FG 31
#define COLOR_RED_BG (COLOR_RED_FG + 0x10)

#define COLOR_GREEN_FG 32
#define COLOR_GREEN_BG (COLOR_GREEN_FG + 0x10

#define COLOR_WHITE_FG 37
#define COLOR_WHITE_BG (COLOR_GREEN_FG + 0x10)

#define CONFIG_INI  "config.ini"
#define DEFAULT_INI "[config]\r\nAutoExit=true\r\n\r\n[patches]\r\nUnsignedManifest=true\r\nChecksumChecks=true\r\nManifestHashes=true\r\nManifestSizes=true\r\nUnrestrictCvarsAndBinds=true\r\nBlockHTTP=true\r\nresource_loadMostRecent=true\r\n"
#define STEAM_LAUNCH_URI "steam://rungameid/782330"