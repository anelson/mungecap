// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#include <stdio.h>
#include <tchar.h>


#include <list>
#include <string>
#include <iostream>

#include <pcap.h>

#ifndef __STDC__
#define __STDC__ 1
#endif
#define __GNU_LIBRARY__ 1

#include "getopt.h"

