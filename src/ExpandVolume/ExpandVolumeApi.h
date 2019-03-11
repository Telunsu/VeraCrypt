// Instead of using conditional __declspec(dllexport)/dllimport way of defining exports
// we define those unconditionally. This library is supposed to be used with 
// LoadLibrary/GetProcAddress way, so no importing required.

#ifndef EXPANDER_API_H
#define EXPANDER_API_H

#include "Api/targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <winver.h>

#include "Options.h"
#include "Password.h"

#define DLLEXPORT __declspec(dllexport)

#ifdef __cplusplus
extern "C" {
#endif

	DLLEXPORT BOOL APIENTRY InitializeExpand(PTCAPI_OPTIONS options);
	DLLEXPORT BOOL APIENTRY LoadVCryptDriverExpand(void);
	DLLEXPORT BOOL APIENTRY UnloadVCryptDriverExpand(void);
	DLLEXPORT BOOL APIENTRY ShutdownExpand(void);

	DLLEXPORT BOOL APIENTRY ExpandV(int nDosDriveNo, wchar_t *szFileName, Password VolumePassword, unsigned long long fileSize, int pim, int pkcs5, int trueCryptMode);
	
#ifdef __cplusplus
}
#endif

#endif