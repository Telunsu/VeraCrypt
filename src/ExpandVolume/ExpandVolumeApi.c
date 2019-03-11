// ExpandVolumeApi.c : Defines the exported functions for the DLL application.
//

#include "ExpandVolumeApi.h"
#include "Errors.h"
#include "Common.h"
#include "EncryptionThreadPool.h"
#include "Apidrvr.h"
#include "Log.h"
#include "Dlgcode.h"

#include "ExpandVolume.h"

BOOL bTcApiInitialized = FALSE;
#define TCAPI_CHECK_INITIALIZED(RESULT) do { if (!bTcApiInitialized) { SetLastError(TCAPI_E_NOT_INITIALIZED); return RESULT; } } while (0)

DLLEXPORT BOOL APIENTRY InitializeExpand(PTCAPI_OPTIONS options) {
    // InitOSVersionInfo();
 	InitGlobalLocks();
	//if (!EncryptionThreadPoolStart (ReadEncryptionThreadPoolFreeCpuCountLimit()))
	//{
	//	SLOG_TRACE("EncryptionThreadPoolStart return false.");
	//	set_error_debug_out(TCAPI_E_CANT_START_ENCPOOL);
	//	return FALSE;
	//}
	// 
	bTcApiInitialized = TRUE;
	return bTcApiInitialized;
}

DLLEXPORT BOOL APIENTRY LoadVCryptDriverExpand(void)
{
	int ret = 0;

	TCAPI_CHECK_INITIALIZED(0);
	init_logger("C:\\Windows\\Temp", S_QUIET);

	SLOG_INFO("LoadVCryptDriverExpand");
	ret = DriverAttach();
	if (ret != 0) {
		SLOG_INFO("DriverAttach failed.");
		return FALSE;
	}
	return TRUE;
}

DLLEXPORT BOOL APIENTRY UnloadVCryptDriverExpand(void)
{
	TCAPI_CHECK_INITIALIZED(0);
	return DriverUnload ();
}

DLLEXPORT BOOL APIENTRY ShutdownExpand(void) {
	//returns FALSE if not initialized
	TCAPI_CHECK_INITIALIZED(0);

	//  EncryptionThreadPoolStop();
	FinalizeGlobalLocks();
	return TRUE;
}

DLLEXPORT BOOL APIENTRY ExpandV(int nDosDriveNo, wchar_t *szFileName, Password VolumePassword, unsigned long long fileSize, int pim, int pkcs5, int trueCryptMode)
{
	init_logger("C:\\Windows\\Temp\\Expand\\", S_QUIET);
	SLOG_TRACE("Expand, nDosDriveNo = %d\n", nDosDriveNo);
	DataCubeExpandVolume(szFileName, &VolumePassword, pkcs5, -1, fileSize, TRUE);
	return TRUE;
}