// Api.c : Defines the exported functions for the DLL application.
//

#include "Api.h"
#include "Errors.h"
#include "Common.h"
#include "EncryptionThreadPool.h"
#include "Apidrvr.h"
#include "Mount.h"
#include "Dlgcode.h"
#include "Log.h"

BOOL bTcApiInitialized = FALSE;

#define TCAPI_CHECK_INITIALIZED(RESULT) do { if (!bTcApiInitialized) { SetLastError(TCAPI_E_NOT_INITIALIZED); return RESULT; } } while (0)

DLLEXPORT BOOL APIENTRY Initialize(PTCAPI_OPTIONS options) {
	init_logger("C:\\Windows\\Temp\\", S_QUIET);

	InitOSVersionInfo();

	if (IsTrueCryptInstallerRunning()) {
		SLOG_TRACE("IsTrueCryptInstallerRunning return true");
		set_error_debug_out(TCAPI_E_TC_INSTALLER_RUNNING);
		return FALSE;
	}

	if (!options || !ApplyOptions(options)) {
		SLOG_TRACE("options is null or ApplyOptions return false.");
		//TODO: Doc -> See GetLastError()
		return FALSE;
	}

	InitGlobalLocks();
	if (!EncryptionThreadPoolStart (ReadEncryptionThreadPoolFreeCpuCountLimit()))
	{
		SLOG_TRACE("EncryptionThreadPoolStart return false.");
		set_error_debug_out(TCAPI_E_CANT_START_ENCPOOL);
		return FALSE;
	}

	bTcApiInitialized = TRUE;
	return bTcApiInitialized;
}

DLLEXPORT BOOL APIENTRY Shutdown(void) {
	//returns FALSE if not initialized
	TCAPI_CHECK_INITIALIZED(0);

	EncryptionThreadPoolStop();
	FinalizeGlobalLocks();
	return TRUE;
}

DLLEXPORT BOOL APIENTRY LoadTrueCryptDriver(void)
{
	TCAPI_CHECK_INITIALIZED(0);
	return DriverAttach ();
}

DLLEXPORT BOOL APIENTRY UnloadTrueCryptDriver(void)
{
	TCAPI_CHECK_INITIALIZED(0);
	return DriverUnload ();
}

DLLEXPORT BOOL APIENTRY MountV(int nDosDriveNo, wchar_t *szFileName, Password VolumePassword, int pim, int pkcs5, int trueCryptMode)
{
	TCAPI_CHECK_INITIALIZED(0);

	return DataCubeMount(24, szFileName, L"XYZ", VolumePassword, -1);
}
