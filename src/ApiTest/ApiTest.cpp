// ApiTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "..\Common\Options.h"
#include "..\Common\Password.h"

using namespace std;

typedef BOOL (STDMETHODCALLTYPE *PINITIALIZE)(PTCAPI_OPTIONS options);
typedef BOOL (STDMETHODCALLTYPE *PSHUTDOWN)();
typedef BOOL (STDMETHODCALLTYPE *PLOAD_TC_DRIVER)();
typedef BOOL (STDMETHODCALLTYPE *PUNLOAD_TC_DRIVER)();
typedef BOOL (STDMETHODCALLTYPE *PMOUNT)(int nDosDriveNo, wchar_t *szFileName, wchar_t *label, Password VolumePassword, int pim, int pkcs5, int trueCryptMode);
typedef BOOL (STDMETHODCALLTYPE *PCREATE)(int nDosDriveNo, wchar_t *szFileName, Password VolumePassword, unsigned long long size, int pim, int pkcs5, int trueCryptMode);
typedef BOOL (STDMETHODCALLTYPE *PUNMOUNT)(int nDosDriveNo);

typedef BOOL (STDMETHODCALLTYPE *PINITIALIZEEXPAND)(PTCAPI_OPTIONS options);
typedef BOOL (STDMETHODCALLTYPE *PSHUTDOWNEXPAND)();
typedef BOOL (STDMETHODCALLTYPE *PLOAD_TC_DRIVER_EXPAND)();
typedef BOOL (STDMETHODCALLTYPE *PUNLOAD_TC_DRIVER_EXPAND)();
typedef BOOL (STDMETHODCALLTYPE *PEXPAND)(int nDosDriveNo, wchar_t *szFileName, Password VolumePassword, unsigned long long fileSize, int pim, int pkcs5, int trueCryptMode);

class ApiTest {
private:
	HMODULE hApiDll;
	HMODULE hExpandApiDll;
	PLOAD_TC_DRIVER LoadTrueCryptDriver;
	PUNLOAD_TC_DRIVER UnloadTrueCryptDriver;
	PLOAD_TC_DRIVER_EXPAND LoadTrueCryptExpandDriver;
	PUNLOAD_TC_DRIVER_EXPAND UnloadTrueCryptExpandDriver;
	PINITIALIZE Initialize;
	PINITIALIZEEXPAND InitializeExpand;
	PSHUTDOWN Shutdown;
	PSHUTDOWNEXPAND ShutdownExpand;
	PMOUNT Mount;
	PCREATE Create;
	PEXPAND Expand;
	PUNMOUNT Unmount;


protected:
	BOOL LoadTrueCryptApi(LPCTSTR path, LPCTSTR expand_dll_path) {
		wcout << "Loading TrueCrypt API dll from " << path << endl;
		hApiDll = LoadLibrary(path);
		if (!hApiDll) {
			cout << "Error loading TrueCrypt API dll: " << GetLastError() << endl;
		} else {
			cout << "Loaded successfully" << endl;
		}

		wcout << "Loading TrueCrypt Expand API dll from " << expand_dll_path << endl;
		hExpandApiDll = LoadLibrary(expand_dll_path);
		if (!hExpandApiDll) {
			cout << "Error loading TrueCrypt Expand API dll: " << GetLastError() << endl;
		} else {
			cout << "Loaded successfully" << endl;
		}

		return (BOOL) hApiDll && (BOOL) hExpandApiDll;
	}

	BOOL UnloadTrueCryptApi() {
		cout << "Unloading TrueCrypt API dll" << endl;
		if (!hApiDll) {
			cout << "TrueCryptApi dll has not been loaded" << endl;
			return FALSE;
		}

		if (FreeLibrary(hApiDll)) {
			hApiDll = NULL;
			cout << "Unloaded\n";
		} else {
			cout << "Error unloading TrueCrypt API dll: " << GetLastError() << endl;
			return FALSE;
		}

		cout << "Unloading TrueCrypt Expand API dll" << endl;
		if (!hExpandApiDll) {
			cout << "TrueCryptApi dll has not been loaded" << endl;
			return FALSE;
		}

		if (FreeLibrary(hExpandApiDll)) {
			hExpandApiDll = NULL;
			cout << "Unloaded\n";
		} else {
			cout << "Error unloading TrueCrypt Expand API dll: " << GetLastError() << endl;
			return FALSE;
		}

		return TRUE;
	}

	BOOL GetApiAddresses() {
		cout << "Getting API addresses" << endl;
		if (!hApiDll) {
			cout << "TrueCryptApi dll has not been initialized" << endl;
			return FALSE;
		}

		if (!hExpandApiDll) {
			cout << "TrueCryptApi dll has not been initialized" << endl;
			return FALSE;
		}

		LoadProcAddress((FARPROC *)&Initialize, "Initialize");
		LoadProcAddress((FARPROC *)&Shutdown, "Shutdown");
		LoadProcAddress((FARPROC *)&LoadTrueCryptDriver, "LoadVCryptDriver");
		LoadProcAddress((FARPROC *)&UnloadTrueCryptDriver, "UnloadVCryptDriver");
		LoadProcAddress((FARPROC *)&Mount, "MountV");
		LoadProcAddress((FARPROC *)&Create, "CreateV");
		LoadProcAddress((FARPROC *)&Unmount, "UnmountV");

		LoadExpandProcAddress((FARPROC *)&InitializeExpand, "InitializeExpand");
		LoadExpandProcAddress((FARPROC *)&ShutdownExpand, "ShutdownExpand");
		LoadExpandProcAddress((FARPROC *)&LoadTrueCryptExpandDriver, "LoadVCryptDriverExpand");
		LoadExpandProcAddress((FARPROC *)&UnloadTrueCryptExpandDriver, "UnloadVCryptDriverExpand");
		LoadExpandProcAddress((FARPROC *)&Expand, "Expand");

		return TRUE;
	}

	void LoadProcAddress(FARPROC *proc, char *name) {
		*proc = GetProcAddress(hApiDll, name);
		if (!proc) {
			cout << "Error getting address of " << name << ": " << GetLastError() << endl;
			return;
		} else {
			cout << name << " loaded at: " << proc << endl;
		}
	}

	void LoadExpandProcAddress(FARPROC *proc, char *name) {
		*proc = GetProcAddress(hExpandApiDll, name);
		if (!proc) {
			cout << "Error getting address of " << name << ": " << GetLastError() << endl;
			return;
		} else {
			cout << name << " loaded at: " << proc << endl;
		}
	}

	void RunInitialize() {
		{
			PTCAPI_OPTIONS pOptions;
			int numOptions = 6;

			DWORD memSize = sizeof TCAPI_OPTIONS + (sizeof TCAPI_OPTION * numOptions);

			pOptions = (PTCAPI_OPTIONS) malloc(memSize);
			memset(pOptions, 0, memSize);
		
			pOptions->Options[0].OptionId = TC_OPTION_PRESERVE_TIMESTAMPS;
			pOptions->Options[0].OptionValue = TRUE;

			pOptions->Options[1].OptionId = TC_OPTION_CACHE_PASSWORDS;
			pOptions->Options[1].OptionValue = TRUE;

			pOptions->Options[2].OptionId = TC_OPTION_MOUNT_READONLY;
			pOptions->Options[2].OptionValue = TRUE;

			pOptions->Options[3].OptionId = TC_OPTION_MOUNT_REMOVABLE;
			pOptions->Options[3].OptionValue = TRUE;

			pOptions->Options[4].OptionId = TC_OPTION_DRIVER_PATH;
			pOptions->Options[4].OptionValue = NULL; //(DWORD) &"D:\\Projects\\Active\\truecrypt-x64.sys";

			pOptions->Options[5].OptionId = TC_OPTION_WIPE_CACHE_ON_EXIT;
			pOptions->Options[5].OptionValue = TRUE;
		
			pOptions->NumberOfOptions = numOptions;

			cout << "Initializing" << endl;
			BOOL res = Initialize(pOptions);
		
			free(pOptions);
			cout << "Initialize returned " << res << endl;
		}
		
		{
			PTCAPI_OPTIONS pOptions;
			int numOptions = 6;

			DWORD memSize = sizeof TCAPI_OPTIONS + (sizeof TCAPI_OPTION * numOptions);

			pOptions = (PTCAPI_OPTIONS) malloc(memSize);
			memset(pOptions, 0, memSize);
		
			pOptions->Options[0].OptionId = TC_OPTION_PRESERVE_TIMESTAMPS;
			pOptions->Options[0].OptionValue = TRUE;

			pOptions->Options[1].OptionId = TC_OPTION_CACHE_PASSWORDS;
			pOptions->Options[1].OptionValue = TRUE;

			pOptions->Options[2].OptionId = TC_OPTION_MOUNT_READONLY;
			pOptions->Options[2].OptionValue = TRUE;

			pOptions->Options[3].OptionId = TC_OPTION_MOUNT_REMOVABLE;
			pOptions->Options[3].OptionValue = TRUE;

			pOptions->Options[4].OptionId = TC_OPTION_DRIVER_PATH;
			pOptions->Options[4].OptionValue = NULL; //(DWORD) &"D:\\Projects\\Active\\truecrypt-x64.sys";

			pOptions->Options[5].OptionId = TC_OPTION_WIPE_CACHE_ON_EXIT;
			pOptions->Options[5].OptionValue = TRUE;
		
			pOptions->NumberOfOptions = numOptions;

			cout << "Initializing" << endl;
			BOOL res = InitializeExpand(pOptions);
		
			free(pOptions);
			cout << "Initialize returned " << res << endl;
		}
	}

	void RunShutdown() {
		cout << "Unloading driver" << endl;
		BOOL res = UnloadTrueCryptDriver();
		cout << "UnloadTrueCryptDriver returned " << res << endl;
		res = UnloadTrueCryptExpandDriver();
		cout << "UnloadTrueCryptExpandDriver returned " << res << endl;


		cout << "Shutting down" << endl;
		res = Shutdown();
		cout << "Shutdown returned " << res << endl;

		res = ShutdownExpand();
		cout << "Shutdown returned " << res << endl;
	}

	void RunMount() {
		Password pass;
		const char *passString = "0123456789";
		memset(&pass, 0, sizeof pass);
		
		pass.Length = strlen(passString);
		strcpy ((char *) &pass.Text[0], passString);

		cout << "Mounting volume" << endl;

		BOOL res = Mount(24, L"D:\\vera_crypt\\vcd\\test_15.vcd", L"YWW", pass, -1, 0, 1);

		cout << "Volume mount result: " << res << endl;
	}

	void RunCreate() {
		Password pass;
		const char *passString = "0123456789";
		memset(&pass, 0, sizeof pass);
		
		pass.Length = strlen(passString);
		strcpy ((char *) &pass.Text[0], passString);

		cout << "Create volume" << endl;

		BOOL res = Create(24, L"D:\\vera_crypt\\vcd\\test_15.vcd", pass, 1, -1, 0, 1);

		cout << "Volume Create result: " << res << endl;
	}

	void RunExpand() {
		cout << "Expand volume" << endl;

		Password pass;
		const char *passString = "0123456789";
		memset(&pass, 0, sizeof pass);
		
		pass.Length = strlen(passString);
		strcpy ((char *) &pass.Text[0], passString);

		BOOL res = Expand(24, L"D:\\vera_crypt\\vcd\\test_15.vcd", pass, 2, -1, 1, 1);

		cout << "Volume Expand result: " << res << endl;
	}

	void RunUnmount() {
		cout << "Unmount volume" << endl;

		BOOL res = Unmount(24);

		cout << "Volume unmount result: " << res << endl;
	}

public:
	void run() {
		if (!LoadTrueCryptApi("DataCubeVCApi64.dll", "DataCubeExpandVolumeApi64.dll")) return;
		if (GetApiAddresses()) {
			RunInitialize();

			cout << "Loading TrueCrypt Driver" << endl;
			int res = LoadTrueCryptDriver();
			if (res == 0) {
				cout << "Error loading TrueCrypt driver: " << hex << GetLastError() << endl;
			} else {
				cout << "LoadTrueCryptDriver version: " << hex << res << endl;
			}

			cout << "Loading TrueCrypt Expand Driver" << endl;
			int expand_res = LoadTrueCryptExpandDriver();
			if (expand_res == 0) {
				cout << "Error loading TrueCrypt Expand driver: " << hex << GetLastError() << endl;
			} else {
				cout << "LoadTrueCryptDriver Expand version: " << hex << expand_res << endl;
			}

			int action = 1;
			if (action == 0) {
			    RunCreate();
			    RunMount();
			} else if (action == 1) {
		        RunExpand();
			} else if (action == 2) {
				RunUnmount();
			}

			RunShutdown();
		}
		UnloadTrueCryptApi();
	}
};

int _tmain(int argc, _TCHAR* argv[])
{
	ApiTest *apiTest = new ApiTest();
	apiTest->run();
 	delete apiTest;
	//// cin.get();
	//while(TRUE) { Sleep(1000); }
	return 0;
}

