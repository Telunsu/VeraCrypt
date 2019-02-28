/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 and also from the source code of extcv, which is Copyright (c) 2009-2010 Kih-Oskh
 or Copyright (c) 2012-2013 Josef Schneider <josef@netpage.dk>

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include <stdlib.h>
#include <string.h>

#include "Tcdefs.h"

#include "Common.h"
#include "Crypto.h"
#include "Random.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Progress.h"
#include "Resource.h"

#include "InitDataArea.h"
#include "Log.h"

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

int FormatWriteBufferSize = 1024 * 1024;
static uint32 FormatSectorSize = 0;

void SetFormatSectorSize(uint32 sector_size)
{
	FormatSectorSize = sector_size;
}

int FormatNoFs (HWND hwndDlg, unsigned __int64 startSector, __int64 num_sectors, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat)
{
	int write_buf_cnt = 0;
	char sector[TC_MAX_VOLUME_SECTOR_SIZE], *write_buf;
	unsigned __int64 nSecNo = startSector;
	int retVal = 0;
	DWORD err;
	CRYPTOPP_ALIGN_DATA(16) char temporaryKey[MASTER_KEYDATA_SIZE];
	CRYPTOPP_ALIGN_DATA(16) char originalK2[MASTER_KEYDATA_SIZE];

	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;

	// Seek to start sector
	startOffset.QuadPart = startSector * FormatSectorSize;
	if (!SetFilePointerEx ((HANDLE) dev, startOffset, &newOffset, FILE_BEGIN)
		|| newOffset.QuadPart != startOffset.QuadPart)
	{
		return ERR_OS_ERROR;
	}

	write_buf = (char *)TCalloc (FormatWriteBufferSize);
	if (!write_buf)
		return ERR_OUTOFMEMORY;

	VirtualLock (temporaryKey, sizeof (temporaryKey));
	VirtualLock (originalK2, sizeof (originalK2));

	memset (sector, 0, sizeof (sector));

	// Remember the original secondary key (XTS mode) before generating a temporary one
	memcpy (originalK2, cryptoInfo->k2, sizeof (cryptoInfo->k2));

	/* Fill the rest of the data area with random data */

	if(!quickFormat)
	{
		/* Generate a random temporary key set to be used for "dummy" encryption that will fill
		the free disk space (data area) with random data.  This is necessary for plausible
		deniability of hidden volumes. */

		// Temporary master key
		if (!RandgetBytes (hwndDlg, (unsigned char *)temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE))
			goto fail;

		// Temporary secondary key (XTS mode)
		if (!RandgetBytes (hwndDlg, cryptoInfo->k2, sizeof cryptoInfo->k2, FALSE))
			goto fail;

		retVal = EAInit (cryptoInfo->ea, (unsigned char *)temporaryKey, cryptoInfo->ks);
		if (retVal != ERR_SUCCESS)
			goto fail;

		if (!EAInitMode (cryptoInfo))
		{
			retVal = ERR_MODE_INIT_FAILED;
			goto fail;
		}

		while (num_sectors--)
		{
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, (long long*)&nSecNo,
				cryptoInfo) == FALSE)
				goto fail;
		}

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, (long long*)&nSecNo, cryptoInfo))
			goto fail;
	}
	else
		nSecNo = num_sectors;

	UpdateProgressBar (nSecNo * FormatSectorSize);

	// Restore the original secondary key (XTS mode) in case NTFS format fails and the user wants to try FAT immediately
	memcpy (cryptoInfo->k2, originalK2, sizeof (cryptoInfo->k2));

	// Reinitialize the encryption algorithm and mode in case NTFS format fails and the user wants to try FAT immediately
	retVal = EAInit (cryptoInfo->ea, cryptoInfo->master_keydata, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		goto fail;
	if (!EAInitMode (cryptoInfo))
	{
		retVal = ERR_MODE_INIT_FAILED;
		goto fail;
	}

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	TCfree (write_buf);

	return 0;

fail:
	err = GetLastError();

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	TCfree (write_buf);

	SetLastError (err);
	return (retVal ? retVal : ERR_OS_ERROR);
}

int DataCubeFormatNoFs (unsigned __int64 startSector, __int64 num_sectors, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat)
{
	HWND hwndDlg = NULL;
	int write_buf_cnt = 0;
	char sector[TC_MAX_VOLUME_SECTOR_SIZE], *write_buf;
	unsigned __int64 nSecNo = startSector;
	int retVal = 0;
	DWORD err;
	CRYPTOPP_ALIGN_DATA(16) char temporaryKey[MASTER_KEYDATA_SIZE];
	CRYPTOPP_ALIGN_DATA(16) char originalK2[MASTER_KEYDATA_SIZE];

	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;

	// Seek to start sector
	startOffset.QuadPart = startSector * FormatSectorSize;
	if (!SetFilePointerEx ((HANDLE) dev, startOffset, &newOffset, FILE_BEGIN)
		|| newOffset.QuadPart != startOffset.QuadPart)
	{ 
		SLOG_ERROR("SetFilePointerEx return FALSE");
		return ERR_OS_ERROR;
	}

	write_buf = (char *)TCalloc (FormatWriteBufferSize);
	if (!write_buf)
		return ERR_OUTOFMEMORY;

	VirtualLock (temporaryKey, sizeof (temporaryKey));
	VirtualLock (originalK2, sizeof (originalK2));

	memset (sector, 0, sizeof (sector));

	// Remember the original secondary key (XTS mode) before generating a temporary one
	memcpy (originalK2, cryptoInfo->k2, sizeof (cryptoInfo->k2));

	/* Fill the rest of the data area with random data */

	if(!quickFormat)
	{
		SLOG_TRACE("quickFormat is FALSE, try to write random byte");


		/* Generate a random temporary key set to be used for "dummy" encryption that will fill
		the free disk space (data area) with random data.  This is necessary for plausible
		deniability of hidden volumes. */

		// Temporary master key
		if (!RandgetBytes (hwndDlg, (unsigned char*)temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE))
			goto fail;

		// Temporary secondary key (XTS mode)
		if (!RandgetBytes (hwndDlg, cryptoInfo->k2, sizeof cryptoInfo->k2, FALSE))
			goto fail;

		retVal = EAInit (cryptoInfo->ea, (unsigned char*)temporaryKey, cryptoInfo->ks);
		if (retVal != ERR_SUCCESS)
			goto fail;

		if (!EAInitMode (cryptoInfo))
		{
			retVal = ERR_MODE_INIT_FAILED;
			goto fail;
		}

		while (num_sectors--)
		{
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, (long long*)&nSecNo,
				cryptoInfo) == FALSE)
				goto fail;
		}

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, (long long*)&nSecNo, cryptoInfo))
			goto fail;
	}
	else
		nSecNo = num_sectors;

	// yww-: ������Ӧ��ûɶ��
	// UpdateProgressBar (nSecNo * FormatSectorSize);

	// Restore the original secondary key (XTS mode) in case NTFS format fails and the user wants to try FAT immediately
	memcpy (cryptoInfo->k2, originalK2, sizeof (cryptoInfo->k2));

	// Reinitialize the encryption algorithm and mode in case NTFS format fails and the user wants to try FAT immediately
	retVal = EAInit (cryptoInfo->ea, cryptoInfo->master_keydata, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
		goto fail;
	if (!EAInitMode (cryptoInfo))
	{
		retVal = ERR_MODE_INIT_FAILED;
		goto fail;
	}

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	TCfree (write_buf);

	return 0;

fail:
	err = GetLastError();

	burn (temporaryKey, sizeof(temporaryKey));
	burn (originalK2, sizeof(originalK2));
	VirtualUnlock (temporaryKey, sizeof (temporaryKey));
	VirtualUnlock (originalK2, sizeof (originalK2));
	TCfree (write_buf);

	SetLastError (err);
	return (retVal ? retVal : ERR_OS_ERROR);
}


BOOL WriteSector (void *dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     __int64 *nSecNo, PCRYPTO_INFO cryptoInfo)
{
	static __int32 updateTime = 0;

	(*nSecNo)++;

	memcpy (write_buf + *write_buf_cnt, sector, FormatSectorSize);
	(*write_buf_cnt) += FormatSectorSize;

	if (*write_buf_cnt == FormatWriteBufferSize && !FlushFormatWriteBuffer (dev, write_buf, write_buf_cnt, nSecNo, cryptoInfo))
		return FALSE;

	if (GetTickCount () - updateTime > 25)
	{
		if (UpdateProgressBar (*nSecNo * FormatSectorSize))
			return FALSE;

		updateTime = GetTickCount ();
	}

	return TRUE;

}


static volatile BOOL WriteThreadRunning;
static volatile BOOL WriteThreadExitRequested;
static HANDLE WriteThreadHandle;

static byte *WriteThreadBuffer;
static HANDLE WriteBufferEmptyEvent;
static HANDLE WriteBufferFullEvent;

static volatile HANDLE WriteRequestHandle;
static volatile int WriteRequestSize;
static volatile DWORD WriteRequestResult;


static void __cdecl FormatWriteThreadProc (void *arg)
{
	DWORD bytesWritten;

	SetThreadPriority (GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	while (!WriteThreadExitRequested)
	{
		if (WaitForSingleObject (WriteBufferFullEvent, INFINITE) == WAIT_FAILED)
		{
			handleWin32Error (NULL, SRC_POS);
			break;
		}

		if (WriteThreadExitRequested)
			break;

		if (!WriteFile (WriteRequestHandle, WriteThreadBuffer, WriteRequestSize, &bytesWritten, NULL))
			WriteRequestResult = GetLastError();
		else
			WriteRequestResult = ERROR_SUCCESS;

		if (!SetEvent (WriteBufferEmptyEvent))
		{
			handleWin32Error (NULL, SRC_POS);
			break;
		}
	}

	WriteThreadRunning = FALSE;
	_endthread();
}


BOOL StartFormatWriteThread ()
{
	DWORD sysErr;

	WriteBufferEmptyEvent = NULL;
	WriteBufferFullEvent = NULL;
	WriteThreadBuffer = NULL;

	WriteBufferEmptyEvent = CreateEvent (NULL, FALSE, TRUE, NULL);
	if (!WriteBufferEmptyEvent)
		goto err;

	WriteBufferFullEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!WriteBufferFullEvent)
		goto err;

	WriteThreadBuffer = (byte*)TCalloc (FormatWriteBufferSize);
	if (!WriteThreadBuffer)
	{
		SetLastError (ERROR_OUTOFMEMORY);
		goto err;
	}

	WriteThreadExitRequested = FALSE;
	WriteRequestResult = ERROR_SUCCESS;

	WriteThreadHandle = (HANDLE) _beginthread (FormatWriteThreadProc, 0, NULL);
	if ((uintptr_t) WriteThreadHandle == -1L)
		goto err;

	WriteThreadRunning = TRUE;
	return TRUE;

err:
	sysErr = GetLastError();

	if (WriteBufferEmptyEvent)
		CloseHandle (WriteBufferEmptyEvent);
	if (WriteBufferFullEvent)
		CloseHandle (WriteBufferFullEvent);
	if (WriteThreadBuffer)
		TCfree (WriteThreadBuffer);

	SetLastError (sysErr);
	return FALSE;
}


void StopFormatWriteThread ()
{
	if (WriteThreadRunning)
	{
		WaitForSingleObject (WriteBufferEmptyEvent, INFINITE);

		WriteThreadExitRequested = TRUE;
		SetEvent (WriteBufferFullEvent);

		WaitForSingleObject (WriteThreadHandle, INFINITE);
	}

	CloseHandle (WriteBufferEmptyEvent);
	CloseHandle (WriteBufferFullEvent);
	TCfree (WriteThreadBuffer);
}


BOOL FlushFormatWriteBuffer (void *dev, char *write_buf, int *write_buf_cnt, __int64 *nSecNo, PCRYPTO_INFO cryptoInfo)
{
	UINT64_STRUCT unitNo;
	DWORD bytesWritten;

	if (*write_buf_cnt == 0)
		return TRUE;

	unitNo.Value = (*nSecNo * FormatSectorSize - *write_buf_cnt) / ENCRYPTION_DATA_UNIT_SIZE;

	EncryptDataUnits ((unsigned char*)write_buf, &unitNo, *write_buf_cnt / ENCRYPTION_DATA_UNIT_SIZE, cryptoInfo);

	if (WriteThreadRunning)
	{
		if (WaitForSingleObject (WriteBufferEmptyEvent, INFINITE) == WAIT_FAILED)
			return FALSE;

		if (WriteRequestResult != ERROR_SUCCESS)
		{
			SetEvent (WriteBufferEmptyEvent);
			SetLastError (WriteRequestResult);
			return FALSE;
		}

		memcpy (WriteThreadBuffer, write_buf, *write_buf_cnt);
		WriteRequestHandle = dev;
		WriteRequestSize = *write_buf_cnt;

		if (!SetEvent (WriteBufferFullEvent))
			return FALSE;
	}
	else
	{
		if (!WriteFile ((HANDLE) dev, write_buf, *write_buf_cnt, &bytesWritten, NULL))
			return FALSE;
	}

	*write_buf_cnt = 0;
	return TRUE;
}


// Creates a volume header in memory
#if defined(_UEFI)
int DataCubeCreateVolumeHeaderInMemory(BOOL bBoot, char *header, int ea, int mode, Password *password,
	int pkcs5_prf, int pim, char *masterKeydata, PCRYPTO_INFO *retInfo,
	unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
	unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode)
#else
int DataCubeCreateVolumeHeaderInMemory (HWND hwndDlg, BOOL bBoot, char *header, int ea, int mode, Password *password,
		   int pkcs5_prf, int pim, char *masterKeydata, PCRYPTO_INFO *retInfo,
		   unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
		   unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode)
#endif // !defined(_UEFI)
{
	unsigned char *p = (unsigned char *) header;
	// static CRYPTOPP_ALIGN_DATA(16) KEY_INFO keyInfo;
	CRYPTOPP_ALIGN_DATA(16) KEY_INFO keyInfo;

	int nUserKeyLen = password? password->Length : 0;
	PCRYPTO_INFO cryptoInfo = crypto_open ();
	// static char dk[MASTER_KEYDATA_SIZE];
	char dk[MASTER_KEYDATA_SIZE];

	int x;
	int retVal = 0;
	int primaryKeyOffset;

	if (cryptoInfo == NULL)
		return ERR_OUTOFMEMORY;

	// if no PIM specified, use default value
	if (pim < 0)
		pim = 0;

	memset (header, 0, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
#if !defined(_UEFI)
	VirtualLock (&keyInfo, sizeof (keyInfo));
	VirtualLock (&dk, sizeof (dk));
#endif // !defined(_UEFI)

	/* Encryption setup */

	if (masterKeydata == NULL)
	{
		// We have no master key data (creating a new volume) so we'll use the TrueCrypt RNG to generate them

		int bytesNeeded;


		switch (mode)
		{

		default:
			bytesNeeded = EAGetKeySize (ea) * 2;	// Size of primary + secondary key(s)
		}


#if !defined(_UEFI)
		if (!RandgetBytes (hwndDlg, (unsigned char*)keyInfo.master_keydata, bytesNeeded, TRUE))
#else
		if (!RandgetBytes(keyInfo.master_keydata, bytesNeeded, TRUE))
#endif
		{
			crypto_close (cryptoInfo);
			retVal = ERR_CIPHER_INIT_WEAK_KEY;
			goto err;
		}
	}
	else
	{
		// We already have existing master key data (the header is being re-encrypted)
		memcpy (keyInfo.master_keydata, masterKeydata, MASTER_KEYDATA_SIZE);
	}

	// User key
	if (password)
	{
		memcpy (keyInfo.userKey, password->Text, nUserKeyLen);
		keyInfo.keyLength = nUserKeyLen;
		keyInfo.noIterations = get_pkcs5_iteration_count (pkcs5_prf, pim, FALSE, bBoot);
	}
	else
	{
		keyInfo.keyLength = 0;
		keyInfo.noIterations = 0;
	}

	// User selected encryption algorithm
	cryptoInfo->ea = ea;

	// User selected PRF
	cryptoInfo->pkcs5 = pkcs5_prf;
	cryptoInfo->bTrueCryptMode = FALSE;
	cryptoInfo->noIterations = keyInfo.noIterations;
	cryptoInfo->volumePim = pim;

	// Mode of operation
	cryptoInfo->mode = mode;

	// TODO(yww-): ����ȷ��RandgetBytes��û����ȫ�ֱ���Ӱ��
	// Salt for header key derivation
#if !defined(_UEFI)
	if (!RandgetBytes(hwndDlg, (unsigned char*)keyInfo.salt, PKCS5_SALT_SIZE, !bWipeMode))
#else
	if (!RandgetBytes(keyInfo.salt, PKCS5_SALT_SIZE, !bWipeMode))
#endif
	{
		crypto_close (cryptoInfo);
		retVal = ERR_CIPHER_INIT_WEAK_KEY; 
		goto err;
	}

	if (password)
	{
		// PBKDF2 (PKCS5) is used to derive primary header key(s) and secondary header key(s) (XTS) from the password/keyfiles
		switch (pkcs5_prf)
		{
		case SHA512:
			derive_key_sha512 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case SHA256:
			derive_key_sha256 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case RIPEMD160:
			derive_key_ripemd160 (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case WHIRLPOOL:
			derive_key_whirlpool (keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		case STREEBOG:
			derive_key_streebog(keyInfo.userKey, keyInfo.keyLength, keyInfo.salt,
				PKCS5_SALT_SIZE, keyInfo.noIterations, dk, GetMaxPkcs5OutSize());
			break;

		default:
			// Unknown/wrong ID
			crypto_close (cryptoInfo);
			TC_THROW_FATAL_EXCEPTION;
		}
	}
	else
	{
		// generate a random key
#if !defined(_UEFI)
		if (!RandgetBytes(hwndDlg, (unsigned char*)dk, GetMaxPkcs5OutSize(), !bWipeMode))
#else
		if (!RandgetBytes(dk, GetMaxPkcs5OutSize(), !bWipeMode))
#endif
		{
			crypto_close (cryptoInfo);
			retVal = ERR_CIPHER_INIT_WEAK_KEY; 
			goto err;
		}
	}

	/* Header setup */
	// Salt
	mputBytes (p, keyInfo.salt, PKCS5_SALT_SIZE);

	// Magic
	mputLong (p, 0x56455241);

	// Header version
	mputWord (p, VOLUME_HEADER_VERSION);
	cryptoInfo->HeaderVersion = VOLUME_HEADER_VERSION;

	// Required program version to handle this volume
	mputWord (p, requiredProgramVersion != 0 ? requiredProgramVersion : TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION);

	// CRC of the master key data
	x = GetCrc32((unsigned char*)keyInfo.master_keydata, MASTER_KEYDATA_SIZE);
	mputLong (p, x);

	// Reserved fields
	p += 2 * 8;

	// Size of hidden volume (if any)
	cryptoInfo->hiddenVolumeSize = hiddenVolumeSize;
	mputInt64 (p, cryptoInfo->hiddenVolumeSize);

	cryptoInfo->hiddenVolume = cryptoInfo->hiddenVolumeSize != 0;

	// Volume size
	cryptoInfo->VolumeSize.Value = volumeSize;
	mputInt64 (p, volumeSize);

	// Encrypted area start
	cryptoInfo->EncryptedAreaStart.Value = encryptedAreaStart;
	mputInt64 (p, encryptedAreaStart);

	// Encrypted area size
	cryptoInfo->EncryptedAreaLength.Value = encryptedAreaLength;
	mputInt64 (p, encryptedAreaLength);

	// Flags
	cryptoInfo->HeaderFlags = headerFlags;
	mputLong (p, headerFlags);

	// Sector size
	if (sectorSize < TC_MIN_VOLUME_SECTOR_SIZE
		|| sectorSize > TC_MAX_VOLUME_SECTOR_SIZE
		|| sectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
	{
		crypto_close (cryptoInfo);
		SLOG_ERROR("Throw fatal exception.");
		TC_THROW_FATAL_EXCEPTION;
	}

	cryptoInfo->SectorSize = sectorSize;
	mputLong (p, sectorSize);

	// CRC of the header fields
	x = GetCrc32 ((unsigned char*)header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
	p = (unsigned char*)header + TC_HEADER_OFFSET_HEADER_CRC;
	mputLong (p, x);

	// The master key data
	memcpy (header + HEADER_MASTER_KEYDATA_OFFSET, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);


	/* Header encryption */

	switch (mode)
	{

	default:
		// The secondary key (if cascade, multiple concatenated)
		memcpy (cryptoInfo->k2, dk + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
		primaryKeyOffset = 0;
	}

	retVal = EAInit (cryptoInfo->ea, (unsigned char*)dk + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
	{
		crypto_close (cryptoInfo);
		goto err;
	}

	// Mode of operation
	if (!EAInitMode (cryptoInfo))
	{
		crypto_close (cryptoInfo);
		retVal = ERR_OUTOFMEMORY;
		goto err;
	}


	// Encrypt the entire header (except the salt)
	EncryptBuffer ((unsigned char*)header + HEADER_ENCRYPTED_DATA_OFFSET,
		HEADER_ENCRYPTED_DATA_SIZE,
		cryptoInfo);


	/* cryptoInfo setup for further use (disk format) */

	// Init with the master key(s)
	retVal = EAInit (cryptoInfo->ea, (unsigned char*)keyInfo.master_keydata + primaryKeyOffset, cryptoInfo->ks);
	if (retVal != ERR_SUCCESS)
	{
		crypto_close (cryptoInfo);
		goto err;
	}

	memcpy (cryptoInfo->master_keydata, keyInfo.master_keydata, MASTER_KEYDATA_SIZE);

	switch (cryptoInfo->mode)
	{

	default:
		// The secondary master key (if cascade, multiple concatenated)
		memcpy (cryptoInfo->k2, keyInfo.master_keydata + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
	}

	// Mode of operation
	if (!EAInitMode (cryptoInfo))
	{
		crypto_close (cryptoInfo);
		retVal = ERR_OUTOFMEMORY;
		goto err;
	}


#ifdef VOLFORMAT
	// yww-: showKeys = false & bBoot = False
	// if (!bInPlaceEncNonSys && (showKeys || (bBoot && !masterKeydata)))
	if (FALSE)
	{
		BOOL dots3 = FALSE;
		int i, j;

		j = EAGetKeySize (ea);

		if (j > NBR_KEY_BYTES_TO_DISPLAY)
		{
			dots3 = TRUE;
			j = NBR_KEY_BYTES_TO_DISPLAY;
		}

		MasterKeyGUIView[0] = 0;
		for (i = 0; i < j; i++)
		{
			wchar_t tmp2[8] = {0};
			StringCchPrintfW (tmp2, ARRAYSIZE(tmp2), L"%02X", (int) (unsigned char) keyInfo.master_keydata[i + primaryKeyOffset]);
			StringCchCatW (MasterKeyGUIView, ARRAYSIZE(MasterKeyGUIView), tmp2);
		}

		HeaderKeyGUIView[0] = 0;
		for (i = 0; i < NBR_KEY_BYTES_TO_DISPLAY; i++)
		{
			wchar_t tmp2[8];
			StringCchPrintfW (tmp2, ARRAYSIZE(tmp2), L"%02X", (int) (unsigned char) dk[primaryKeyOffset + i]);
			StringCchCatW (HeaderKeyGUIView, ARRAYSIZE(HeaderKeyGUIView), tmp2);
		}

		if (dots3)
		{
			DisplayPortionsOfKeys (hHeaderKey, hMasterKey, HeaderKeyGUIView, MasterKeyGUIView, !showKeys);
		}
		else
		{
			SendMessage (hMasterKey, WM_SETTEXT, 0, (LPARAM) MasterKeyGUIView);
			SendMessage (hHeaderKey, WM_SETTEXT, 0, (LPARAM) HeaderKeyGUIView);
		}
	}
#endif	// #ifdef VOLFORMAT

	*retInfo = cryptoInfo;

err:
	burn (dk, sizeof(dk));
	burn (&keyInfo, sizeof (keyInfo));
#if !defined(_UEFI)
	VirtualUnlock (&keyInfo, sizeof (keyInfo));
	VirtualUnlock (&dk, sizeof (dk));
#endif // !defined(_UEFI)

	return 0;
}
