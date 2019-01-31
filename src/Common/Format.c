/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
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
#include "Fat.h"
#include "Format.h"
#include "Random.h"
#include "Volumes.h"

#include "Apidrvr.h"
#include "Dlgcode.h"
#include "Language.h"
#include "Progress.h"
#include "Resource.h"
#include "Format/FormatCom.h"
#include "Format/Tcformat.h"
#include "Pkcs5.h"
#include "Crc.h"

#include <Strsafe.h>

#include "Log.h"

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

int FormatWriteBufferSize = 1024 * 1024;
static uint32 FormatSectorSize = 0;


uint64 GetVolumeDataAreaSize (BOOL hiddenVolume, uint64 volumeSize)
{
	uint64 reservedSize;

	if (hiddenVolume)
	{
		// Reserve free space at the end of the host filesystem. FAT file system fills the last sector with
		// zeroes (marked as free; observed when quick format was performed using the OS format tool).
		// Therefore, when the outer volume is mounted with hidden volume protection, such write operations
		// (e.g. quick formatting the outer volume filesystem as FAT) would needlessly trigger hidden volume
		// protection.

#if TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE > 4096
#	error	TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE too large for very small volumes. Revise the code.
#endif

#if TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH < TC_MAX_VOLUME_SECTOR_SIZE
#	error	TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH too small.
#endif

		if (volumeSize < TC_VOLUME_SMALL_SIZE_THRESHOLD)
			reservedSize = TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE;
		else
			reservedSize = TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH; // Ensure size of a hidden volume larger than TC_VOLUME_SMALL_SIZE_THRESHOLD is a multiple of the maximum supported sector size
	}
	else
	{
		reservedSize = TC_TOTAL_VOLUME_HEADERS_SIZE;
	}

	if (volumeSize < reservedSize)
		return 0;

	return volumeSize - reservedSize;
}


int TCFormatVolume (volatile FORMAT_VOL_PARAMETERS *volParams)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo = NULL;
	HANDLE dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	unsigned __int64 num_sectors, startSector;
	fatparams ft;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	BOOL bInstantRetryOtherFilesys = FALSE;
	WCHAR dosDev[TC_MAX_PATH] = { 0 };
	WCHAR devName[MAX_PATH] = { 0 };
	int driveLetter = -1;
	WCHAR deviceName[MAX_PATH];
	uint64 dataOffset, dataAreaSize;
	LARGE_INTEGER offset;
	BOOL bFailedRequiredDASD = FALSE;
	HWND hwndDlg = volParams->hwndDlg;

	FormatSectorSize = volParams->sectorSize;

	SLOG_TRACE("[TCFormatVolume] TCFormatVolume Mark 1 ================");
	if (FormatSectorSize < TC_MIN_VOLUME_SECTOR_SIZE
		|| FormatSectorSize > TC_MAX_VOLUME_SECTOR_SIZE
		|| FormatSectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
	{
		SLOG_TRACE("[TCFormatVolume] SECTOR_SIZE_UNSUPPORTED");
		// Error ("SECTOR_SIZE_UNSUPPORTED", hwndDlg);
		return ERR_DONT_REPORT;
	}

	/* WARNING: Note that if Windows fails to format the volume as NTFS and the volume size is
	less than the maximum FAT size, the user is asked within this function whether he wants to instantly
	retry FAT format instead (to avoid having to re-create the whole container again). If the user
	answers yes, some of the input parameters are modified, the code below 'begin_format' is re-executed
	and some destructive operations that were performed during the first attempt must be (and are) skipped.
	Therefore, whenever adding or modifying any potentially destructive operations below 'begin_format',
	determine whether they (or their portions) need to be skipped during such a second attempt; if so,
	use the 'bInstantRetryOtherFilesys' flag to skip them. */

	if (volParams->hiddenVol)
	{
		SLOG_TRACE("[TCFormatVolume] TCFormatVolume Mark 2 ================");
		dataOffset = volParams->hiddenVolHostSize - TC_VOLUME_HEADER_GROUP_SIZE - volParams->size;
	}
	else
	{
		SLOG_TRACE("[TCFormatVolume] TCFormatVolume Mark 3 ================");
		if (volParams->size <= TC_TOTAL_VOLUME_HEADERS_SIZE) {
		    SLOG_TRACE("[TCFormatVolume] volParams->size <= TC_TOTAL_VOLUME_HEADERS_SIZE");
			SLOG_TRACE("volParams->size = %llu, TC_TOTAL_VOLUME_HEADERS_SIZE = %llu", volParams->size, TC_TOTAL_VOLUME_HEADERS_SIZE);

			return ERR_VOL_SIZE_WRONG;
		}

		dataOffset = TC_VOLUME_DATA_OFFSET;
	}

	dataAreaSize = GetVolumeDataAreaSize (volParams->hiddenVol, volParams->size);

	num_sectors = dataAreaSize / FormatSectorSize;

	if (volParams->bDevice)
	{
		StringCchCopyW (deviceName, ARRAYSIZE(deviceName), volParams->volumePath);

		driveLetter = GetDiskDeviceDriveLetter (deviceName);
	}

	VirtualLock (header, sizeof (header));

	SLOG_TRACE("[TCFormatVolume] TCFormatVolume Mark 4 ================");
	nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
				     header,
				     volParams->ea,
					 FIRST_MODE_OF_OPERATION_ID,
				     volParams->password,
				     volParams->pkcs5,
					  volParams->pim,
					 NULL,
				     &cryptoInfo,
					 dataAreaSize,
					 volParams->hiddenVol ? dataAreaSize : 0,
					 dataOffset,
					 dataAreaSize,
					 0,
					 volParams->headerFlags,
					 FormatSectorSize,
					 FALSE);

	/* cryptoInfo sanity check to make Coverity happy eventhough it can't be NULL if nStatus = 0 */
	if ((nStatus != 0) || !cryptoInfo)
	{
	    SLOG_TRACE("[TCFormatVolume] nStatus = %d", nStatus);

		burn (header, sizeof (header));
		VirtualUnlock (header, sizeof (header));
		return nStatus? nStatus : ERR_OUTOFMEMORY;
	}

begin_format:

	if (volParams->bDevice)
	{
		/* Device-hosted volume */

		DWORD dwResult;
		int nPass;

		if (FakeDosNameForDevice (volParams->volumePath, dosDev, sizeof(dosDev), devName, sizeof(devName), FALSE) != 0)
			return ERR_OS_ERROR;

		if (IsDeviceMounted (devName))
		{
	        SLOG_TRACE("[TCFormatVolume] begin_format, IsDeviceMounted return true.");

			if ((dev = DismountDrive (devName, volParams->volumePath)) == INVALID_HANDLE_VALUE)
			{
	            SLOG_TRACE("[TCFormatVolume] begin_format, FORMAT_CANT_DISMOUNT_FILESYS.");

				Error ("FORMAT_CANT_DISMOUNT_FILESYS", hwndDlg);
				nStatus = ERR_DONT_REPORT;
				goto error;
			}

			/* Gain "raw" access to the partition (it contains a live filesystem and the filesystem driver
			would otherwise prevent us from writing to hidden sectors). */

			if (!DeviceIoControl (dev,
				FSCTL_ALLOW_EXTENDED_DASD_IO,
				NULL,
				0,
				NULL,
				0,
				&dwResult,
				NULL))
			{
	            SLOG_TRACE("[TCFormatVolume] begin_format, DeviceIoControl return false.");

				bFailedRequiredDASD = TRUE;
			}
		}
		else if (IsOSAtLeast (WIN_VISTA) && driveLetter == -1)
		{
			// Windows Vista doesn't allow overwriting sectors belonging to an unformatted partition
			// to which no drive letter has been assigned under the system. This problem can be worked
			// around by assigning a drive letter to the partition temporarily.

			wchar_t szDriveLetter[] = { L'A', L':', 0 };
			wchar_t rootPath[] = { L'A', L':', L'\\', 0 };
			wchar_t uniqVolName[MAX_PATH+1] = { 0 };
			int tmpDriveLetter = -1;
			BOOL bResult = FALSE;

			tmpDriveLetter = GetFirstAvailableDrive ();

			if (tmpDriveLetter != -1)
			{
				rootPath[0] += (wchar_t) tmpDriveLetter;
				szDriveLetter[0] += (wchar_t) tmpDriveLetter;

				if (DefineDosDevice (DDD_RAW_TARGET_PATH, szDriveLetter, volParams->volumePath))
				{
					bResult = GetVolumeNameForVolumeMountPoint (rootPath, uniqVolName, MAX_PATH);

					DefineDosDevice (DDD_RAW_TARGET_PATH|DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE,
						szDriveLetter,
						volParams->volumePath);

					if (bResult
						&& SetVolumeMountPoint (rootPath, uniqVolName))
					{
						// The drive letter can be removed now
						DeleteVolumeMountPoint (rootPath);
					}
				}
			}
		}

		// For extra safety, we will try to gain "raw" access to the partition. Note that this should actually be
		// redundant because if the filesystem was mounted, we already tried to obtain DASD above. If we failed,
		// bFailedRequiredDASD was set to TRUE and therefore we will perform pseudo "quick format" below. However,
		// for extra safety, in case IsDeviceMounted() failed to detect a live filesystem, we will blindly
		// send FSCTL_ALLOW_EXTENDED_DASD_IO (possibly for a second time) without checking the result.

		DeviceIoControl (dev,
			FSCTL_ALLOW_EXTENDED_DASD_IO,
			NULL,
			0,
			NULL,
			0,
			&dwResult,
			NULL);

	    SLOG_TRACE("[TCFormatVolume] DeviceIoControl return false.");

		// If DASD is needed but we failed to obtain it, perform open - 'quick format' - close - open
		// so that the filesystem driver does not prevent us from formatting hidden sectors.
		for (nPass = (bFailedRequiredDASD ? 0 : 1); nPass < 2; nPass++)
		{
			int retryCount;

			retryCount = 0;

			// Try exclusive access mode first
			// Note that when exclusive access is denied, it is worth retrying (usually succeeds after a few tries).
			while (dev == INVALID_HANDLE_VALUE && retryCount++ < EXCL_ACCESS_MAX_AUTO_RETRIES)
			{
				dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

				if (retryCount > 1)
					Sleep (EXCL_ACCESS_AUTO_RETRY_DELAY);
			}

			if (dev == INVALID_HANDLE_VALUE)
			{
				// Exclusive access denied -- retry in shared mode
				dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
				if (dev != INVALID_HANDLE_VALUE)
				{
	                SLOG_TRACE("[TCFormatVolume] Exclusive access denied -- retry in shared mode.");
					if (!volParams->bForceOperation && (Silent || (IDNO == MessageBoxW (volParams->hwndDlg, GetString ("DEVICE_IN_USE_FORMAT"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2))))
					{
						nStatus = ERR_DONT_REPORT;
						goto error;
					}
				}
				else
				{
	                SLOG_TRACE("[TCFormatVolume] Exclusive access denied -- retry in shared mode.");
					handleWin32Error (volParams->hwndDlg, SRC_POS);
					Error ("CANT_ACCESS_VOL", hwndDlg);
					nStatus = ERR_DONT_REPORT;
					goto error;
				}
			}

			if (volParams->hiddenVol || bInstantRetryOtherFilesys)
				break;	// The following "quick format" operation would damage the outer volume

			if (nPass == 0)
			{
				char buf [2 * TC_MAX_VOLUME_SECTOR_SIZE];
				DWORD bw;

				// Perform pseudo "quick format" so that the filesystem driver does not prevent us from
				// formatting hidden sectors
				memset (buf, 0, sizeof (buf));

				if (!WriteFile (dev, buf, sizeof (buf), &bw, NULL))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}

				FlushFileBuffers (dev);
				CloseHandle (dev);
				dev = INVALID_HANDLE_VALUE;
			}
		}

		if (DeviceIoControl (dev, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwResult, NULL))
		{
			Error ("FORMAT_CANT_DISMOUNT_FILESYS", hwndDlg);
			nStatus = ERR_DONT_REPORT;
			goto error;
		}
	}
	else
	{
	    SLOG_TRACE("[TCFormatVolume] DFile-hosted volume.");

		/* File-hosted volume */

		dev = CreateFile (volParams->volumePath, GENERIC_READ | GENERIC_WRITE,
			(volParams->hiddenVol || bInstantRetryOtherFilesys) ? (FILE_SHARE_READ | FILE_SHARE_WRITE) : 0,
			NULL, (volParams->hiddenVol || bInstantRetryOtherFilesys) ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
	        SLOG_TRACE("[TCFormatVolume] CreateFile return invalid handle.");

			nStatus = ERR_OS_ERROR;
			goto error;
		}

		DisableFileCompression (dev);

		if (!volParams->hiddenVol && !bInstantRetryOtherFilesys)
		{
			LARGE_INTEGER volumeSize;
			volumeSize.QuadPart = dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

			if (volParams->sparseFileSwitch && volParams->quickFormat)
			{
				// Create as sparse file container
				DWORD tmp;
				SLOG_TRACE("Create as sparse file container, control_code = %lu", FSCTL_SET_SPARSE);

				if (!DeviceIoControl (dev, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &tmp, NULL))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}
			}

			SLOG_TRACE("volumeSize= %lu, FILE_BEGIN = %ld", volumeSize, FILE_BEGIN);

			// Preallocate the file
			if (!SetFilePointerEx (dev, volumeSize, NULL, FILE_BEGIN)
				|| !SetEndOfFile (dev)
				|| SetFilePointer (dev, 0, NULL, FILE_BEGIN) != 0)
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}
	}

	if (volParams->hiddenVol && !volParams->bDevice && bPreserveTimestamp)
	{
		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			bTimeStampValid = FALSE;
		else
			bTimeStampValid = TRUE;
	}

	if (volParams->hwndDlg && volParams->bGuiMode) KillTimer (volParams->hwndDlg, TIMER_ID_RANDVIEW);

	/* Volume header */

	// Hidden volume setup
	if (volParams->hiddenVol)
	{
		LARGE_INTEGER headerOffset;

		// Check hidden volume size
		if (volParams->hiddenVolHostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE || volParams->hiddenVolHostSize > TC_MAX_HIDDEN_VOLUME_HOST_SIZE)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}

		// Seek to hidden volume header location

		headerOffset.QuadPart = TC_HIDDEN_VOLUME_HEADER_OFFSET;

		if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}
	}
	else if (bInstantRetryOtherFilesys)
	{
		// The previous file system format failed and the user wants to try again with a different file system.
		// The volume header had been written successfully so we need to seek to the byte after the header.

		LARGE_INTEGER offset;
		offset.QuadPart = TC_VOLUME_DATA_OFFSET;
		if (!SetFilePointerEx ((HANDLE) dev, offset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}
	}

	if (!bInstantRetryOtherFilesys)
	{
		// Write the volume header
		if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, (byte*)header))
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}

		// To prevent fragmentation, write zeroes to reserved header sectors which are going to be filled with random data
		if (!volParams->bDevice && !volParams->hiddenVol)
		{
			byte buf[TC_VOLUME_HEADER_GROUP_SIZE - TC_VOLUME_HEADER_EFFECTIVE_SIZE];
			DWORD bytesWritten;
			ZeroMemory (buf, sizeof (buf));

			if (!WriteFile (dev, buf, sizeof (buf), &bytesWritten, NULL))
			{
				nStatus = ERR_OS_ERROR;
				SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
				goto error;
			}

			if (bytesWritten != sizeof (buf))
			{
				nStatus = ERR_PARAMETER_INCORRECT;
				SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
				goto error;
			}
		}
	}

	if (volParams->hiddenVol)
	{
		// Calculate data area position of hidden volume
		cryptoInfo->hiddenVolumeOffset = dataOffset;

		// Validate the offset
		if (dataOffset % FormatSectorSize != 0)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}

		volParams->quickFormat = TRUE;		// To entirely format a hidden volume would be redundant
	}

	/* Data area */
	startSector = dataOffset / FormatSectorSize;

	// Format filesystem
	SLOG_TRACE("Format.c - [TCFormatVolume] Format filesystem.");

	switch (volParams->fileSystem)
	{
	case FILESYS_NONE:
	case FILESYS_NTFS:
	case FILESYS_EXFAT:
	case FILESYS_REFS:

		if (volParams->bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("Format.c - [TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}

		nStatus = FormatNoFs (hwndDlg, startSector, num_sectors, dev, cryptoInfo, volParams->quickFormat);
	    SLOG_TRACE("Format.c - [TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);

		if (volParams->bDevice) {
			SLOG_TRACE("Format.c - [TCFormatVolume] StopFormatWriteThread begin.");
			StopFormatWriteThread();
			SLOG_TRACE("Format.c - [TCFormatVolume] SStopFormatWriteThread end.");
		}

		break;

	case FILESYS_FAT:
		if (num_sectors > 0xFFFFffff)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}

		// Calculate the fats, root dir etc
		ft.num_sectors = (unsigned int) (num_sectors);

#if TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#error TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#endif

		ft.sector_size = (uint16) FormatSectorSize;
		ft.cluster_size = volParams->clusterSize;
		memcpy (ft.volume_name, "NO NAME    ", 11);
		GetFatParams (&ft);
		*(volParams->realClusterSize) = ft.cluster_size * FormatSectorSize;

		if (volParams->bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		nStatus = FormatFat (hwndDlg, startSector, &ft, (void *) dev, cryptoInfo, volParams->quickFormat);

		if (volParams->bDevice)
			StopFormatWriteThread();

		break;

	default:
	    SLOG_TRACE("Format.c - [TCFormatVolume] nStatus = ERR_PARAMETER_INCORRECT");
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	if (nStatus != ERR_SUCCESS) {
	    SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
		goto error;
	}

	// Write header backup
	offset.QuadPart = volParams->hiddenVol ? volParams->hiddenVolHostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET : dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

	SLOG_TRACE("Format.c - [TCFormatVolume] Start SetFilePointerEx.");
	if (!SetFilePointerEx ((HANDLE) dev, offset, NULL, FILE_BEGIN))
	{
		nStatus = ERR_OS_ERROR;
	    SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
		goto error;
	}

	SLOG_TRACE("Format.c - [TCFormatVolume] Start CreateVolumeHeaderInMemory.");
	nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
		header,
		volParams->ea,
		FIRST_MODE_OF_OPERATION_ID,
		volParams->password,
		volParams->pkcs5,
		volParams->pim,
		(char*)cryptoInfo->master_keydata,
		&cryptoInfo,
		dataAreaSize,
		volParams->hiddenVol ? dataAreaSize : 0,
		dataOffset,
		dataAreaSize,
		0,
		volParams->headerFlags,
		FormatSectorSize,
		FALSE);

	SLOG_TRACE("Start WriteEffectiveVolumeHeader.");
	if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, (byte*)header))
	{
		nStatus = ERR_OS_ERROR;
	    SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
		goto error;
	}
	SLOG_TRACE("WriteEffectiveVolumeHeader over.");

	// Fill reserved header sectors (including the backup header area) with random data
	if (!volParams->hiddenVol)
	{
		BOOL bUpdateBackup = FALSE;

		SLOG_TRACE("Format.c - [TCFormatVolume] Start WriteRandomDataToReservedHeaderAreas.");
		nStatus = WriteRandomDataToReservedHeaderAreas (hwndDlg, dev, cryptoInfo, dataAreaSize, FALSE, FALSE);

		if (nStatus != ERR_SUCCESS) {
			SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
			goto error;
		}

		// write fake hidden volume header to protect against attacks that use statistical entropy
		// analysis to detect presence of hidden volumes.
		
		while (TRUE)
		{
			PCRYPTO_INFO dummyInfo = NULL;
			LARGE_INTEGER hiddenOffset;

			hiddenOffset.QuadPart = bUpdateBackup ? dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE + TC_HIDDEN_VOLUME_HEADER_OFFSET: TC_HIDDEN_VOLUME_HEADER_OFFSET;

		    SLOG_TRACE("Format.c - [TCFormatVolume] Start CreateVolumeHeaderInMemory.");
			nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
				header,
				volParams->ea,
				FIRST_MODE_OF_OPERATION_ID,
				NULL,
				0,
				0,
				NULL,
				&dummyInfo,
				dataAreaSize,
				dataAreaSize,
				dataOffset,
				dataAreaSize,
				0,
				volParams->headerFlags,
				FormatSectorSize,
				FALSE);

			if (nStatus != ERR_SUCCESS) {
				SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
				goto error;
			}

			crypto_close (dummyInfo);

			if (!SetFilePointerEx ((HANDLE) dev, hiddenOffset, NULL, FILE_BEGIN))
			{
				nStatus = ERR_OS_ERROR;
				SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
				goto error;
			}

			if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, (byte*)header))
			{
				nStatus = ERR_OS_ERROR;
				SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
				goto error;
			}

			if (bUpdateBackup)
				break;

			bUpdateBackup = TRUE;
		}
	}

#ifndef DEBUG
	if (volParams->quickFormat && volParams->fileSystem != FILESYS_NTFS && volParams->fileSystem != FILESYS_EXFAT && volParams->fileSystem != FILESYS_REFS)
		Sleep (500);	// User-friendly GUI
#endif

	SLOG_TRACE("Format.c - [TCFormatVolume] ==================mark=============.");
error:
	dwError = GetLastError();
	SLOG_TRACE("[TCFormatVolume] error, nStatus = %d, dwError = %d", nStatus, dwError);

	burn (header, sizeof (header));
	VirtualUnlock (header, sizeof (header));

	if (dev != INVALID_HANDLE_VALUE)
	{
		if (!volParams->bDevice && !volParams->hiddenVol && nStatus != 0)
		{
			// Remove preallocated part before closing file handle if format failed
			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) == 0)
				SetEndOfFile (dev);
		}

		FlushFileBuffers (dev);

		if (bTimeStampValid)
			SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime);

		CloseHandle (dev);
		dev = INVALID_HANDLE_VALUE;
	}

	if (nStatus != 0)
	{
		SetLastError(dwError);
	    SLOG_TRACE("Format.c - [TCFormatVolume] error, nStatus = %d, dwError = %d", nStatus, dwError);
		goto fv_end;
	}

	if (volParams->fileSystem == FILESYS_NTFS || volParams->fileSystem == FILESYS_EXFAT || volParams->fileSystem == FILESYS_REFS)
	{
		// Quick-format volume as NTFS
		int mountVolumeRet;
		int driveNo;
		MountOptions mountOptions;
		int retCode;
		int fsType = volParams->fileSystem;

	    SLOG_TRACE("[TCFormatVolume] volParams->drive_in_cmd = %lc", volParams->drive_in_cmd);
		if (volParams->drive_in_cmd >= L'A' && volParams->drive_in_cmd <= L'Z') {
	        SLOG_TRACE("[TCFormatVolume] Input drive in command is %lc", volParams->drive_in_cmd);
			driveNo = volParams->drive_in_cmd - L'A';
		} else if (volParams->drive_in_cmd >= L'a' && volParams->drive_in_cmd <= L'z') {
	        SLOG_TRACE("[TCFormatVolume] Input drive in command is %lc", volParams->drive_in_cmd);
			driveNo = volParams->drive_in_cmd - L'a';
		} else {
		    driveNo = GetLastAvailableDrive ();
	        SLOG_TRACE("[TCFormatVolume] GetLastAvailableDrive return %d", driveNo);
		}


		ZeroMemory (&mountOptions, sizeof (mountOptions));

		if (driveNo == -1)
		{
			if (!Silent)
			{
				MessageBoxW (volParams->hwndDlg, GetString ("NO_FREE_DRIVES"), lpszTitle, ICON_HAND);
				MessageBoxW (volParams->hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);
			}

			nStatus = ERR_NO_FREE_DRIVES;
	        SLOG_TRACE("[TCFormatVolume] nStatus = %d", nStatus);
			goto fv_end;
		}

		mountOptions.ReadOnly = FALSE;
		mountOptions.Removable = FALSE;
		mountOptions.ProtectHiddenVolume = FALSE;
		mountOptions.PreserveTimestamp = bPreserveTimestamp;
		mountOptions.PartitionInInactiveSysEncScope = FALSE;
		mountOptions.UseBackupHeader = FALSE;


	    SLOG_TRACE("[TCFormatVolume] Start MountVolume.");
		mountVolumeRet = MountVolume (volParams->hwndDlg, driveNo, volParams->volumePath, volParams->password, volParams->pkcs5, volParams->pim, FALSE, FALSE, FALSE, TRUE, &mountOptions, TRUE, TRUE);
	    SLOG_TRACE("[TCFormatVolume] mount_volume_ret = %d", mountVolumeRet);
		
		if (mountVolumeRet < 1)
		{
			if (!Silent)
			{
				MessageBoxW (volParams->hwndDlg, GetString ("CANT_MOUNT_VOLUME"), lpszTitle, ICON_HAND);
				MessageBoxW (volParams->hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);
			}
			nStatus = ERR_VOL_MOUNT_FAILED;
	        SLOG_TRACE("[TCFormatVolume] MountVolume failed, nStatus = %d", nStatus);
			goto fv_end;
		}

		if (!Silent && !IsAdmin () && IsUacSupported ())
			retCode = UacFormatFs (volParams->hwndDlg, driveNo, volParams->clusterSize, fsType);
		else
			retCode = FormatFs (driveNo, volParams->clusterSize, fsType);

		if (retCode != TRUE)
		{
            if (!UnmountVolumeAfterFormatExCall (volParams->hwndDlg, driveNo) && !Silent)
				MessageBoxW (volParams->hwndDlg, GetString ("CANT_DISMOUNT_VOLUME"), lpszTitle, ICON_HAND);

			if (dataAreaSize <= TC_MAX_FAT_SECTOR_COUNT * FormatSectorSize)
			{
				if (AskErrYesNo ("FORMAT_NTFS_FAILED_ASK_FAT", hwndDlg) == IDYES)
				{
					// NTFS format failed and the user wants to try FAT format immediately
					volParams->fileSystem = FILESYS_FAT;
					bInstantRetryOtherFilesys = TRUE;
					volParams->quickFormat = TRUE;  // Volume has already been successfully TC-formatted
					volParams->clusterSize = 0;		// Default cluster size
					goto begin_format;
				}
			}
			else
				Error ("FORMAT_NTFS_FAILED", hwndDlg);

			nStatus = ERR_DONT_REPORT;
			goto fv_end;
		}

		if (!UnmountVolumeAfterFormatExCall (volParams->hwndDlg, driveNo) && !Silent)
			MessageBoxW (volParams->hwndDlg, GetString ("CANT_DISMOUNT_VOLUME"), lpszTitle, ICON_HAND);
	}

fv_end:
	dwError = GetLastError();

	if (dosDev[0])
		RemoveFakeDosName (volParams->volumePath, dosDev);

	crypto_close (cryptoInfo);

	SetLastError (dwError);
	return nStatus;
}

int DataCubeTCFormatVolume (volatile FORMAT_VOL_PARAMETERS *volParams)
{
	int nStatus;
	PCRYPTO_INFO cryptoInfo = NULL;
	HANDLE dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	unsigned __int64 num_sectors, startSector;
	fatparams ft;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	BOOL bInstantRetryOtherFilesys = FALSE;
	WCHAR dosDev[TC_MAX_PATH] = { 0 };
	WCHAR devName[MAX_PATH] = { 0 };
	int driveLetter = -1;
	WCHAR deviceName[MAX_PATH];
	uint64 dataOffset, dataAreaSize;
	LARGE_INTEGER offset;
	BOOL bFailedRequiredDASD = FALSE;
	// HWND hwndDlg = volParams->hwndDlg;

	uint32 dc_FormatSectorSize = volParams->sectorSize;

	SLOG_TRACE("=====================DataCubeTCFormatVolume Mark 1 ================");
	if (dc_FormatSectorSize < TC_MIN_VOLUME_SECTOR_SIZE
		|| dc_FormatSectorSize > TC_MAX_VOLUME_SECTOR_SIZE
		|| dc_FormatSectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
	{
		SLOG_TRACE("[TCFormatVolume] SECTOR_SIZE_UNSUPPORTED");
		// Error ("SECTOR_SIZE_UNSUPPORTED", hwndDlg);
		return ERR_DONT_REPORT;
	}

	/* WARNING: Note that if Windows fails to format the volume as NTFS and the volume size is
	less than the maximum FAT size, the user is asked within this function whether he wants to instantly
	retry FAT format instead (to avoid having to re-create the whole container again). If the user
	answers yes, some of the input parameters are modified, the code below 'begin_format' is re-executed
	and some destructive operations that were performed during the first attempt must be (and are) skipped.
	Therefore, whenever adding or modifying any potentially destructive operations below 'begin_format',
	determine whether they (or their portions) need to be skipped during such a second attempt; if so,
	use the 'bInstantRetryOtherFilesys' flag to skip them. */

	// yww-: volParams->hiddenVol is FALSE
	// if (volParams->hiddenVol)
	// {
	// 	SLOG_TRACE("[=====================DataCubeTCFormatVolume Mark 2 ================");
	// 	dataOffset = volParams->hiddenVolHostSize - TC_VOLUME_HEADER_GROUP_SIZE - volParams->size;
	// }
	// else
	// {
		SLOG_TRACE("=====================DataCubeTCFormatVolume Mark 3 ================");
		if (volParams->size <= TC_TOTAL_VOLUME_HEADERS_SIZE) {
		    SLOG_TRACE("[TCFormatVolume] volParams->size <= TC_TOTAL_VOLUME_HEADERS_SIZE");
			SLOG_TRACE("volParams->size = %llu, TC_TOTAL_VOLUME_HEADERS_SIZE = %llu", volParams->size, TC_TOTAL_VOLUME_HEADERS_SIZE);
			return ERR_VOL_SIZE_WRONG;
		}

		dataOffset = TC_VOLUME_DATA_OFFSET;
		SLOG_TRACE("dataOffset = %lu, volParams->size = %lu", dataOffset, volParams->size);
	// }

	dataAreaSize = GetVolumeDataAreaSize (volParams->hiddenVol, volParams->size);

	num_sectors = dataAreaSize / dc_FormatSectorSize;
	SLOG_TRACE("dataAreaSize = %lu, num_sectors = %lu", dataAreaSize, num_sectors);

	// yww-: volParams->bDevice is FALSE
	// if (volParams->bDevice)
	// {
	// 	StringCchCopyW (deviceName, ARRAYSIZE(deviceName), volParams->volumePath);
	// 
	// 	driveLetter = GetDiskDeviceDriveLetter (deviceName);
	// }

	VirtualLock (header, sizeof (header));

	SLOG_TRACE("=====================DataCubeTCFormatVolume Mark 4 ================");
	// nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
	nStatus = DataCubeCreateVolumeHeaderInMemory (NULL, FALSE,
				     header,
				     volParams->ea,
					 FIRST_MODE_OF_OPERATION_ID,
				     volParams->password,
				     volParams->pkcs5,
					 volParams->pim,
					 NULL,
				     &cryptoInfo,
					 dataAreaSize,
					 volParams->hiddenVol ? dataAreaSize : 0,
					 dataOffset,
					 dataAreaSize,
					 0,
					 volParams->headerFlags,
					 dc_FormatSectorSize,
					 FALSE);

	SLOG_TRACE("DataCubeCreateVolumeHeaderInMemory return nStatus = %d", nStatus);
	/* cryptoInfo sanity check to make Coverity happy eventhough it can't be NULL if nStatus = 0 */
	if ((nStatus != 0) || !cryptoInfo)
	{
	    SLOG_TRACE("[TCFormatVolume] nStatus = %d", nStatus);

		burn (header, sizeof (header));
		VirtualUnlock (header, sizeof (header));
		return nStatus? nStatus : ERR_OUTOFMEMORY;
	}

begin_format:
	SLOG_TRACE("=====================Begin Format====================");
	if (volParams->bDevice)
	{
		/* Device-hosted volume */

		DWORD dwResult;
		int nPass;

		if (FakeDosNameForDevice (volParams->volumePath, dosDev, sizeof(dosDev), devName, sizeof(devName), FALSE) != 0)
			return ERR_OS_ERROR;

		if (IsDeviceMounted (devName))
		{
	        SLOG_TRACE("begin_format, IsDeviceMounted return true.");

			if ((dev = DismountDrive (devName, volParams->volumePath)) == INVALID_HANDLE_VALUE)
			{
	            SLOG_TRACE("[TCFormatVolume] begin_format, FORMAT_CANT_DISMOUNT_FILESYS.");

				nStatus = ERR_DONT_REPORT;
				goto error;
			}

			/* Gain "raw" access to the partition (it contains a live filesystem and the filesystem driver
			would otherwise prevent us from writing to hidden sectors). */

			if (!DeviceIoControl (dev,
				FSCTL_ALLOW_EXTENDED_DASD_IO,
				NULL,
				0,
				NULL,
				0,
				&dwResult,
				NULL))
			{
	            SLOG_TRACE("[TCFormatVolume] begin_format, DeviceIoControl return false.");

				bFailedRequiredDASD = TRUE;
			}
		}
		else if (IsOSAtLeast (WIN_VISTA) && driveLetter == -1)
		{
			// Windows Vista doesn't allow overwriting sectors belonging to an unformatted partition
			// to which no drive letter has been assigned under the system. This problem can be worked
			// around by assigning a drive letter to the partition temporarily.

			wchar_t szDriveLetter[] = { L'A', L':', 0 };
			wchar_t rootPath[] = { L'A', L':', L'\\', 0 };
			wchar_t uniqVolName[MAX_PATH+1] = { 0 };
			int tmpDriveLetter = -1;
			BOOL bResult = FALSE;

			tmpDriveLetter = GetFirstAvailableDrive ();

			if (tmpDriveLetter != -1)
			{
				rootPath[0] += (wchar_t) tmpDriveLetter;
				szDriveLetter[0] += (wchar_t) tmpDriveLetter;

				if (DefineDosDevice (DDD_RAW_TARGET_PATH, szDriveLetter, volParams->volumePath))
				{
					bResult = GetVolumeNameForVolumeMountPoint (rootPath, uniqVolName, MAX_PATH);

					DefineDosDevice (DDD_RAW_TARGET_PATH|DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE,
						szDriveLetter,
						volParams->volumePath);

					if (bResult
						&& SetVolumeMountPoint (rootPath, uniqVolName))
					{
						// The drive letter can be removed now
						DeleteVolumeMountPoint (rootPath);
					}
				}
			}
		}

		// For extra safety, we will try to gain "raw" access to the partition. Note that this should actually be
		// redundant because if the filesystem was mounted, we already tried to obtain DASD above. If we failed,
		// bFailedRequiredDASD was set to TRUE and therefore we will perform pseudo "quick format" below. However,
		// for extra safety, in case IsDeviceMounted() failed to detect a live filesystem, we will blindly
		// send FSCTL_ALLOW_EXTENDED_DASD_IO (possibly for a second time) without checking the result.

		DeviceIoControl (dev,
			FSCTL_ALLOW_EXTENDED_DASD_IO,
			NULL,
			0,
			NULL,
			0,
			&dwResult,
			NULL);

	    SLOG_TRACE("DeviceIoControl return false.");

		// If DASD is needed but we failed to obtain it, perform open - 'quick format' - close - open
		// so that the filesystem driver does not prevent us from formatting hidden sectors.
		for (nPass = (bFailedRequiredDASD ? 0 : 1); nPass < 2; nPass++)
		{
			int retryCount;

			retryCount = 0;

			// Try exclusive access mode first
			// Note that when exclusive access is denied, it is worth retrying (usually succeeds after a few tries).
			while (dev == INVALID_HANDLE_VALUE && retryCount++ < EXCL_ACCESS_MAX_AUTO_RETRIES)
			{
				dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

				if (retryCount > 1)
					Sleep (EXCL_ACCESS_AUTO_RETRY_DELAY);
			}

			if (dev == INVALID_HANDLE_VALUE)
			{
				// Exclusive access denied -- retry in shared mode
				dev = CreateFile (devName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
				if (dev != INVALID_HANDLE_VALUE)
				{
	                SLOG_INFO("CreateFile return dev is not INVALID_HANDLE_VALUE.");
					if (!volParams->bForceOperation && (Silent || (IDNO == MessageBoxW (volParams->hwndDlg, GetString ("DEVICE_IN_USE_FORMAT"), lpszTitle, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2))))
					{
						nStatus = ERR_DONT_REPORT;
						goto error;
					}
				}
				else
				{
	                SLOG_ERROR("[TCFormatVolume] Exclusive access denied -- retry in shared mode.");
					// handleWin32ErrTRACEolParams->hwndDlg, SRC_POS);
					// Error ("CANT_ACCESS_VOL", hwndDlg);
					nStatus = ERR_DONT_REPORT;
					goto error;
				}
			}

			if (volParams->hiddenVol || bInstantRetryOtherFilesys)
				break;	// The following "quick format" operation would damage the outer volume

			if (nPass == 0)
			{
				char buf [2 * TC_MAX_VOLUME_SECTOR_SIZE];
				DWORD bw;

				// Perform pseudo "quick format" so that the filesystem driver does not prevent us from
				// formatting hidden sectors
				memset (buf, 0, sizeof (buf));

				if (!WriteFile (dev, buf, sizeof (buf), &bw, NULL))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}

				FlushFileBuffers (dev);
				CloseHandle (dev);
				dev = INVALID_HANDLE_VALUE;
			}
		}

		if (DeviceIoControl (dev, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwResult, NULL))
		{
			SLOG_ERROR("FORMAT_CANT_DISMOUNT_FILESYS");
			// Error ("FORMAT_CANT_DISMOUNT_FILESYS", hwndDlg);
			nStatus = ERR_DONT_REPORT;
			goto error;
		}
	}
	else
	{
	    SLOG_TRACE("volParams->bDevice is FALSE, DFile-hosted volume.");

		/* File-hosted volume */

		dev = CreateFile (volParams->volumePath, GENERIC_READ | GENERIC_WRITE,
			(volParams->hiddenVol || bInstantRetryOtherFilesys) ? (FILE_SHARE_READ | FILE_SHARE_WRITE) : 0,
			NULL, (volParams->hiddenVol || bInstantRetryOtherFilesys) ? OPEN_EXISTING : CREATE_ALWAYS, 0, NULL);

		if (dev == INVALID_HANDLE_VALUE)
		{
	        SLOG_TRACE("CreateFile return invalid handle.");

			nStatus = ERR_OS_ERROR;
			goto error;
		}

		DisableFileCompression (dev);

		if (!volParams->hiddenVol && !bInstantRetryOtherFilesys)
		{
			LARGE_INTEGER volumeSize;
			volumeSize.QuadPart = dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

			if (volParams->sparseFileSwitch && volParams->quickFormat)
			{
				// Create as sparse file container
				DWORD tmp;
				SLOG_TRACE("Create as sparse file container, control_code = %lu", FSCTL_SET_SPARSE);
				if (!DeviceIoControl (dev, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &tmp, NULL))
				{
					nStatus = ERR_OS_ERROR;
					goto error;
				}
				SLOG_TRACE("DeviceIoControl tmp = %lu", tmp);
			}

			SLOG_TRACE("volumeSize= %lu, FILE_BEGIN = %ld", volumeSize, FILE_BEGIN);

			// Preallocate the file
			if (!SetFilePointerEx (dev, volumeSize, NULL, FILE_BEGIN))
			{
				SLOG_TRACE("SetFilePointerEx return False");
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (!SetEndOfFile (dev))
			{
				SLOG_TRACE("SetEndOfFile return False");
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) != 0)
			{
				SLOG_TRACE("SetFilePointer return False");
				nStatus = ERR_OS_ERROR;
				goto error;
			}
		}
	}

	if (volParams->hiddenVol && !volParams->bDevice && bPreserveTimestamp)
	{
		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			bTimeStampValid = FALSE;
		else
			bTimeStampValid = TRUE;
	}

	// if (volParams->hwndDlg && volParams->bGuiMode) KillTimer (volParams->hwndDlg, TIMER_ID_RANDVIEW);

	/* Volume header */

	// Hidden volume setup
	if (volParams->hiddenVol)
	{
		LARGE_INTEGER headerOffset;

		// Check hidden volume size
		if (volParams->hiddenVolHostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE || volParams->hiddenVolHostSize > TC_MAX_HIDDEN_VOLUME_HOST_SIZE)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
	        SLOG_ERROR("[TCFormatVolume] ERR_VOL_SIZE_WRONG error, nStatus = %d", nStatus);
			goto error;
		}

		// Seek to hidden volume header location

		headerOffset.QuadPart = TC_HIDDEN_VOLUME_HEADER_OFFSET;

		if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}
	}
	else if (bInstantRetryOtherFilesys)
	{
		// The previous file system format failed and the user wants to try again with a different file system.
		// The volume header had been written successfully so we need to seek to the byte after the header.

		LARGE_INTEGER offset;
		offset.QuadPart = TC_VOLUME_DATA_OFFSET;
		if (!SetFilePointerEx ((HANDLE) dev, offset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}
	}

	if (!bInstantRetryOtherFilesys)
	{
		// Write the volume header
		if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, (byte*)header))
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}

		// To prevent fragmentation, write zeroes to reserved header sectors which are going to be filled with random data
		if (!volParams->bDevice && !volParams->hiddenVol)
		{
			byte buf[TC_VOLUME_HEADER_GROUP_SIZE - TC_VOLUME_HEADER_EFFECTIVE_SIZE];
			DWORD bytesWritten;
			ZeroMemory (buf, sizeof (buf));

			if (!WriteFile (dev, buf, sizeof (buf), &bytesWritten, NULL))
			{
				nStatus = ERR_OS_ERROR;
				SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
				goto error;
			}

			if (bytesWritten != sizeof (buf))
			{
				nStatus = ERR_PARAMETER_INCORRECT;
				SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
				goto error;
			}
		}
	}

	if (volParams->hiddenVol)
	{
		// Calculate data area position of hidden volume
		cryptoInfo->hiddenVolumeOffset = dataOffset;

		// Validate the offset
		if (dataOffset % dc_FormatSectorSize != 0)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
	        SLOG_TRACE("[TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}

		volParams->quickFormat = TRUE;		// To entirely format a hidden volume would be redundant
	}

	/* Data area */
	startSector = dataOffset / dc_FormatSectorSize;

	// Format filesystem
	SLOG_TRACE("Format filesystem, fs = %d", volParams->fileSystem);

	switch (volParams->fileSystem)
	{
	case FILESYS_NONE:
	case FILESYS_NTFS:
	case FILESYS_EXFAT:
	case FILESYS_REFS:

		if (volParams->bDevice && !StartFormatWriteThread())
		{
			nStatus = ERR_OS_ERROR;
	        SLOG_TRACE("Format.c - [TCFormatVolume] error, nStatus = %d", nStatus);
			goto error;
		}

		nStatus = DataCubeFormatNoFs (startSector, num_sectors, dev, cryptoInfo, volParams->quickFormat);
	    SLOG_TRACE("Format.c - [TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);

		if (volParams->bDevice) {
			SLOG_TRACE("Format.c - [TCFormatVolume] StopFormatWriteThread begin.");
			StopFormatWriteThread();
			SLOG_TRACE("Format.c - [TCFormatVolume] SStopFormatWriteThread end.");
		}

		break;
// yww-: FAT��ʱ������
//	case FILESYS_FAT:
//		if (num_sectors > 0xFFFFffff)
//		{
//			nStatus = ERR_VOL_SIZE_WRONG;
//			goto error;
//		}
//
//		// Calculate the fats, root dir etc
//		ft.num_sectors = (unsigned int) (num_sectors);
//
//#if TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
//#error TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
//#endif
//
//		ft.sector_size = (uint16) dc_FormatSectorSize;
//		ft.cluster_size = volParams->clusterSize;
//		memcpy (ft.volume_name, "NO NAME    ", 11);
//		GetFatParams (&ft);
//		*(volParams->realClusterSize) = ft.cluster_size * dc_FormatSectorSize;
//
//		if (volParams->bDevice && !StartFormatWriteThread())
//		{
//			nStatus = ERR_OS_ERROR;
//			goto error;
//		}
//
//		nStatus = FormatFat (hwndDlg, startSector, &ft, (void *) dev, cryptoInfo, volParams->quickFormat);
//
//		if (volParams->bDevice)
//			StopFormatWriteThread();
//
//		break;
//
	default:
	    SLOG_TRACE("Format.c - [TCFormatVolume] nStatus = ERR_PARAMETER_INCORRECT");
		nStatus = ERR_PARAMETER_INCORRECT;
		goto error;
	}

	if (nStatus != ERR_SUCCESS) {
	    SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
		goto error;
	}

	// Write header backup
	offset.QuadPart = volParams->hiddenVol ? volParams->hiddenVolHostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET : dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE;

	SLOG_TRACE("Format.c - [TCFormatVolume] Start SetFilePointerEx.");
	if (!SetFilePointerEx ((HANDLE) dev, offset, NULL, FILE_BEGIN))
	{
		nStatus = ERR_OS_ERROR;
	    SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
		goto error;
	}

	SLOG_TRACE("Format.c - [TCFormatVolume] Start CreateVolumeHeaderInMemory.");
	nStatus = DataCubeCreateVolumeHeaderInMemory (NULL, FALSE,
		header,
		volParams->ea,
		FIRST_MODE_OF_OPERATION_ID,
		volParams->password,
		volParams->pkcs5,
		volParams->pim,
		(char*)cryptoInfo->master_keydata,
		&cryptoInfo,
		dataAreaSize,
		volParams->hiddenVol ? dataAreaSize : 0,
		dataOffset,
		dataAreaSize,
		0,
		volParams->headerFlags,
		dc_FormatSectorSize,
		FALSE);

	SLOG_TRACE("Start WriteEffectiveVolumeHeader.");
	if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, (byte*)header))
	{
		nStatus = ERR_OS_ERROR;
	    SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
		goto error;
	}
	SLOG_TRACE("WriteEffectiveVolumeHeader over.");

	// Fill reserved header sectors (including the backup header area) with random data
	if (!volParams->hiddenVol)
	{
		BOOL bUpdateBackup = FALSE;

		SLOG_TRACE("Format.c - [TCFormatVolume] Start WriteRandomDataToReservedHeaderAreas.");
		nStatus = WriteRandomDataToReservedHeaderAreas (NULL, dev, cryptoInfo, dataAreaSize, FALSE, FALSE);

		if (nStatus != ERR_SUCCESS) {
			SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
			goto error;
		}

		// write fake hidden volume header to protect against attacks that use statistical entropy
		// analysis to detect presence of hidden volumes.
		
		while (TRUE)
		{
			PCRYPTO_INFO dummyInfo = NULL;
			LARGE_INTEGER hiddenOffset;

			hiddenOffset.QuadPart = bUpdateBackup ? dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE + TC_HIDDEN_VOLUME_HEADER_OFFSET: TC_HIDDEN_VOLUME_HEADER_OFFSET;

		    SLOG_TRACE("Format.c - [TCFormatVolume] Start CreateVolumeHeaderInMemory.");
			nStatus = DataCubeCreateVolumeHeaderInMemory (NULL, FALSE,
				header,
				volParams->ea,
				FIRST_MODE_OF_OPERATION_ID,
				NULL,
				0,
				0,
				NULL,
				&dummyInfo,
				dataAreaSize,
				dataAreaSize,
				dataOffset,
				dataAreaSize,
				0,
				volParams->headerFlags,
				dc_FormatSectorSize,
				FALSE);

			if (nStatus != ERR_SUCCESS) {
				SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
				goto error;
			}

			crypto_close (dummyInfo);

			if (!SetFilePointerEx ((HANDLE) dev, hiddenOffset, NULL, FILE_BEGIN))
			{
				nStatus = ERR_OS_ERROR;
				SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
				goto error;
			}

			if (!WriteEffectiveVolumeHeader (volParams->bDevice, dev, (byte*)header))
			{
				nStatus = ERR_OS_ERROR;
				SLOG_TRACE("[TCFormatVolume] FormatNoFs over, nStatus = %d", nStatus);
				goto error;
			}

			if (bUpdateBackup)
				break;

			bUpdateBackup = TRUE;
		}
	}

#ifndef DEBUG
	if (volParams->quickFormat && volParams->fileSystem != FILESYS_NTFS && volParams->fileSystem != FILESYS_EXFAT && volParams->fileSystem != FILESYS_REFS)
		Sleep (500);	// User-friendly GUI
#endif

	SLOG_TRACE("============================mark=============.");
error:
	dwError = GetLastError();
	SLOG_TRACE("[TCFormatVolume] error, nStatus = %d, dwError = %d", nStatus, dwError);

	burn (header, sizeof (header));
	VirtualUnlock (header, sizeof (header));

	if (dev != INVALID_HANDLE_VALUE)
	{
		if (!volParams->bDevice && !volParams->hiddenVol && nStatus != 0)
		{
			// Remove preallocated part before closing file handle if format failed
			if (SetFilePointer (dev, 0, NULL, FILE_BEGIN) == 0)
				SetEndOfFile (dev);
		}

		FlushFileBuffers (dev);

		if (bTimeStampValid)
			SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime);

		CloseHandle (dev);
		dev = INVALID_HANDLE_VALUE;
	}

	if (nStatus != 0)
	{
		SetLastError(dwError);
	    SLOG_TRACE("Format.c - [TCFormatVolume] error, nStatus = %d, dwError = %d", nStatus, dwError);
		goto fv_end;
	}

	if (volParams->fileSystem == FILESYS_NTFS || volParams->fileSystem == FILESYS_EXFAT || volParams->fileSystem == FILESYS_REFS)
	{
		// Quick-format volume as NTFS
		int mountVolumeRet;
		int driveNo;
		MountOptions mountOptions;
		int retCode;
		int fsType = volParams->fileSystem;

	    SLOG_TRACE("[TCFormatVolume] volParams->drive_in_cmd = %lc", volParams->drive_in_cmd);
		if (volParams->drive_in_cmd >= L'A' && volParams->drive_in_cmd <= L'Z') {
	        SLOG_TRACE("[TCFormatVolume] Input drive in command is %lc", volParams->drive_in_cmd);
			driveNo = volParams->drive_in_cmd - L'A';
		} else if (volParams->drive_in_cmd >= L'a' && volParams->drive_in_cmd <= L'z') {
	        SLOG_TRACE("[TCFormatVolume] Input drive in command is %lc", volParams->drive_in_cmd);
			driveNo = volParams->drive_in_cmd - L'a';
		} else {
		    driveNo = GetLastAvailableDrive ();
	        SLOG_TRACE("[TCFormatVolume] GetLastAvailableDrive return %d", driveNo);
		}


		ZeroMemory (&mountOptions, sizeof (mountOptions));

		mountOptions.ReadOnly = FALSE;
		mountOptions.Removable = FALSE;
		mountOptions.ProtectHiddenVolume = FALSE;
		mountOptions.PreserveTimestamp = bPreserveTimestamp;
		mountOptions.PartitionInInactiveSysEncScope = FALSE;
		mountOptions.UseBackupHeader = FALSE;


	    SLOG_TRACE("[TCFormatVolume] Start MountVolume.");
		mountVolumeRet = MountVolume (volParams->hwndDlg, driveNo, volParams->volumePath, volParams->password, volParams->pkcs5, volParams->pim, FALSE, FALSE, FALSE, TRUE, &mountOptions, TRUE, TRUE);
	    SLOG_TRACE("[TCFormatVolume] mount_volume_ret = %d", mountVolumeRet);
		
		if (mountVolumeRet < 1)
		{
			if (!Silent)
			{
				MessageBoxW (volParams->hwndDlg, GetString ("CANT_MOUNT_VOLUME"), lpszTitle, ICON_HAND);
				MessageBoxW (volParams->hwndDlg, GetString ("FORMAT_NTFS_STOP"), lpszTitle, ICON_HAND);
			}
			nStatus = ERR_VOL_MOUNT_FAILED;
	        SLOG_TRACE("[TCFormatVolume] MountVolume failed, nStatus = %d", nStatus);
			goto fv_end;
		}

		if (!Silent && !IsAdmin () && IsUacSupported ())
			retCode = UacFormatFs (volParams->hwndDlg, driveNo, volParams->clusterSize, fsType);
		else
			retCode = FormatFs (driveNo, volParams->clusterSize, fsType);

		if (retCode != TRUE)
		{
            if (!UnmountVolumeAfterFormatExCall (volParams->hwndDlg, driveNo) && !Silent) {
				SLOG_ERROR("CANT_DISMOUNT_VOLUME");
			}

			if (dataAreaSize <= TC_MAX_FAT_SECTOR_COUNT * dc_FormatSectorSize)
			{
				if (AskErrYesNo ("FORMAT_NTFS_FAILED_ASK_FAT", NULL) == IDYES)
				{
					// NTFS format failed and the user wants to try FAT format immediately
					volParams->fileSystem = FILESYS_FAT;
					bInstantRetryOtherFilesys = TRUE;
					volParams->quickFormat = TRUE;  // Volume has already been successfully TC-formatted
					volParams->clusterSize = 0;		// Default cluster size
					goto begin_format;
				}
			}
			else {
				SLOG_ERROR("FORMAT_NTFS_FAILED");
			}

			nStatus = ERR_DONT_REPORT;
			goto fv_end;
		}

		if (!UnmountVolumeAfterFormatExCall (volParams->hwndDlg, driveNo) && !Silent)
			MessageBoxW (volParams->hwndDlg, GetString ("CANT_DISMOUNT_VOLUME"), lpszTitle, ICON_HAND);
	}

fv_end:
	dwError = GetLastError();

	if (dosDev[0])
		RemoveFakeDosName (volParams->volumePath, dosDev);

	crypto_close (cryptoInfo);

	SetLastError (dwError);
	return nStatus;
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


volatile BOOLEAN FormatExError;

BOOLEAN __stdcall FormatExCallback (int command, DWORD subCommand, PVOID parameter)
{
	if (FormatExError)
		return FALSE;

	switch(command) {
	case FMIFS_PROGRESS:
		break;
	case FMIFS_STRUCTURE_PROGRESS:
		break;
	case FMIFS_DONE:
		if(*(BOOLEAN*)parameter == FALSE) {
			FormatExError = TRUE;
		}
		break;
	case FMIFS_DONE_WITH_STRUCTURE:
		break;
	case FMIFS_INCOMPATIBLE_FILE_SYSTEM:
		FormatExError = TRUE;
		break;
	case FMIFS_ACCESS_DENIED:
		FormatExError = TRUE;
		break;
	case FMIFS_MEDIA_WRITE_PROTECTED:
		FormatExError = TRUE;
		break;
	case FMIFS_VOLUME_IN_USE:
		FormatExError = TRUE;
		break;
	case FMIFS_DEVICE_NOT_READY:
		FormatExError = TRUE;
		break;
	case FMIFS_CANT_QUICK_FORMAT:
		FormatExError = TRUE;
		break;
	case FMIFS_BAD_LABEL:
		FormatExError = TRUE;
		break;
	case FMIFS_OUTPUT:
		break;
	case FMIFS_CLUSTER_SIZE_TOO_BIG:
	case FMIFS_CLUSTER_SIZE_TOO_SMALL:
		FormatExError = TRUE;
		break;
	case FMIFS_VOLUME_TOO_BIG:
	case FMIFS_VOLUME_TOO_SMALL:
		FormatExError = TRUE;
		break;
	case FMIFS_NO_MEDIA_IN_DRIVE:
		FormatExError = TRUE;
		break;
	default:
		FormatExError = TRUE;
		break;
	}
	return (FormatExError? FALSE : TRUE);
}

BOOL FormatFs (int driveNo, int clusterSize, int fsType)
{
	wchar_t dllPath[MAX_PATH] = {0};
	WCHAR dir[8] = { (WCHAR) driveNo + L'A', 0 };
	PFORMATEX FormatEx;
	HMODULE hModule;
	int i;
	WCHAR szFsFormat[16];
	WCHAR szLabel[2] = {0};
	switch (fsType)
	{
		case FILESYS_NTFS:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"NTFS");
			break;
		case FILESYS_EXFAT:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"EXFAT");
			break;
		case FILESYS_REFS:
			StringCchCopyW (szFsFormat, ARRAYSIZE (szFsFormat),L"ReFS");
			break;
		default:
			return FALSE;
	}


	if (GetSystemDirectory (dllPath, MAX_PATH))
	{
		StringCchCatW(dllPath, ARRAYSIZE(dllPath), L"\\fmifs.dll");
	}
	else
		StringCchCopyW(dllPath, ARRAYSIZE(dllPath), L"C:\\Windows\\System32\\fmifs.dll");

	hModule = LoadLibrary (dllPath);

	if (hModule == NULL)
		return FALSE;

	if (!(FormatEx = (PFORMATEX) GetProcAddress (GetModuleHandle (L"fmifs.dll"), "FormatEx")))
	{
		FreeLibrary (hModule);
		return FALSE;
	}

	StringCchCatW (dir, ARRAYSIZE(dir), L":\\");

	FormatExError = TRUE;

	// Windows sometimes fails to format a volume (hosted on a removable medium) as NTFS.
	// It often helps to retry several times.
	for (i = 0; i < 50 && FormatExError; i++)
	{
		FormatExError = FALSE;
		FormatEx (dir, FMIFS_HARDDISK, szFsFormat, szLabel, TRUE, clusterSize * FormatSectorSize, FormatExCallback);
	}

	// The device may be referenced for some time after FormatEx() returns
	Sleep (4000);

	FreeLibrary (hModule);
	return FormatExError? FALSE : TRUE;
}

BOOL FormatNtfs (int driveNo, int clusterSize)
{
	return FormatFs (driveNo, clusterSize, FILESYS_NTFS);
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


static BOOL StartFormatWriteThread ()
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

	WriteThreadBuffer = (byte *)TCalloc (FormatWriteBufferSize);
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


static void StopFormatWriteThread ()
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

	SLOG_TRACE("=============== CreateVolumeHeaderInMemory 1 ================");
	if (masterKeydata == NULL)
	{
		// We have no master key data (creating a new volume) so we'll use the TrueCrypt RNG to generate them

		int bytesNeeded;
		SLOG_TRACE("=============== masterKeydata is NULL ================");


		switch (mode)
		{

		default:
			bytesNeeded = EAGetKeySize (ea) * 2;	// Size of primary + secondary key(s)
		}

		SLOG_TRACE("=============== Start RandgetBytes ================");

#if !defined(_UEFI)
		if (!RandgetBytes (hwndDlg, (unsigned char*)keyInfo.master_keydata, bytesNeeded, TRUE))
#else
		if (!RandgetBytes(keyInfo.master_keydata, bytesNeeded, TRUE))
#endif
		{
			SLOG_TRACE("=============== RandgetBytes Error ================");

			crypto_close (cryptoInfo);
			retVal = ERR_CIPHER_INIT_WEAK_KEY;
			goto err;
		}
	}
	else
	{
		SLOG_TRACE("=============== masterKeydata is not NULL ================");

		// We already have existing master key data (the header is being re-encrypted)
		memcpy (keyInfo.master_keydata, masterKeydata, MASTER_KEYDATA_SIZE);
	}

	SLOG_TRACE("=============== CreateVolumeHeaderInMemory 2 ================");
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

	SLOG_TRACE("=============== CreateVolumeHeaderInMemory 3 ================");
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

	SLOG_TRACE("=============== CreateVolumeHeaderInMemory  4================");
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


	SLOG_TRACE("=============== CreateVolumeHeaderInMemory  5 ================");
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
