/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0, and also derived from source code of extcv which
 is Copyright (c) 2009-2010 by Kih-Oskh or Copyright (c) 2012-2013 Josef Schneider
 <josef@netpage.dk>

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_InitDataArea
#define TC_HEADER_InitDataArea

#ifdef __cplusplus
extern "C" {
#endif

void SetFormatSectorSize (uint32 sector_size);
int FormatNoFs (HWND hwndDlg, unsigned __int64 startSector, __int64 num_sectors, void *dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat);
BOOL WriteSector ( void *dev , char *sector , char *write_buf , int *write_buf_cnt , __int64 *nSecNo , PCRYPTO_INFO cryptoInfo );
BOOL FlushFormatWriteBuffer (void *dev, char *write_buf, int *write_buf_cnt, __int64 *nSecNo, PCRYPTO_INFO cryptoInfo);
BOOL StartFormatWriteThread ();
void StopFormatWriteThread ();
int DataCubeFormatNoFs (unsigned __int64 startSector, __int64 num_sectors, void * dev, PCRYPTO_INFO cryptoInfo, BOOL quickFormat);

// Creates a volume header in memory
#if defined(_UEFI)
int DataCubeCreateVolumeHeaderInMemory(BOOL bBoot, char *header, int ea, int mode, Password *password,
	int pkcs5_prf, int pim, char *masterKeydata, PCRYPTO_INFO *retInfo,
	unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
	unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode);
#else
int DataCubeCreateVolumeHeaderInMemory (HWND hwndDlg, BOOL bBoot, char *header, int ea, int mode, Password *password,
		   int pkcs5_prf, int pim, char *masterKeydata, PCRYPTO_INFO *retInfo,
		   unsigned __int64 volumeSize, unsigned __int64 hiddenVolumeSize,
		   unsigned __int64 encryptedAreaStart, unsigned __int64 encryptedAreaLength, uint16 requiredProgramVersion, uint32 headerFlags, uint32 sectorSize, BOOL bWipeMode);
#endif // !defined(_UEFI)

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_InitDataArea