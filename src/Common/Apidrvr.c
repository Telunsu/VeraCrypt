/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Apidrvr.h"
#include "Common.h"
#include "Errors.h"
#include "Options.h"
#include "DlgCode.h"
#include "Registry.h"
#include "BootEncryption.h"

#ifdef _WIN32

using namespace VeraCrypt;

/*
BOOL InitBootEncryption() {
	try
	{
		BootEncObj = new BootEncryption ();
	}
	catch (Exception &e)
	{
		e.Show ();
		return FALSE;
	}

	if (BootEncObj == NULL)
		return FALSE;
	//TODO: more info
	//AbortProcess ("INIT_SYS_ENC");
	
	
	return TRUE;
}
*/

#endif /* _WIN32 */

