// locale_stub.cpp -- override BOTH downlevel locale-name<->LCID helpers to drop the
// ~13 KB lcidtoname_downlevel table from libucrt.
//
// WHY: libucrt:lcidtoname_downlevel.obj embeds a ~13 KB .rdata lookup table (hundreds of
// locale-name string literals + LcidToLocaleNameTable + LocaleNameToIndexTable) and THREE
// functions:
//   __acrt_DownlevelLocaleNameToLCID   (name -> LCID)
//   __acrt_DownlevelLCIDToLocaleName   (LCID -> name)
//   _invoke_watson_if_error            (COMDAT helper -- also defined in 32 other members)
// libucrt:winapi_thunks.obj references the two locale functions as the PRE-VISTA fallback
// for LCID<->locale-name conversion. On Windows 10/11 the native LocaleNameToLCID /
// LCIDToLocaleName APIs (kernel32, available since Vista) are resolved first, so these
// fallbacks are never reached at runtime. The beacon makes ZERO direct locale calls
// (verified by source grep: no setlocale/_create_locale/strcoll/_wsetlocale), so dropping
// them is safe.
//
// THE LNK2005 TRAP (why overriding ONLY one function fails): a lib member is pulled to
// satisfy ANY of its referenced symbols. lcidtoname_downlevel.obj exposes both locale
// functions, so stubbing only one still pulls the obj for the OTHER -> LNK2005 on the
// stubbed symbol. Fix: stub BOTH. (_invoke_watson_if_error is also defined in 32 other
// members, so the linker satisfies any reference to it from elsewhere -- it does NOT keep
// this obj linked.) With both locale symbols provided by our explicit obj, the member is
// never pulled -> the table + both functions are gone.
//
// ABI: callers are already-compiled libucrt code; on x64 __cdecl the exact prototype is
// irrelevant -- args land in registers we don't read, return goes in rax. We return 0 for
// both: __acrt_DownlevelLocaleNameToLCID returns LCID (0 == not-found -> caller uses the
// system-default locale, which the beacon never inspects); __acrt_DownlevelLCIDToLocaleName
// returns the char count written (0 == none -> caller falls back to the native API result).
// Both bodies are dead code on Win10/11. extern "C" yields the undecorated symbols that
// match libucrt's C symbols.

extern "C" {

unsigned long __acrt_DownlevelLocaleNameToLCID(const void *localeName)
{
    (void)localeName;
    return 0;
}

unsigned long __acrt_DownlevelLCIDToLocaleName(unsigned long lcid, void *localeName,
                                               unsigned long localeNameCch, unsigned long flags)
{
    (void)lcid; (void)localeName; (void)localeNameCch; (void)flags;
    return 0;
}

} /* extern "C" */
