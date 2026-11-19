#pragma once
/* Build identity stamp. CI (build.yml) overwrites this file at build time
 * with "bstamp:<sha7>:<utc>:<runid>"; local builds carry the dev value.
 * Greppable in the raw dll/exe bytes (C-26 stale-slot forensics). */
#define BUILDSTAMP_STRING "bstamp:dev"
