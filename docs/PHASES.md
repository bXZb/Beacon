# Delivery phases

| Phase | Goal | Exit criteria |
|-------|------|---------------|
| **P0** | Skeleton + HTTP default check-in | Beacon appears on default-profile listener; stable sleep loop |
| **P1** | Core commands | sleep/cd/pwd/shell/ls/upload/download/exit from CS console |
| **P2** | Official Malleable VM | jquery/amazon/custom profile round-trip |
| **P3** | BOF + jobs | ELF BOF; background jobs |
| **P4** | Channels | SOCKS/TCP pivot/link; DNS; ExtC2 |
| **P5** | Hardening | strategy, kill date, optional sleep mask, static musl |

## P0 checklist

- [x] Project layout + Makefile
- [x] `parse` / `build` big-endian helpers
- [x] `settings` TLV + XOR unmask
- [x] `security` AES/HMAC/RSA
- [x] `metadata` / agent_init
- [x] HTTP GET Cookie metadata + POST `?id=`
- [x] Main loop check-in
- [x] Live teamserver smoke test (lab)

## P1 checklist

- [x] Command dispatch in `proto.c` (core set)
- [x] SLEEP / DIE / CD / PWD / EXECUTE_JOB / FILE_LIST / UPLOAD / DOWNLOAD
- [x] Callback encrypt path
- [x] SOCKS + rportfwd (also P4 early)

## P2 checklist

- [x] `encoders.c`: base64, base64url, netbios, mask (xor)
- [x] `profile.c` `apply()` full opcode switch (official profile.cpp)
- [x] `profile.c` `recover()` reverse transforms
- [x] `channel_http.c` GET/POST go through apply + recover (no hardcoded Cookie/`?id=` primary path)
- [x] Host header override (`SETTING_HOST_HEADER` / IN_ADD_HEADER_HOST)
- [x] Offline VM unit test: `tests/test_profile_vm.c`
- [x] Settings-only jar bridge: `tools/bridge/LinuxBeaconBridge.java`
- [x] `gen_payload.sh --bridge jar` + `CustomBeacon.cna` UI hooks
- [ ] Live retest: default profile still checks in
- [ ] Live retest: non-default profile with jar-exported settings blob

