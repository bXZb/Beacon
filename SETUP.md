## Setup

### Dependencies (Linux build host)

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libcurl4-openssl-dev python3
```

### Teamserver public key

1. On the teamserver (folder with `.cobaltstrike.beacon_keys`):
   ```bash
   java -cp /path/to/cobaltstrike.jar /path/to/LinuxBeacon/tools/DumpPublicKey.java
   ```
   Produces `publickey.txt` (hex).
2. On the build host:
   ```bash
   python3 tools/hexkey_to_der.py publickey.txt tools/fixtures/publickey.der
   ```

### Build with defaults (dev)

```bash
bash tools/gen_payload.sh --host 192.168.1.10 --port 80 --https 0
# → implant/bin/beacon
```

### Aggressor

1. Edit `CustomBeacon.cna` line 1 to absolute project path.
2. Load script in CS client (Linux).
3. Menu **LinuxBeacon → Generate Linux Beacon**.

### Teamserver listener

Use an HTTP/S listener with the **default** malleable profile for P0
(metadata in Cookie, POST `submit.php?id=`). Custom profiles require P2.
