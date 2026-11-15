# -*- coding: utf-8 -*-
"""bump_live_waits.py - the beacon's sleep-cycle task scheduling makes kit
BOF output land 3-4.5 min after dispatch (observed 2026-11-17: outputs at
+176s/+254s); widen the live-test windows to cover them."""
import io

P = r"C:\Users\Public\kit_bg_live.py"
s = io.open(P, encoding="utf-8").read()

old1 = 'print("bg asyncx dispatched")\ntime.sleep(60)'
new1 = 'print("bg asyncx dispatched")\ntime.sleep(300)'
assert old1 in s, "asyncx wait not found"
s = s.replace(old1, new1)

old2 = 'print("follow-up dispatched via asyncx2")\ntime.sleep(90)'
new2 = 'print("follow-up dispatched via asyncx2")\ntime.sleep(420)'
assert old2 in s, "asyncx2 wait not found"
s = s.replace(old2, new2)

io.open(P, "w", encoding="utf-8", newline="").write(s)
print("live waits bumped: 300s / 420s")
