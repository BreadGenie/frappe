"""Rerun the unchanged CI shard only for ticket 08's two accepted flakes."""
import re
import subprocess
import sys
import time
from pathlib import Path

allowed = {"test_rq_pool_idle_cpu_usage", "test_remove_failed_jobs"}
command = [sys.executable, str(Path(__file__).with_name("ci.py"))]
for attempt in range(1, 4):
    print(f"Ticket 08: unchanged Integration shard attempt {attempt}/3", flush=True)
    lines = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as child:
        for line in child.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            lines.append(line)
        status = child.wait()
    if status == 0:
        sys.exit(0)
    output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", "".join(lines))
    failures = re.findall(r"^\s*(?:FAIL|ERROR)\s*:?\s+([A-Za-z0-9_]+)\s*\(", output, re.MULTILINE)
    if not failures or not set(failures) <= allowed or attempt == 3:
        sys.exit(status)
    print("Ticket 08: rerunning accepted flakes without editing tests: " + ", ".join(sorted(set(failures))), flush=True)
    time.sleep(10)
