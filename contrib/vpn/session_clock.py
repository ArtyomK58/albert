"""Read the generation/start of the supervisor-owned VPN process, without logs or secrets."""
import os
from pathlib import Path
import re


def process_session(pid_file, namespace_file, binary, proc=Path('/proc'), ticks=None):
    if not all((pid_file, namespace_file, binary)):
        return {}
    try:
        p = Path(pid_file)
        st = p.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            return {}
        pid = p.read_text().strip()
        if not re.fullmatch(r'[1-9][0-9]*', pid) or int(pid) <= 1:
            return {}
        process = proc / pid
        stat = (process / 'stat').read_text()
        start = int(stat[stat.rfind(')') + 2:].split()[19])
        argv = (process / 'cmdline').read_bytes().split(b'\0')
        if not argv or os.fsdecode(argv[0]) != binary:
            return {}
        if not os.path.samefile(process / 'ns/net', namespace_file):
            return {}
        boot = next(int(line.split()[1]) for line in (proc / 'stat').read_text().splitlines()
                    if line.startswith('btime '))
        frequency = ticks or os.sysconf('SC_CLK_TCK')
        again = (process / 'stat').read_text()
        if p.read_text().strip() != pid or int(again[again.rfind(')') + 2:].split()[19]) != start:
            return {}  # PID turnover during observation is never a confirmed generation.
        return {'session_id': pid + ':' + str(start), 'session_started_at': boot + start / frequency}
    except (OSError, ValueError, IndexError, StopIteration):
        return {}
