import os
import sys
from datetime import datetime, timedelta, timezone
from logging import getLogger

import psutil

_logger = getLogger(__name__)


def check_process(filename, kill_in: int = 0):
    def is_debugged():
        """
        Method to check if the current code is being debugged
        """
        import inspect

        for frame in inspect.stack():
            if "pydevd" in frame[1]:
                return True
        return False

    app_filename = str(os.path.basename(filename))
    app_folder = str(os.path.dirname(filename))
    app_process = psutil.Process()

    is_debugged = is_debugged()

    for proc in psutil.process_iter():
        try:
            # Get process name and pid from a process object.
            process_name = proc.name()
            if "py" in process_name.lower():
                cmd_found = [
                    item
                    for item in proc.cmdline()
                    if (
                        app_filename.lower() in item.lower()
                        and (app_folder.lower() in item.lower())
                    )
                ]
                if cmd_found and proc.pid != app_process.pid and not is_debugged:
                    msg = (
                        f"Stopping the current integration {app_process.pid}, it might have another older instance running,"
                        f" check if is feasible or not older pid: {proc.pid} - cwd: {proc.cwd()} - "
                        f"since: {datetime.fromtimestamp(proc.create_time())} - cmdline: {' '.join(proc.cmdline()).split('--')[0]}"
                    )

                    if kill_in > 0:
                        now = datetime.now(tz=timezone.utc)
                        pid_date = datetime.fromtimestamp(
                            proc.create_time(), tz=timezone.utc
                        )
                        if pid_date + timedelta(minutes=kill_in) < now:
                            proc.terminate()
                            msg += f"\n{proc.pid} terminated!!!!!!"

                    _logger.critical(msg)
                    sys.exit(1)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
