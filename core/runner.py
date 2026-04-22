from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from core.models import CommandPlan, ScanRunMetadata
from core.platform_utils import platform_name
from core.results import ResultStore

OutputCallback = Callable[[str], None]


class ScanRunner:
    def __init__(self, result_store: ResultStore) -> None:
        self.result_store = result_store

    def run(
        self,
        plan: CommandPlan,
        targets: list[str],
        run_dir: Path,
        output_callback: OutputCallback | None = None,
    ) -> ScanRunMetadata:
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"
        output_files = {"stdout": stdout_path, "stderr": stderr_path}
        metadata = ScanRunMetadata.create(
            command=plan.argv,
            preview=plan.preview(),
            targets=targets,
            platform=platform_name(),
            output_files=output_files,
        )
        self.result_store.save_command(run_dir, plan.preview())
        try:
            with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout_file, stderr_path.open(
                "w", encoding="utf-8", errors="replace"
            ) as stderr_file:
                process = subprocess.Popen(
                    plan.argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    shell=False,
                )
                assert process.stdout is not None
                assert process.stderr is not None
                for line in process.stdout:
                    stdout_file.write(line)
                    stdout_file.flush()
                    if output_callback:
                        output_callback(line.rstrip("\n"))
                stderr_text = process.stderr.read()
                stderr_file.write(stderr_text)
                metadata.return_code = process.wait()
                metadata.stderr_tail = "\n".join(stderr_text.splitlines()[-12:])
        except KeyboardInterrupt:
            metadata.interrupted = True
            metadata.return_code = None
            if output_callback:
                output_callback("Scan interrupted by user.")
        except FileNotFoundError:
            metadata.return_code = 127
            metadata.stderr_tail = "Nmap executable not found."
            stderr_path.write_text(metadata.stderr_tail + "\n", encoding="utf-8")
        except OSError as exc:
            metadata.return_code = 126
            metadata.stderr_tail = str(exc)
            stderr_path.write_text(str(exc) + "\n", encoding="utf-8")
        finally:
            self.result_store.save_metadata(run_dir, metadata)
        return metadata
