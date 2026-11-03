"""
Soft-Delete Quarantine Engine.
Provides reversible fail-safe execution for destructive file operations.
"""

import os
import shutil
import time
import json
from typing import Dict, Any, Optional, Tuple


class QuarantineEngine:
    """
    Intercepts destructive file operations (delete, unlink, remove).
    Moves targets to a timestamped .sentinel_trash quarantine rather than permanent unrecoverable deletion.
    """

    def __init__(self, quarantine_base_dir: str):
        self.quarantine_base_dir = os.path.realpath(quarantine_base_dir)
        os.makedirs(self.quarantine_base_dir, exist_ok=True)
        self.receipts_log = os.path.join(self.quarantine_base_dir, "quarantine_receipts.jsonl")

    def soft_delete(self, target_path: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Moves the target file/folder to quarantine.
        Returns (success, message, receipt).
        """
        resolved_path = os.path.realpath(os.path.abspath(target_path))
        if not os.path.exists(resolved_path):
            return False, f"File does not exist: {target_path}", {}

        timestamp = int(time.time())
        basename = os.path.basename(resolved_path)
        quarantine_filename = f"{timestamp}_{basename}"
        dest_path = os.path.join(self.quarantine_base_dir, quarantine_filename)

        try:
            shutil.move(resolved_path, dest_path)
            
            receipt = {
                "timestamp": timestamp,
                "original_path": resolved_path,
                "quarantine_path": dest_path,
                "action": "soft_delete",
                "status": "quarantined",
            }
            
            # Append audit receipt
            with open(self.receipts_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(receipt) + "\n")

            return True, f"File safely quarantined to {dest_path}", receipt

        except Exception as e:
            return False, f"Failed to quarantine file: {str(e)}", {}

    def restore_quarantined_file(self, original_path: str) -> Tuple[bool, str]:
        """Restores the most recent quarantined version of a file."""
        if not os.path.exists(self.receipts_log):
            return False, "No quarantine receipts found."

        receipts = []
        with open(self.receipts_log, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    receipts.append(json.loads(line))

        # Find latest matching original_path
        matches = [r for r in receipts if r.get("original_path") == os.path.realpath(original_path)]
        if not matches:
            return False, f"No quarantine record found for: {original_path}"

        latest = matches[-1]
        quarantine_file = latest["quarantine_path"]
        if not os.path.exists(quarantine_file):
            return False, f"Quarantined copy missing: {quarantine_file}"

        shutil.move(quarantine_file, latest["original_path"])
        return True, f"Successfully restored {original_path}"
