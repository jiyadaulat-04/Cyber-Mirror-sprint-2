import os
import re
import tempfile
from pathlib import Path


def update_nginx_config(
    config_path: Path,
    selected_mitigations: list[str],
    approved_mitigations: dict[str, str]
) -> None:

    config_path = Path(config_path)

    if not config_path.is_file():
        raise FileNotFoundError(
            f"Nginx configuration not found: {config_path}"
        )

    existing_lines = config_path.read_text(
        encoding="utf-8"
    ).splitlines()

    selected = {
        header.lower(): header
        for header in selected_mitigations
        if header in approved_mitigations
    }

    updated_lines = []
    replaced_headers = set()

    header_pattern = re.compile(
        r"^\s*add_header\s+([A-Za-z0-9-]+)\s+",
        re.IGNORECASE
    )

    for line in existing_lines:
        match = header_pattern.match(line)

        if not match:
            updated_lines.append(line)
            continue

        header_name = match.group(1).lower()

        if header_name not in selected:
            updated_lines.append(line)
            continue

        if header_name in replaced_headers:
            continue

        approved_name = selected[header_name]

        updated_lines.append(
            approved_mitigations[approved_name]
        )

        replaced_headers.add(header_name)

    for header_name, original_name in selected.items():
        if header_name not in replaced_headers:
            updated_lines.append(
                approved_mitigations[original_name]
            )

    configuration = "\n".join(updated_lines) + "\n"

    temp_path = None

    try:
        file_descriptor, temp_name = tempfile.mkstemp(
            prefix=".blue-ai-",
            suffix=".tmp",
            dir=str(config_path.parent)
        )

        temp_path = Path(temp_name)

        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
            newline="\n"
        ) as temporary_file:
            temporary_file.write(configuration)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temp_path, config_path)

    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()