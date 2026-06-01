from packaging.requirements import Requirement, InvalidRequirement


def parse_requirements(content: str) -> list[tuple[str, str | None]]:
    """Parse requirements.txt content into (name, pinned_version) tuples.

    Args:
        content: Raw requirements.txt text

    Returns:
        List of (package_name, pinned_version_or_None) tuples.
        pinned_version is only set if the requirement uses == operator.
    """
    results = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments, blank lines, and option lines
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        # Extract pinned version (only ==)
        pinned = None
        for spec in req.specifier:
            if spec.operator == "==":
                pinned = spec.version
                break
        results.append((req.name, pinned))
    return results
