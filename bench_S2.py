# --------------------------------------------------------------------------- #
# Scenario groups
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExtensionCase:
    id: str
    tool_name: str
    arguments: dict
    category: str
    label: str
    expected: str
    capability: str
    synthetic_provenance: str
    note: str
    scope: str = "engine"


@dataclass(frozen=True)
class SelectedGroupA:
    ids: tuple[str, ...]
    count: int
    label: str


def group_a_ids(partition: str = "development") -> tuple[str, ...]:
    if partition != "development":
        raise ValueError(f"group A is development-only; got partition={partition!r}")
    assigned = corpus_module.partition_map()
    return tuple(
        sorted(case.id for case in corpus_module.CASES if assigned.get(case.id) == "development")
    )


def load_group_a_selection(path: Path) -> SelectedGroupA:
    payload = load_json(path)
    ids = tuple(payload["ids"])
    if len(ids) != len(set(ids)):
        raise ValueError("group A selection contains duplicate scenario ids")
    invalid = [sid for sid in ids if sid not in group_a_ids()]
    if invalid:
        raise ValueError(f"group A selection contains ids not in the development partition: {invalid}")
    return SelectedGroupA(ids=ids, count=len(ids), label="development-coverage")
