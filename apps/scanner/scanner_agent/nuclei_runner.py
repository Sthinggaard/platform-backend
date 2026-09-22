"""CA-04.4 — executes a real Nuclei vulnerability-template scan against the
command's own approved targets, using only the signed, pinned template
pack CA-03.2 already baked into the image (``tool_checks.NUCLEI_TEMPLATES_DIR``).

Deliberately never triggers an arbitrary upstream fetch: always passes an
explicit ``-t <pinned templates dir>`` rather than relying on nuclei's own
default template-path resolution, and always passes ``-duc`` (disable
update check) so nuclei never phones home to check for a newer
nuclei-templates release or binary version at scan time. Never passes
``-update-templates``/``-ut`` — that flag is exactly the "arbitrary
upstream fetch" CA-03's own refinement flagged as conflicting with the
platform's "prohibit arbitrary template downloads" rule; this module must
never introduce it. Mirrors ``nmap_runner.py``/``subfinder_runner.py``'s
own scope and style.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from scanner_agent.tool_checks import NUCLEI_TEMPLATES_DIR

#: Template trees this agent will run, and the only strings it will ever join
#: to the pinned pack root.
#:
#: The server chooses which of these a host is worth scanning
#: (``discovery_template_scoping``), but it does **not** get to name a path. A
#: tree arrives as a bare name and is accepted only if it is in this set, so a
#: malformed or hostile command cannot walk out of the pack directory or point
#: nuclei at templates nobody reviewed. That is the whole reason the wire
#: carries names rather than the paths the server could have computed.
#:
#: Deliberately excludes cloud/code/dast/file/headless: a remote host scan
#: cannot match them, and admitting them here would let a scope include work
#: that can only ever come back empty.
ALLOWED_TEMPLATE_TREES: frozenset[str] = frozenset(
    {"http", "network", "ssl", "dns", "javascript"}
)


class NucleiNotAvailableError(RuntimeError):
    """Raised when the nuclei binary or the pinned template pack is missing."""


class NucleiScanError(RuntimeError):
    """Raised when the nuclei process fails outright.

    A **timeout is no longer one of these.** It became a reported outcome
    (``NucleiScanResult.completed``) rather than an exception, because raising
    it here meant the only thing the caller could do was discard the partial
    output and report a clean empty scan — which is exactly what happened on
    every run for ten days. Kept because a future process-level failure needs
    somewhere to land, and because nuclei's own nonzero exit deliberately is
    not one (see run_nuclei_scan).
    """


@dataclass(frozen=True)
class NucleiScanResult:
    target: str
    raw_output: str
    #: Whether nuclei ran to the end of its own work on this target. False when
    #: it was killed at the time budget — the output is then whatever it had
    #: already written, which is real but is **not** the whole answer for this
    #: target. Defaulted True so the field is additive for existing callers.
    completed: bool = True
    #: Every host this result covers. One invocation now scans all the hosts
    #: that share a template scope, so ``target`` is a label for the group and
    #: this is the list a caller reports. Defaults to ``(target,)`` so a
    #: single-target result needs no special case.
    targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.targets:
            object.__setattr__(self, "targets", (self.target,))


def _decode_partial(output: bytes | str | None) -> str:
    """Whatever nuclei had written before it was killed.

    ``TimeoutExpired`` carries the captured stream as **bytes** even when the
    call passed ``text=True`` (CPython does not run the timeout path through
    the text decoder), so this cannot assume a string. ``errors="replace"``
    because a kill lands wherever it lands: a truncated multi-byte character at
    the cut would otherwise raise, and losing a whole scan's findings to the
    last half-character of it is the failure this function exists to prevent.
    """
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def resolve_template_paths(templates_dir: Path, trees: list[str] | None) -> list[Path]:
    """The ``-t`` arguments for a scope, or the whole pack when none is given.

    ``trees`` is the server's scope. Only names in ``ALLOWED_TEMPLATE_TREES``
    are honoured and anything else is dropped — the agent never joins an
    arbitrary string to the pack root.

    Two different empties, and conflating them would be a silent coverage cut:

    * ``None`` — the command carried no scope at all, which is what an older
      server sends. The whole pack runs, exactly as before.
    * every name unusable — a scope arrived and nothing in it was recognised.
      Running the whole pack here would silently ignore a deliberate narrowing,
      so this returns nothing and the caller treats it as a failure rather than
      quietly scanning more than it was told to.

    A tree the pack does not actually contain is skipped: nuclei errors on a
    missing ``-t`` path, and losing a whole host's scan to one absent directory
    would be worse than scanning the trees that are there.
    """
    if trees is None:
        return [templates_dir]
    resolved = []
    for tree in trees:
        if not isinstance(tree, str) or tree not in ALLOWED_TEMPLATE_TREES:
            continue
        candidate = templates_dir / tree
        if candidate.is_dir():
            resolved.append(candidate)
    return resolved


def run_nuclei_scan(
    target: str | list[str],
    *,
    templates_dir: Path = NUCLEI_TEMPLATES_DIR,
    timeout: float = 180.0,
    template_trees: list[str] | None = None,
) -> NucleiScanResult:
    """One nuclei invocation, over one host or a group that shares a scope.

    A group is passed to nuclei's own ``-list`` rather than looped, because the
    template set is loaded once per invocation and that load is the dominant
    cost (46s for the http tree, measured; ~20s of actual work per target).

    ⚠️ **Truncation is reported for the whole group.** nuclei's JSONL says which
    host produced a finding but not which hosts it finished, so a kill part-way
    through means the honest answer for every host in the group is "not
    complete". That over-reports rather than under-reports, which is the only
    safe direction: the platform treats a later scan finding nothing as proof a
    fix held, so claiming a host was fully scanned when it was not could
    silently discharge a real finding.
    """
    hosts = [target] if isinstance(target, str) else list(target)
    if not hosts:
        raise NucleiScanError("run_nuclei_scan was given no target to scan.")
    label = hosts[0] if len(hosts) == 1 else f"{hosts[0]} +{len(hosts) - 1} more"

    if shutil.which("nuclei") is None:
        raise NucleiNotAvailableError("nuclei is not installed or not on PATH.")
    if not (templates_dir.is_dir() and any(templates_dir.iterdir())):
        raise NucleiNotAvailableError(
            f"Pinned nuclei template pack not found at {templates_dir} — refusing to fall back to an "
            "unpinned template fetch."
        )

    template_paths = resolve_template_paths(templates_dir, template_trees)
    if not template_paths:
        raise NucleiScanError(
            f"Command scoped {target} to template trees this agent does not have "
            f"({template_trees!r}). Refusing to scan the whole pack instead — that would "
            "ignore a deliberate narrowing and report far more work than was asked for."
        )

    command = ["nuclei", "-duc", "-silent", "-jsonl"]
    for path in template_paths:
        command += ["-t", str(path)]

    # `-target` takes one host; a group goes through a list file, which is
    # nuclei's own interface for exactly this and avoids a command line that
    # grows with the estate.
    with tempfile.TemporaryDirectory() as tmp:
        if len(hosts) == 1:
            command += ["-target", hosts[0]]
        else:
            list_file = Path(tmp) / "targets.txt"
            list_file.write_text("\n".join(hosts) + "\n")
            command += ["-list", str(list_file)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # 🐞 A timeout used to be raised here, swallowed one frame up, and
            # returned as an empty result — so a scan that was **killed mid-way**
            # arrived at the platform indistinguishable from one that ran to the
            # end and matched nothing. Every nuclei run since 2026-08-27 took that
            # path (the approved scope was a /24, which cannot finish in the
            # budget) and each was recorded as a clean, empty scan.
            #
            # That is not a cosmetic mislabel. The platform's resolution model is
            # that a person records the action they took and a **later scan finding
            # nothing** is what proves it resolved — so a timeout presented as
            # "found nothing" can silently discharge a real, unfixed finding. An
            # assertion must never be able to pose as an observation.
            #
            # nuclei streams JSONL as it matches, so what it wrote before the kill
            # is genuine evidence and is kept. The target is reported incomplete.
            return NucleiScanResult(
                target=label,
                raw_output=_decode_partial(exc.stdout),
                completed=False,
                targets=tuple(hosts),
            )

    # nuclei exits non-zero when templates match findings — that is a
    # successful scan outcome, not a process failure, so returncode is not
    # checked here (unlike nmap/subfinder, whose nonzero exit always means
    # a real error).
    return NucleiScanResult(target=label, raw_output=result.stdout, targets=tuple(hosts))


def run_nuclei_discovery(
    targets: list[str] | list[tuple[str, list[str] | None]],
    *,
    templates_dir: Path = NUCLEI_TEMPLATES_DIR,
    timeout: float = 180.0,
) -> list[NucleiScanResult]:
    """Every approved target this command actually covers — one target
    failing does not abort the batch; a partial result is still a real
    result, mirroring run_subfinder_discovery/run_discovery_scan.

    ``timeout`` is **per target**, and each result says whether its own target
    finished. A caller reporting the batch must read ``completed`` rather than
    assuming an empty ``raw_output`` means a clean scan.

    NucleiNotAvailableError — missing binary or missing/empty pinned template
    pack — would repeat identically for every remaining target and must never
    be silently swallowed into a false "scanned, found nothing" result, so it
    propagates immediately instead of being collected as one target's failure.
    """
    # Grouped by template scope, then one invocation per group.
    #
    # 🐞 Scanning one host per invocation made nuclei re-load and re-compile the
    # whole template set for every host. Measured on the Pi against the pinned
    # v10.4.7 pack: the http tree costs **46s of fixed load** plus ~20s of
    # actual work per target. Eight hosts therefore paid 371s of pure repeated
    # loading — **41% of the 676s run on 2026-09-07** — before a single
    # additional check was performed, and it is why the four http hosts were
    # still killed at their share of the budget even after scoping cut 82% of
    # the pack.
    #
    # Grouping by scope rather than scanning everything at once is deliberate:
    # the whole point of the scope is that these hosts get *different* template
    # sets, so one invocation per distinct set is the fewest possible while
    # still honouring it. Here that is 2 invocations instead of 8.
    grouped: dict[tuple[str, ...] | None, list[str]] = {}
    for entry in targets:
        # A bare string is a target with no scope — the shape an older command
        # produces, and the shape every other runner uses.
        target, trees = entry if isinstance(entry, tuple) else (entry, None)
        key = tuple(trees) if trees is not None else None
        grouped.setdefault(key, []).append(target)

    # The budget was divided per target by the caller; a group covering several
    # targets is owed all of their shares.
    return [
        run_nuclei_scan(
            group,
            templates_dir=templates_dir,
            timeout=timeout * len(group),
            template_trees=list(key) if key is not None else None,
        )
        for key, group in grouped.items()
    ]
