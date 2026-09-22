"""CA-06.3 — how one artefact relates to another.

The inventory was a flat list: it could say *what* an organisation has, but not
that this application runs on that host, or that this name resolves to that
address. This vocabulary makes the inventory describe a structure.

Strictly artefact-to-artefact. Business dependency mapping — which Business
Service depends on which artefact — is CA-09A's job and has its own model
(``SlotInstance``); nothing here is a substitute for it.

Two things every relationship must carry, and the reason both are enums rather
than free text: **who says so** and **how sure**. A relationship the platform
inferred from a scan is a different kind of claim from one a person asserted,
and the difference has to survive into every screen that shows it — the platform
recommends and explains, it never presents its own inference as established
fact.
"""

from enum import StrEnum


class ArtefactRelationshipType(StrEnum):
    """What the relationship actually says, from the source artefact's side.

    Deliberately small. Each value is here because discovery evidence can
    actually support it or a person can meaningfully assert it — not to cover
    every relationship a graph could theoretically hold. Adding a type is
    cheap; removing one after it has been written to live rows is not.
    """

    #: The source runs on the target — an application on a host, a container on
    #: a node. The most common structural fact discovery can establish.
    RUNS_ON = "runs_on"
    #: The source is a hostname/domain that resolves to the target address.
    RESOLVES_TO = "resolves_to"
    #: The source is reached through the target — a service behind a load
    #: balancer, gateway or proxy.
    SERVED_BY = "served_by"
    #: The source talks to the target to do its job. Directional and weaker
    #: than RUNS_ON: it says traffic was observed, not that one hosts the other.
    CONNECTS_TO = "connects_to"
    #: The source is a member of the target grouping — a node in a cluster, an
    #: instance in a pool.
    MEMBER_OF = "member_of"
    #: The target manages the source's lifecycle — an orchestrator over what it
    #: schedules.
    MANAGED_BY = "managed_by"


class ArtefactRelationshipOrigin(StrEnum):
    """Who says this relationship exists.

    The distinction the AC calls for: an inferred relationship must never be
    presentable as established fact, and that is only possible if the record
    itself remembers which it was. Never defaulted — a relationship with no
    stated origin would be exactly the ambiguity this prevents.
    """

    #: Read directly out of scanner evidence (a provider's own topology, a
    #: resolved DNS answer). The platform saw it.
    OBSERVED = "observed"
    #: The platform derived it from other facts rather than seeing it stated.
    #: Always a proposal, never a conclusion.
    INFERRED = "inferred"
    #: A person said so. The strongest origin, and the only one that outranks
    #: what a later scan reports.
    ASSERTED_BY_PERSON = "asserted_by_person"


class ArtefactRelationshipConfidence(StrEnum):
    """How sure the origin is of what it is claiming.

    Words rather than a 0.0–1.0 float on purpose: this value is read by people,
    and a number invites false precision — 0.72 implies a calibration nothing in
    this pipeline actually has. Three bands are honest about what the evidence
    supports.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ArtefactRelationshipState(StrEnum):
    """Whether the relationship is currently held to be true.

    A relationship that stops being observed is **withdrawn**, not deleted —
    the same rule the rest of CA-06 follows. "These two used to be connected,
    and stopped on the 14th" is a fact worth keeping; deleting the row destroys
    the only evidence the connection ever existed.
    """

    ACTIVE = "active"
    WITHDRAWN = "withdrawn"
    #: A person said this relationship is not real. Distinct from WITHDRAWN,
    #: which only means it stopped being observed.
    REJECTED = "rejected"


#: Origins whose claims a person has personally stood behind. A rescan may add
#: to these, but must never quietly overwrite or withdraw one — the platform
#: does not overrule a human decision on its own.
HUMAN_AUTHORED_ORIGINS: frozenset[ArtefactRelationshipOrigin] = frozenset(
    {ArtefactRelationshipOrigin.ASSERTED_BY_PERSON}
)

#: Origins that are the platform's own claim rather than a person's, and so must
#: always be shown as such.
PLATFORM_AUTHORED_ORIGINS: frozenset[ArtefactRelationshipOrigin] = frozenset(
    {ArtefactRelationshipOrigin.OBSERVED, ArtefactRelationshipOrigin.INFERRED}
)

# Audit event names — dot-separated snake_case, matching the artefact domain's
# existing convention in artefact_identity_enums.py.
ARTEFACT_RELATIONSHIP_AUDIT_RECORDED = "artefact_relationship.recorded"
ARTEFACT_RELATIONSHIP_AUDIT_WITHDRAWN = "artefact_relationship.withdrawn"
ARTEFACT_RELATIONSHIP_AUDIT_REPOINTED = "artefact_relationship.repointed"
