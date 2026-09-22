"""CA-09A.3 (#315) — what an artefact *does*, in the reader's language.

Søren, 2026-08-26: *"how do we map the found artefacts and name them so we know
what they are and do?"*

CA-07.1 and CA-08.4 answered the first half: an artefact can now be named, and
says what the name was read from. The second half is still missing. Knowing a
host runs *Uvicorn* does not tell anyone it serves an API, and a slot mapping is
asking exactly that — **what does this do for the business?**

Kept separate from ``ArtefactType``, which it is derived from, because the two
answer different questions and are read by different people. ``ArtefactType`` is
a classification — *Web service* — and belongs on a chip. A function is a claim
about the estate, written to be read in a sentence by someone deciding whether a
business service could depend on this.

📌 **Whatever this produces is evidence for a suggestion, never a mapping.** It
describes; a person decides.
"""

from __future__ import annotations

from enum import StrEnum


class ArtefactFunction(StrEnum):
    """What this artefact does for the organisation, as far as the scan can tell."""

    #: Answers requests from people or other systems.
    SERVES_APPLICATION = "serves_application"
    #: Holds data that other things read and write.
    STORES_DATA = "stores_data"
    #: Carries or directs traffic for everything else.
    CARRIES_NETWORK_TRAFFIC = "carries_network_traffic"
    #: Decides who is allowed in.
    VERIFIES_IDENTITY = "verifies_identity"
    #: A way in for administration. Deliberately its own answer: an exposed
    #: management path is a different conversation from a business service, and
    #: reporting it as one would put a jump host in a dependency chain.
    ALLOWS_ADMINISTRATION = "allows_administration"
    #: Several purposes answered and they disagree. Its own answer rather than
    #: ``UNDETERMINED``, because "we heard two things" and "we heard nothing"
    #: are different findings and only one of them is a dead end — reporting the
    #: first as the second throws away evidence a person could act on
    #: immediately.
    SERVES_SEVERAL_PURPOSES = "serves_several_purposes"
    #: Nothing observed says what it is for. An honest answer, not a failure.
    UNDETERMINED = "undetermined"


#: What each function means for the business, in one sentence a non-technical
#: reader can act on. Held beside the vocabulary so every surface composes from
#: one source rather than restating the model — the same rule
#: ``IDENTITY_UNDETERMINED_EXPLANATION`` follows.
ARTEFACT_FUNCTION_STATEMENT: dict[str, str] = {
    ArtefactFunction.SERVES_APPLICATION.value: (
        "Answers requests from people or other systems, so anything that calls it stops when it stops."
    ),
    ArtefactFunction.STORES_DATA.value: (
        "Holds data that other services read and write, so what it loses, they lose."
    ),
    ArtefactFunction.CARRIES_NETWORK_TRAFFIC.value: (
        "Carries traffic for everything else here — when it fails, things that never touch it fail too."
    ),
    ArtefactFunction.VERIFIES_IDENTITY.value: (
        "Decides who is allowed in, so nobody signs in to anything while it is down."
    ),
    ArtefactFunction.ALLOWS_ADMINISTRATION.value: (
        "Offers a way in for administration. It is a route into the estate rather than a service the "
        "business depends on."
    ),
    ArtefactFunction.SERVES_SEVERAL_PURPOSES.value: (
        "Answers for more than one purpose at once. From outside, a device with an administrative "
        "page and a server genuinely doing both look identical, so somebody who knows the estate "
        "should say which this is."
    ),
    ArtefactFunction.UNDETERMINED.value: (
        "Nothing observed says what this is for. It has not been ruled out — it has not been established."
    ),
}

#: Appended when the function rests only on a port number rather than on
#: anything the host actually returned. #249 made that distinction explicit for
#: services; it matters more here, because a *function* reads as a statement
#: about the business and would otherwise carry a certainty the evidence has
#: not earned.
FUNCTION_FROM_PORT_NUMBER_ALONE = (
    "This rests on the port number alone — nothing was asked of it directly."
)
