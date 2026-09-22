"""CA-07.1 — the vocabulary for *what named an artefact*, and for why nothing did.

Separate from ``artefact_identity_enums`` on purpose. That module answers "are
these two observations the same thing?" (matching and deduplication). This one
answers "what is this thing called, and how do we know?" — a different question
with a different consumer: CA-07.1 states what is unknown about an artefact and
what deeper access would answer, and it can only do that honestly if the reason
something is unnamed is recorded rather than inferred at the surface.

The distinction this module exists to preserve: **"we looked and could not tell"
is not the same as "we never looked."** Only the first is an argument for
granting deeper access. Collapsing them is how a product ends up asking for SSH
to learn something an unauthenticated request would have answered for free.
"""

from enum import StrEnum


class ArtefactIdentityBasis(StrEnum):
    """What the artefact's name was read from, strongest first.

    Ordering is meaningful — ``IDENTITY_BASIS_PRECEDENCE`` below is the single
    definition of which evidence wins when a host offers several.
    """

    # --- Established by deep verification (CA-08.4) -----------------------
    # These outrank everything below because they are read *inside* the host
    # under a person's explicit approval, rather than inferred from what it
    # chose to say over the network. A web page can title itself anything; the
    # image a container was built from cannot.

    #: The image a container was built from — `docker container inspect`. The
    #: strongest identity evidence this platform can obtain: it names the
    #: software and its version as deployed, and it is what closes #249, where
    #: Plane and a monitoring dashboard were indistinguishable on port 8080.
    CONTAINER_IMAGE = "container_image"
    #: The executable holding the listening socket. Answers "what is behind this
    #: port" for anything not in a container, which a process list alone cannot.
    LISTENING_PROCESS = "listening_process"
    #: What the operating system calls itself, from `/etc/os-release`. Names the
    #: host rather than the service on it, so it ranks below the two above — but
    #: it is a definite answer where the others found nothing.
    OS_RELEASE = "os_release"

    # --- Read from the network (CA-07.1) ----------------------------------

    #: The application naming itself: `<title>` on an open web port. The
    #: strongest signal available *without* logging in, and the cheapest to
    #: obtain.
    HTTP_TITLE = "http_title"
    #: The subject on the certificate a TLS port already presents on connect.
    TLS_CERTIFICATE = "tls_certificate"
    #: What nmap's version detection concluded is running (`product`/`version`).
    SERVICE_PRODUCT = "service_product"
    #: The MAC OUI vendor. Weak — it names who made the box, not what it does —
    #: but it is the only thing that can name a host with nothing listening.
    HARDWARE_VENDOR = "hardware_vendor"


IDENTITY_BASIS_PRECEDENCE: tuple[ArtefactIdentityBasis, ...] = (
    # Verified from inside the host, under an approval, first. An artefact that
    # has been verified must not keep reading as whatever a web page called
    # itself — that would make deep verification cost a person a decision and
    # change nothing they can see.
    ArtefactIdentityBasis.CONTAINER_IMAGE,
    ArtefactIdentityBasis.LISTENING_PROCESS,
    ArtefactIdentityBasis.OS_RELEASE,
    # Søren, 2026-08-27, ruling on the contradiction #316 surfaced: a
    # certificate outranks a page title. It is the stronger claim — a
    # certificate is issued to a name and presented as an assertion of it, while
    # a page can title itself anything, which is exactly how two artefacts came
    # to be called "Site doesn't have a title (text/html)". The two were the
    # other way round here, and the ordering below is the single definition of
    # which evidence wins, so this is the only place it changes.
    ArtefactIdentityBasis.TLS_CERTIFICATE,
    ArtefactIdentityBasis.HTTP_TITLE,
    ArtefactIdentityBasis.SERVICE_PRODUCT,
    ArtefactIdentityBasis.HARDWARE_VENDOR,
)


class ArtefactIdentityUndetermined(StrEnum):
    """Why an artefact has no determined name.

    Each member is a *different conversation with a person*, which is why they
    are not one "unknown" value. CA-07.1's surface turns these into what it
    offers: only ``PROBED_NOTHING_IDENTIFYING`` is an honest argument for
    deeper access.
    """

    #: Nothing answered on any scanned port. Deeper access has nothing to reach.
    NOTHING_LISTENING = "nothing_listening"
    #: Something answered, but the scan never ran version detection, so no
    #: identifying evidence was ever requested. **Not** a case for credentials —
    #: the cheap answer has not been attempted yet.
    NOT_PROBED = "not_probed"
    #: Version detection ran, the host answered, and nothing in the response
    #: named it. This is the genuine remainder, and the only one where deeper
    #: access is the next reasonable step.
    PROBED_NOTHING_IDENTIFYING = "probed_nothing_identifying"
    #: CA-09A.2 — nothing answered, **and** the Collector was never permitted to
    #: see hardware addresses, so the one basis that can name a silent device
    #: was unreachable by construction. Its own member rather than
    #: ``NOTHING_LISTENING`` because those are opposite statements: one says
    #: there is nothing here, the other says we were unable to look. Reporting
    #: the second as the first is how 242 echoes off a userspace network stack
    #: became artefacts (#175), and it is the conflation Søren approved
    #: ``NET_RAW`` on 2026-08-25 to end.
    HARDWARE_NOT_VISIBLE = "hardware_not_visible"
    #: CA-08.4 — deep verification ran, logged in, and what it read still did
    #: not name the artefact. The end of the line: every cheaper answer was
    #: tried and a person already approved the expensive one. Its own member
    #: because *"we went in and it still would not say"* must not be reported as
    #: *"nobody has looked closely"*, which would invite asking for the approval
    #: that was already given.
    VERIFIED_NOTHING_IDENTIFYING = "verified_nothing_identifying"


#: How a determined identity was arrived at, in words a non-technical reader can
#: weigh. Held beside the vocabulary for the same reason
#: ``IDENTITY_UNDETERMINED_EXPLANATION`` below is: a name read off a TLS
#: certificate and one read off a hardware vendor are different strengths of
#: claim, and every surface that says so must say it identically.
#:
#: ⚠️ The tenant carries a hand-maintained copy of this map
#: (``artefactInventoryCopy.ts``). It predates this one and is not yet fed from
#: here; until it is, a change to either must be made to both.
IDENTITY_BASIS_PHRASE: dict[str, str] = {
    ArtefactIdentityBasis.CONTAINER_IMAGE.value: "from the container image it runs",
    ArtefactIdentityBasis.LISTENING_PROCESS.value: "from the process listening on it",
    ArtefactIdentityBasis.OS_RELEASE.value: "from its own operating system record",
    ArtefactIdentityBasis.HTTP_TITLE.value: "from the page it serves",
    ArtefactIdentityBasis.TLS_CERTIFICATE.value: "from its security certificate",
    ArtefactIdentityBasis.SERVICE_PRODUCT.value: "from the service banner it returned",
    ArtefactIdentityBasis.HARDWARE_VENDOR.value: "from its hardware manufacturer",
}


#: Business-language explanation per reason. Held beside the vocabulary so the
#: surface composes sentences from one source rather than restating the model.
IDENTITY_UNDETERMINED_EXPLANATION: dict[str, str] = {
    ArtefactIdentityUndetermined.NOTHING_LISTENING.value: (
        "Nothing answered on this address, so there was nothing to identify it by."
    ),
    ArtefactIdentityUndetermined.NOT_PROBED.value: (
        "This has not been examined closely enough to identify. The approved scan "
        "profile does not include service identification."
    ),
    ArtefactIdentityUndetermined.PROBED_NOTHING_IDENTIFYING.value: (
        "This was examined and answered, but nothing it returned identified what it is."
    ),
    ArtefactIdentityUndetermined.HARDWARE_NOT_VISIBLE.value: (
        "Nothing answered on this address, and this Collector cannot see hardware "
        "addresses on the network it runs on — so a device that answers nothing "
        "cannot be named. Granting it that visibility would say whether anything "
        "is here at all."
    ),
    ArtefactIdentityUndetermined.VERIFIED_NOTHING_IDENTIFYING.value: (
        "This was examined from the inside, with approval, and still did not identify "
        "itself. There is nothing further to try automatically."
    ),
}
