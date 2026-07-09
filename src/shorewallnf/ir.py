"""Family-aware intermediate representation (IR) core.

The nftables-agnostic model the compiler builds and the Generator consumes. Modeled per
ADR-0001 (frozen stdlib ``dataclasses`` — immutable, no I/O) and ADR-0002 (a single
family-aware model; family is data on the IR, scoped as ``both``/``ipv4``/``ipv6``).

This module holds the datatypes — the :class:`Family` scoping enum, :class:`Zone` (with its
:class:`ZoneMember` records), the :class:`Interface`, :class:`Policy`, :class:`Rule` and
:class:`Nat` records the Generator consumes, the :class:`MacroDef`/:class:`MacroRule`
records a rule's ``action`` name resolves to (ADR-0020), and the conntrack-helper types
(:class:`ConntrackHelper`, :class:`HelperDef`, :class:`HelperCapabilities`; ADR-0040).
These are datatype **shapes**; each
feature epic owns the deep per-file semantics (which options/actions are valid, how fields are
populated).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum

# Reserved transparent-proxy constants (ADR-0051 Part A). The tproxy mark is a single
# compiler-supplied reserved value — never a per-rule operator value: ``DIVERT`` and
# ``TPROXY(<port>)`` are markless in surface syntax and the generator injects ``TPROXY_MARK``,
# which one ``ip rule fwmark`` consumes into ``TPROXY_TABLE_ID`` for local delivery. Both reserve
# the top of the 32-bit fwmark / routing-table-id spaces so no provider can collide (the validator
# caps provider ranges at ``1..0xFFFFFFFE``). The two share the numeral but live in disjoint
# namespaces (fwmark vs. routing-table id). ``TPROXY_TABLE_ID`` is not a kernel-reserved id
# ({0, 253, 254, 255}), so teardown can never flush a system table.
TPROXY_MARK = 0xFFFFFFFF
TPROXY_TABLE_ID = 0xFFFFFFFF


class Family(Enum):
    """Address family an IR construct scopes to (ADR-0002).

    ``BOTH`` is dual-stack: the Generator emits it once in the ``inet`` table with no
    family guard, so it matches IPv4 and IPv6 naturally. ``IPV4``/``IPV6`` scope to one
    family. (The nftables output table is always ``inet``; that is a Generator concern,
    not an IR scoping value — hence there is no ``INET`` member here.)
    """

    BOTH = "both"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class ZoneMember:
    """One way a zone is populated (ADR-0002: family lives on membership, not the zone).

    A bare interface (``host is None``) is dual-stack (``Family.BOTH``); a host/CIDR entry
    carries the family of its literal (``Family.IPV4`` or ``Family.IPV6``). A zone is
    therefore dual, v4-only, or v6-only as an emergent consequence of its members.

    ``path``/``line`` are the originating ``file:line`` (set by the parser) so IR-stage errors
    can cite the source; they are ``compare=False`` metadata and do not participate in equality
    (ADR-0001, #316).
    """

    interface: str
    family: Family
    host: str | None = None
    path: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class Zone:
    """A named zone — one family-independent identity (ADR-0002).

    Family is not modeled on the zone; it lives on each :class:`ZoneMember`. ``is_firewall``
    marks the single ``firewall``-type zone (Shorewall's ``$FW``) — the firewall host itself,
    which has no interface members, so ``members`` defaults to empty.

    ``path``/``line`` are the originating ``file:line`` (set by the parser) so IR-stage errors
    can cite the source; they are ``compare=False`` metadata and do not participate in equality
    (ADR-0001, #316).
    """

    name: str
    members: tuple[ZoneMember, ...] = ()
    is_firewall: bool = False
    path: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class Interface:
    """A network interface (device) and its options.

    Zone membership is not modeled here — it lives on :class:`ZoneMember`. Which option
    tokens are valid is the zones/interfaces epic's concern.

    The protective-check options (epic #310) are lifted out of the raw ``options`` passthrough
    into typed fields the generator gates emission on: ``rpfilter``/``tcpflags`` are boolean
    toggles, and ``sfilter`` is the anti-spoof source-network list (empty = disabled). All
    default off, so an interface with none of them set is unchanged. The ``sfilter`` literals
    are recorded verbatim; family classification (v4/v6) is deferred to the generator.
    """

    name: str
    options: tuple[str, ...] = ()
    rpfilter: bool = False
    tcpflags: bool = False
    sfilter: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Policy:
    """A default policy for traffic from one zone to another (the ``policy`` file).

    ``path``/``line`` are the originating ``file:line`` (set by the parser) so IR-stage errors
    can cite the source; they are ``compare=False`` metadata and do not participate in equality
    (ADR-0001, #316).
    """

    source: str
    dest: str
    action: str
    log_level: str | None = None
    path: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class Rule:
    """A single firewall rule, carrying the family it scopes to (ADR-0002).

    ``family`` defaults to ``both``: the Generator emits such a rule once in the ``inet``
    table with no family guard. A literal address or family-specific protocol narrows it to
    ``ipv4``/``ipv6`` (inferred by the parser, not here).

    ``source``/``dest`` are the raw ``zone`` or ``zone:host`` tokens; the generator splits the
    ``zone:host`` narrowing. ``sport`` is the SOURCE PORT column and ``section`` the enclosing
    ``?SECTION`` name (``None`` for rules before any section marker), both verbatim.

    ``path``/``line`` are the originating ``file:line`` (set by the parser) so IR-stage errors
    can cite the source. They are ``compare=False`` metadata: location does not participate in
    equality or hashing, keeping value semantics stable (ADR-0001, #195).
    """

    action: str
    source: str
    dest: str
    proto: str | None = None
    dport: str | None = None
    sport: str | None = None
    section: str | None = None
    family: Family = Family.BOTH
    path: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class MacroRule:
    """One line of a macro/custom-action body: a verdict plus optional narrowing (ADR-0020).

    The body of a :class:`MacroDef` is an ordered tuple of these. ``action`` is a built-in
    verdict (``ACCEPT``/``DROP``/``REJECT`` — the subset epic #176 scopes). ``proto``/``dport``/
    ``sport`` are the protocol/port constraints this body line adds; the resolver intersects
    them with the invoking rule's constraints (source/dest come from the call site, so they are
    not modeled here). ``family`` scopes the line per ADR-0002.
    """

    action: str
    proto: str | None = None
    dport: str | None = None
    sport: str | None = None
    family: Family = Family.BOTH


@dataclass(frozen=True, slots=True)
class MacroDef:
    """A named macro/custom-action definition — an ordered body of verdict templates (ADR-0020).

    Both a Shorewall macro and a custom action are, for the scoped subset, a name plus a body
    that expands to built-in verdicts; they share this one type (ADR-0020 fixes the resolution
    model). A rule whose ``action`` names a ``MacroDef`` is replaced by its :class:`MacroRule`
    body, in order, by the resolver stage. ``family`` scopes the whole definition per ADR-0002.
    """

    name: str
    body: tuple[MacroRule, ...] = ()
    family: Family = Family.BOTH


@dataclass(frozen=True, slots=True)
class Nat:
    """A NAT entry — a v4 ``DNAT`` port-forward (``rules`` file) or source NAT (``snat`` file).

    ``Nat`` is a tagged union over ``action``; which columns are populated depends on it:

    - **DNAT** (``rules``): ``source``/``dest`` are the source/target zones and ``to`` the
      ``host[:port]`` DNAT target (port an optional remap); ``proto``/``dport`` the matched
      protocol and external destination port(s).
    - **MASQUERADE**/**SNAT** (``snat``): ``source_nets`` is the source network list (a
      comma-separated CIDR list stored verbatim for the generator to expand), ``out_interface``
      the egress (out) interface; ``snat_to`` carries the explicit ``SNAT(<addr>)`` address —
      ``None`` for ``MASQUERADE``, which uses the egress interface's own address.

    ``family`` is IPv4 for true NAT (ADR-0002: IPv6 does no NAT) — the default, and always IPv4
    for source NAT — but a ``DNAT`` whose target is an IPv6 literal is scoped :data:`Family.IPV6`
    and compiles to a plain ``ACCEPT`` to the global address instead of NAT.

    ``path``/``line`` are the originating ``file:line`` (set by the parser) so IR-stage errors
    can cite the source; they are ``compare=False`` metadata and do not participate in equality
    (ADR-0001, #316).
    """

    action: str
    source: str = ""
    dest: str = ""
    to: str | None = None
    proto: str | None = None
    dport: str | None = None
    source_nets: str | None = None
    out_interface: str | None = None
    snat_to: str | None = None
    family: Family = Family.IPV4
    path: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class ConntrackHelper:
    """A conntrack helper attached to a flow (the ``conntrack`` file), family-aware (ADR-0040).

    ``name`` is the canonical helper name — a key into the built-in registry
    (:data:`shorewallnf.conntrack.BUILTIN_HELPERS`). The remaining fields are the flow-scope
    narrowing from the ``conntrack`` row that restricts which connections the helper attaches
    to: ``source``/``dest`` are the raw ``zone`` or ``zone:host`` tokens and ``proto``/``dport``
    the matched protocol / destination port(s), verbatim. ``family`` is the resolved family
    (ADR-0002): a v4-only helper, or a row narrowed by a v4 literal, scopes to
    :data:`Family.IPV4`. Populating these is the parser's job (#220), not this stage's.
    """

    name: str
    source: str = ""
    dest: str = ""
    proto: str | None = None
    dport: str | None = None
    family: Family = Family.BOTH


@dataclass(frozen=True, slots=True)
class HelperDef:
    """A built-in conntrack-helper registry entry: canonical proto/port + family capability.

    Static, documented data (cf. :class:`MacroDef` for macros; ADR-0040). ``name`` is the
    helper's canonical name, ``proto`` its L4 protocol, ``ports`` its default port(s), and
    ``family_capability`` the widest family the kernel helper supports — :data:`Family.IPV4`
    for a v4-only helper, :data:`Family.BOTH` for a v6-capable one (ADR-0002). The instances
    live in :mod:`shorewallnf.conntrack`.
    """

    name: str
    proto: str
    ports: tuple[str, ...]
    family_capability: Family


@dataclass(frozen=True, slots=True)
class HelperCapabilities:
    """Compile-time platform-capability input — which helpers the platform provides (ADR-0040).

    The ``AUTOHELPERS`` / ``__*_HELPER`` equivalent, expressed as pure data: no apply-time
    module autodetection (out of scope per epic #200). ``available`` is the set of helper
    names the platform offers; the generator (#221) calls :meth:`provides` to gate emission.
    """

    available: frozenset[str] = frozenset()

    def provides(self, name: str) -> bool:
        """Whether the platform provides the named helper."""
        return name in self.available


@dataclass(frozen=True, slots=True)
class Provider:
    """A policy-routing provider (the ``providers`` file), family-aware (epic #204, ADR-0002).

    Models one provider's routing attributes: ``name`` the provider label, ``number`` its
    routing-table id, ``mark`` the fwmark steered into that table, ``interface`` the egress
    interface, ``gateway`` the next-hop (an address literal or a non-literal like ``detect``),
    and ``options`` the verbatim options tokens. ``family`` follows the gateway (ADR-0002): an
    IPv4 gateway scopes the provider to :data:`Family.IPV4`, an IPv6 gateway to
    :data:`Family.IPV6`, and a non-literal gateway leaves it dual-stack (:data:`Family.BOTH`).
    Populating these is the parser's job (#232); validation (unique mark/table id, known
    interface) is a later task (#233). ``path``/``line`` are the originating ``file:line`` (set by
    the parser) so validator errors can cite the source; they are ``compare=False`` metadata and do
    not participate in equality (ADR-0001, #251).
    """

    name: str
    number: int
    mark: int
    interface: str
    gateway: str
    options: tuple[str, ...] = ()
    family: Family = Family.BOTH
    path: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class MangleRule:
    """A packet-marking rule (the ``mangle`` file), family-aware (epic #203, ADR-0001/0002).

    A tagged union over ``action`` — which fields are populated depends on it:

    - **MARK** / **CONNMARK**: ``mark`` is the mark value and ``mask`` an optional mask (a packet
      mark for MARK, a connection mark for CONNMARK).
    - **DIVERT**: no parameters — the match criteria alone divert the flow to the local socket.
    - **TPROXY**: ``port`` is the transparent-proxy destination port. ``mark`` is unused (always
      ``None``): the tproxy mark is the reserved :data:`TPROXY_MARK`, injected by the generator,
      not a per-rule value (ADR-0051 Part A).

    ``source``/``dest`` are the raw ``zone``/``zone:host`` match tokens and ``proto``/``dport`` the
    matched protocol / destination port(s), verbatim. ``family`` is inferred from the rule content
    (ADR-0002), defaulting to :data:`Family.BOTH`. The generator (#229) consumes this IR.
    ``path``/``line`` are the originating ``file:line`` (set by the parser) for located diagnostics;
    they are ``compare=False`` metadata and do not participate in equality (ADR-0001, #251).
    """

    action: str
    source: str = ""
    dest: str = ""
    proto: str | None = None
    dport: str | None = None
    mark: int | None = None
    mask: int | None = None
    port: int | None = None
    family: Family = Family.BOTH
    path: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class RoutingArtifact:
    """A provider lowered into policy-routing artifacts (the second output channel, ADR-0050).

    The whole routing lowering of one :class:`Provider`, shared by the Generator (which produces
    it) and the Applier (#235, which renders it to ``ip rule``/``ip route``): ``table_id`` is the
    routing-table id (= the provider number) whose default route is ``via <gateway> dev
    <interface>``, and ``fwmark`` (= the provider mark) is the mark whose ``ip rule`` selects that
    table. ``family`` is :data:`Family.IPV4` or :data:`Family.IPV6` — never :data:`Family.BOTH`; a
    routing table is family-specific (ADR-0002). Not part of the nftables JSON channel.
    """

    table_id: int
    fwmark: int
    gateway: str
    interface: str
    family: Family


@dataclass(frozen=True, slots=True)
class TproxyRoutingArtifact:
    """Transparent-proxy local delivery lowered into a routing artifact (ADR-0051 Part B).

    A sibling of :class:`RoutingArtifact` on the same second output channel (ADR-0050), but a
    different route type from a different source: a ``local`` route out ``lo`` rather than a
    default route via a gateway. It renders to ``ip -N rule add fwmark <fwmark> table <table_id>``
    + ``ip -N route add local 0.0.0.0/0 dev lo table <table_id>`` (v6: ``::/0``). ``table_id`` is
    the reserved :data:`TPROXY_TABLE_ID` and ``fwmark`` the reserved :data:`TPROXY_MARK` (both
    ``0xFFFFFFFF``), injected by the generator; a tproxy'd packet carries that mark and is selected
    only into that table. ``family`` is :data:`Family.IPV4` or :data:`Family.IPV6` — never
    :data:`Family.BOTH`; a routing table is family-specific (ADR-0002). Not part of the nftables
    JSON channel.
    """

    table_id: int
    fwmark: int
    family: Family


class OnOffKeep(Enum):
    """Tri-state kernel toggle (ADR-0061): enable, disable, or leave the value untouched."""

    ON = "On"
    OFF = "Off"
    KEEP = "Keep"


class YesNoKeep(Enum):
    """Tri-state kernel toggle (ADR-0061) whose surface spelling is ``Yes``/``No``/``Keep``."""

    YES = "Yes"
    NO = "No"
    KEEP = "Keep"


class Disposition(Enum):
    """A protective-check verdict (ADR-0063 §4), shared by the interface anti-spoof / flag
    checks (rpfilter #380, tcpflags #381, sfilter #382) and available to later gating.

    ``ACCEPT``/``DROP``/``REJECT`` render to the matching nft terminal verdict; ``CONTINUE``
    emits **no** terminal verdict — the matched packet falls through the rest of the chain
    (a log line, if configured, is still emitted), which is how an operator log-only's a check.
    """

    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    CONTINUE = "CONTINUE"


class ClampMss(Enum):
    """``CLAMPMSS=Yes`` path-MTU sentinel (ADR-0061).

    The clamp is a three-state setting kept distinct without conflating ``bool`` with ``int``
    (``bool ⊂ int``): ``None`` is off, this sentinel clamps the forwarded-SYN MSS to the route's
    path MTU (``Yes``), and a positive ``int`` clamps to that fixed size.
    """

    PATH_MTU = "Yes"


@dataclass(frozen=True, slots=True)
class Settings:
    """Whole-ruleset behaviour from ``shorewallnf.conf`` (ADR-0061).

    Each in-scope key is one typed field with a default equal to today's behaviour, so an absent
    file (or absent key) is the all-defaults instance and changes no output. Later epics add
    fields as they build the behaviour a key configures (#310/#311); a key with no consumer yet
    is an unknown key and fails fast in the parser. The generator reads emission-time settings
    (``log_level``/``logformat``); the applier reads kernel-state settings (the tri-states).
    """

    # LOG_LEVEL / LOGFORMAT feed the generator's log emission (wired byte-for-byte by #309); the
    # defaults mirror upstream Shorewall so an absent file reproduces today's output.
    log_level: str = "info"
    logformat: str = "Shorewall:%s:%s:"
    ip_forwarding: OnOffKeep = OnOffKeep.KEEP
    log_martians: YesNoKeep = YesNoKeep.KEEP
    route_filter: YesNoKeep = YesNoKeep.KEEP
    # DISABLE_IPV6 is Yes/No only (no Keep), so a plain bool rather than a tri-state: when True the
    # generator family-gates the ruleset to IPv4-only (ADR-0061/ADR-0002, #369). Default False =
    # today's dual-stack output.
    disable_ipv6: bool = False
    # CLAMPMSS (ADR-0061, #368): None = off (default; no clamp rule), ClampMss.PATH_MTU = clamp
    # the forwarded-SYN MSS to path MTU (Yes), a positive int = a fixed MSS. Read by the generator.
    clampmss: int | ClampMss | None = None
    # RPFILTER_DISPOSITION / RPFILTER_LOG_LEVEL (ADR-0063 §4, #380): the reverse-path check's
    # verdict and log level. Defaults mirror Shorewall — DROP, and no log line unless a level is
    # set — so an rpfilter interface under default settings emits `... drop` with no `log`.
    rpfilter_disposition: Disposition = Disposition.DROP
    rpfilter_log_level: str | None = None


@dataclass(frozen=True, slots=True)
class Ruleset:
    """Top-level IR container. Immutable; built once by the parser.

    Collections are tuples, not lists, to keep the whole structure immutable.
    """

    zones: tuple[Zone, ...] = ()
    interfaces: tuple[Interface, ...] = ()
    policies: tuple[Policy, ...] = ()
    rules: tuple[Rule, ...] = ()
    # Admin-access rules from the ``stoppedrules`` file — the traffic permitted while the
    # firewall is stopped. Kept distinct from ``rules`` so the stopped ruleset is generated
    # separately (#210/#211), not mixed into the running filter chains.
    stopped_rules: tuple[Rule, ...] = ()
    nats: tuple[Nat, ...] = ()
    conntrack_helpers: tuple[ConntrackHelper, ...] = ()
    providers: tuple[Provider, ...] = ()
    mangle_rules: tuple[MangleRule, ...] = ()
    # Site-defined ``action.<Name>`` definitions, keyed by ``<Name>`` in deterministic
    # (name-sorted) order — the registry the resolver (ADR-0020, #184) consumes.
    actions: Mapping[str, MacroDef] = field(default_factory=dict)
    # Global settings from ``shorewallnf.conf`` (ADR-0061); the all-defaults instance when the
    # file is absent, so every existing construction keeps today's behaviour.
    settings: Settings = field(default_factory=Settings)
