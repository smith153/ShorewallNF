"""Generator — the pure IR → nftables JSON stage (ADR-0001/0003).

Consumes the family-aware IR and emits the base ``inet`` skeleton (ADR-0005), the ADR-0063
prerouting anti-spoof chain (rpfilter) and the ADR-0063 §2 tcpflags illegal-flag check at the head
of ``input``/``forward``, then the per-connection feature rules from the ``Rule``
IR (ADR-0007), then the inter-zone default-policy rules from the ``Policy`` IR (ADR-0006), as
``python3-nftables`` JSON: one ``inet filter`` table, the fail-closed
``input``/``forward``/``output`` base chains, the always-present prerouting anti-spoof chain, the
always-on stateful + loopback accepts, the feature rules, and finally one rule per policy.
Feature rules land in their chain **before** the policy fall-through, so an explicit verdict
wins over the zone-pair default. It is dual-stack by construction (ADR-0002) and
golden-file-testable without an ``nft`` binary.
"""

from __future__ import annotations

import warnings
from typing import Any

from .conntrack import BUILTIN_HELPERS
from .errors import ConfigError
from .ir import (
    TPROXY_MARK,
    TPROXY_TABLE_ID,
    ClampMss,
    ConnLimit,
    ConntrackHelper,
    Disposition,
    Family,
    HelperCapabilities,
    HelperDef,
    Interface,
    MangleRule,
    Nat,
    Policy,
    Provider,
    RateLimit,
    RoutingArtifact,
    Rule,
    Ruleset,
    Settings,
    TproxyRoutingArtifact,
    Zone,
)

_FAMILY = "inet"
_TABLE = "filter"
_NAT_TABLE = "nat"

# nftables truncates a log prefix at NF_LOG_PREFIXLEN (128) including the NUL terminator, so the
# rendered prefix must fit in 127 chars (ADR-0061 §4). The parser applies the same limit to the
# raw LOGFORMAT template; here it guards the prefix *after* %s substitution, which can grow it.
_LOG_PREFIX_MAX = 127

# Fail-closed default capability surface: with nothing declared available, every helper is
# skipped (with a warning). The caller passes a real HelperCapabilities to enable them.
_NO_CAPABILITIES = HelperCapabilities()

# (chain name == hook name, base-chain policy). Input/forward fail closed; output accepts.
_BASE_CHAINS = (("input", "drop"), ("forward", "drop"), ("output", "accept"))

# nft verdict keyword per (uppercase) policy action; the parser guarantees these three.
_VERDICTS = {"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject"}

_Command = dict[str, Any]


def generate(
    ruleset: Ruleset, capabilities: HelperCapabilities = _NO_CAPABILITIES
) -> dict[str, list[_Command]]:
    """Emit base skeleton (ADR-0005), then feature rules (ADR-0007), then policies (ADR-0006).

    ``capabilities`` is the compile-time helper-availability surface (AUTOHELPERS-equivalent,
    ADR-0040): the ``conntrack`` helpers it does not mark available are skipped with a warning
    (ADR-0041). It defaults to the empty surface, so a helper is emitted only when the caller
    declares the platform provides it.
    """
    tcp_input, tcp_forward = _tcpflags_rules(ruleset)
    commands = _filter_base(
        ruleset.settings.disable_ipv6,
        forward_prefix=tcp_forward + _clampmss(ruleset.settings),
        input_prefix=tcp_input,
    )
    commands += _prerouting_checks(ruleset)
    commands += _mangle_rules(ruleset)
    commands += _nat_base(ruleset)
    commands += _ct_helpers(ruleset, capabilities)
    commands += _feature_rules(ruleset)
    commands += _nat_rules(ruleset)
    commands += _policy_rules(ruleset)
    return {"nftables": commands}


def generate_stopped(ruleset: Ruleset) -> dict[str, list[_Command]]:
    """Emit the stopped safe-state ruleset (ADR-0021).

    A self-contained ``inet filter`` table with the same fail-closed default-drop base chains
    (ADR-0005) and no-lockout baseline (loopback + established/related accepts) as the running
    ruleset, but carrying **only** the admin-access ``stopped_rules`` (#210) — never the running
    ``rules``/``policies``/``nats``. With zero admin rules the baseline alone still admits the
    operator's return traffic and loopback, so ``stop`` can never silently lock anyone out.

    Honors ``DISABLE_IPV6`` exactly as the running gate does (#376): the base IPv6 drop is
    installed at the head of every base chain and explicitly v6-scoped ``stopped_rules`` are
    suppressed, so a ``DISABLE_IPV6=Yes`` firewall stays IPv4-only while stopped as well.
    """
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = _firewalls(ruleset)
    disable_ipv6 = ruleset.settings.disable_ipv6
    commands = _filter_base(disable_ipv6)
    rules = _family_gated(ruleset.stopped_rules, disable_ipv6)
    commands += _translate_rules(rules, interfaces, firewalls)
    return {"nftables": commands}


def generate_routing(ruleset: Ruleset) -> tuple[RoutingArtifact, ...]:
    """Lower each ``providers`` entry into a policy-routing :class:`RoutingArtifact` (ADR-0050).

    The second output channel, distinct from the nftables JSON: policy routing lives in the Linux
    routing subsystem (``ip rule`` + per-provider routing tables), not nftables. Each provider
    yields a routing table (id = provider number, default route via its gateway/interface) and the
    fwmark→table selection rule. File order is preserved. Providers set no nft mark rule — the mark
    is owned by the mangle epic (#203) and only consumed here. A provider whose gateway is not an
    address literal (family ``BOTH``) cannot be family-scoped and fails closed (ADR-0004).
    """
    return tuple(_provider_routing(provider) for provider in ruleset.providers)


def _provider_routing(provider: Provider) -> RoutingArtifact:
    if provider.family is Family.BOTH:
        raise ConfigError(
            f"provider {provider.name!r} has a non-address gateway {provider.gateway!r}: a routing "
            "table needs a concrete IPv4/IPv6 next-hop (apply-time gateway detection is out of "
            "scope) — give the provider a literal gateway address"
        )
    return RoutingArtifact(
        table_id=provider.number,
        fwmark=provider.mark,
        gateway=provider.gateway,
        interface=provider.interface,
        family=provider.family,
    )


def generate_tproxy_routing(ruleset: Ruleset) -> tuple[TproxyRoutingArtifact, ...]:
    """Lower TPROXY rules into local-delivery routing artifacts (ADR-0051 Part B).

    The transparent-proxy half of the second output channel: a TPROXY'd packet carries the
    reserved :data:`TPROXY_MARK`, and one ``ip rule fwmark`` selects the reserved
    :data:`TPROXY_TABLE_ID`, whose ``local`` route out ``lo`` delivers it to the local listener.
    Emits **one** artifact per family that has any TPROXY rule — not one per rule (all tproxy rules
    share the one reserved mark and table) — deterministically v4 before v6. Empty when no TPROXY.
    A TPROXY rule with an ambiguous family fails closed (ADR-0004), as in the nft channel: a
    ``local`` route is per-family (ADR-0002). Pure ``IR → data``, no I/O.
    """
    seen: set[Family] = set()
    for rule in ruleset.mangle_rules:
        if rule.action != "TPROXY":
            continue
        if rule.family is Family.BOTH:
            raise ConfigError(
                "TPROXY needs a concrete family — narrow the rule to IPv4 or IPv6 "
                "(local-delivery routing tables are per-family)",
                path=rule.path,
                line=rule.line,
            )
        seen.add(rule.family)
    return tuple(
        TproxyRoutingArtifact(table_id=TPROXY_TABLE_ID, fwmark=TPROXY_MARK, family=family)
        for family in (Family.IPV4, Family.IPV6)
        if family in seen
    )


def _filter_base(
    disable_ipv6: bool = False,
    forward_prefix: list[_Command] | None = None,
    input_prefix: list[_Command] | None = None,
) -> list[_Command]:
    """The always-present ADR-0005 filter skeleton: table, default-drop base chains, and the
    no-lockout baseline accepts (established/related on input+forward, loopback on input).

    With ``disable_ipv6`` (ADR-0061/ADR-0002, #369) a ``meta nfproto ipv6 drop`` is installed at
    the head of every base chain — ahead of the no-lockout accepts and of all feature/policy rules
    — so nothing downstream passes IPv6 and the ``inet`` ruleset is effectively IPv4-only.

    ``input_prefix``/``forward_prefix`` are emitted into their chain **ahead of** its
    established/related accept — for rules that must run before that terminating stateful accept:
    the CLAMPMSS clamp (#368/#375), which has to see the reply SYN-ACK that accept would otherwise
    swallow, and the ADR-0063 §2 tcpflags check, which must catch a malformed-flag packet even on
    an already-established flow. Both empty (the default) for the stopped ruleset.
    """
    commands: list[_Command] = [_table()]
    commands += [_chain(name, policy) for name, policy in _BASE_CHAINS]
    if disable_ipv6:
        commands += [_ipv6_drop(name) for name, _ in _BASE_CHAINS]
    commands += input_prefix or []
    commands.append(_rule("input", [_ct_established_related(), _accept()]))
    commands.append(_rule("input", [_ifname("iifname", "lo"), _accept()]))
    commands += forward_prefix or []
    commands.append(_rule("forward", [_ct_established_related(), _accept()]))
    return commands


def _ipv6_drop(chain: str) -> _Command:
    """A ``meta nfproto ipv6 drop`` rule for ``chain`` — the DISABLE_IPV6 family-gate (#369)."""
    return _rule(chain, [_nfproto_match("ipv6"), _verdict("DROP")])


def _clampmss(settings: Settings) -> list[_Command]:
    """The forward-path TCP MSS clamp (ADR-0061, #368), or empty when ``CLAMPMSS=No``.

    A single ``inet`` rule (ADR-0002 — ``tcp option maxseg``/``rt mtu`` are family-agnostic, so no
    per-family duplication) that matches forwarded SYNs and sets the MSS to the route's path MTU
    (``CLAMPMSS=Yes``) or a fixed size. ``tcp flags syn`` (op ``in``) matches both the client's SYN
    and the server's SYN-ACK, clamping **both** handshake directions.

    Placement matters (#375): the caller threads this in ahead of the forward
    ``established,related`` accept. Conntrack classifies the reply SYN-ACK of a NEW connection as
    already ``established``, so were the clamp behind that terminating accept the SYN-ACK would be
    accepted before ever reaching it — leaving the client→server direction (the one that
    PMTU-black-holes) unclamped. The rule is non-terminating and matches only SYNs, so sitting
    first is lockout-safe and untouched by established data packets.
    """
    mss = settings.clampmss
    if mss is None:
        return []
    size: Any = {"rt": {"key": "mtu"}} if mss is ClampMss.PATH_MTU else mss
    syn: _Command = {
        "match": {
            "op": "in",
            "left": {"payload": {"protocol": "tcp", "field": "flags"}},
            "right": "syn",
        }
    }
    clamp: _Command = {
        "mangle": {"key": {"tcp option": {"name": "maxseg", "field": "size"}}, "value": size}
    }
    return [_rule("forward", [syn, clamp])]


def _firewalls(ruleset: Ruleset) -> set[str]:
    return {zone.name for zone in ruleset.zones if zone.is_firewall}


# ---- prerouting anti-spoof chain: rpfilter (ADR-0063; sfilter is #382) -------------------

# The anti-spoof chain hooks prerouting at `priority raw` (-300) — ahead of conntrack (-200) and
# of the input/forward hooks — so a spoofed packet drops before a conntrack entry exists and
# before the ADR-0005 established/related base-accept can wave it through (ADR-0063 §1/§3). Its
# name is distinct from the mangle chain's own `prerouting` (a base-chain name is unique per table;
# mangle sits later at prio -150) — ADR-0063 §1 calls it the "prerouting" chain, but that name is
# already taken, so it rides here as `prerouting_raw` (see the PR note / follow-up issue).
_PREROUTING_RAW_CHAIN = "prerouting_raw"
_PREROUTING_RAW_PRIO = -300


def _prerouting_checks(ruleset: Ruleset) -> list[_Command]:
    """The always-present ADR-0063 prerouting anti-spoof chain plus its rpfilter rules.

    The chain is part of the fixed skeleton — emitted even with no check configured, inert
    (`policy accept`, empty body). One reverse-path rule is added per interface whose IR carries
    `rpfilter`; a config with none leaves the chain empty. Scoped to the running ruleset only —
    protective checks don't apply while stopped — so the stopped golden stays byte-for-byte.
    """
    commands: list[_Command] = [
        _chain(_PREROUTING_RAW_CHAIN, "accept", hook="prerouting", prio=_PREROUTING_RAW_PRIO)
    ]
    commands += [
        _rpfilter_rule(iface, ruleset.settings)
        for iface in ruleset.interfaces
        if iface.rpfilter
    ]
    # sfilter follows rpfilter in the same chain (ADR-0063 §1 order), one rule per family present.
    for iface in ruleset.interfaces:
        commands += _sfilter_rules(iface, ruleset.settings)
    return commands


def _rpfilter_rule(iface: Interface, settings: Settings) -> _Command:
    """One reverse-path check for an rpfilter interface: gate on ``iifname``, then the
    family-neutral ``fib saddr . iif oif missing`` match (ADR-0063 §5 — one rule covers IPv4 and
    IPv6 in the ``inet`` chain, no nfproto guard), then the shared disposition tail."""
    ctx = f"rpfilter on interface {iface.name!r}"
    expr: list[_Command] = [_ifname("iifname", iface.name), _fib_rpfilter()]
    expr += _disposition(
        _PREROUTING_RAW_CHAIN,
        settings.rpfilter_disposition,
        settings.rpfilter_log_level,
        settings.logformat,
        ctx,
    )
    return _rule(_PREROUTING_RAW_CHAIN, expr)


def _fib_rpfilter() -> _Command:
    """``fib saddr . iif oif missing`` — matches when the packet's source address has no route
    back out its ingress interface (a spoofed / asymmetric-path packet). Family-neutral."""
    return {
        "match": {
            "op": "==",
            "left": {"fib": {"result": "oif", "flags": ["saddr", "iif"]}},
            "right": False,
        }
    }


# ---- sfilter anti-spoof source check (ADR-0063 §5, #382) --------------------------------

# The source-filter check drops packets whose source address falls in a network that cannot
# legitimately arrive on the ingress interface (ADR-0063 §5). #378 records the sfilter nets as
# verbatim literals; here they are classified into IPv4/IPv6 by the `":" in net` idiom (as in
# `_addr_value`/`_addr_match`) so the one `inet` ruleset emits up to two family-correct rules per
# interface (`ip saddr` for v4, `ip6 saddr` for v6, ADR-0002) — only the families actually present.


def _sfilter_rules(iface: Interface, settings: Settings) -> list[_Command]:
    """The ADR-0063 §5 source-filter rules for one interface: up to two `iifname <if>` rules —
    `ip saddr {v4 nets}` and/or `ip6 saddr {v6 nets}` — each reaching the shared disposition tail.
    Empty when the interface carries no sfilter list, so an un-filtered config is unchanged."""
    if not iface.sfilter:
        return []
    v4 = [net for net in iface.sfilter if ":" not in net]
    v6 = [net for net in iface.sfilter if ":" in net]
    return [
        _sfilter_rule(iface, settings, proto, nets)
        for proto, nets in (("ip", v4), ("ip6", v6))
        if nets
    ]


def _sfilter_rule(
    iface: Interface, settings: Settings, proto: str, nets: list[str]
) -> _Command:
    """One family's source-filter rule: gate on ``iifname``, match the source nets (a scalar/prefix
    or an anonymous set for a list) via ``<proto> saddr``, then the shared disposition tail."""
    ctx = f"sfilter on interface {iface.name!r}"
    expr: list[_Command] = [_ifname("iifname", iface.name), _sfilter_saddr(proto, nets)]
    expr += _disposition(
        _PREROUTING_RAW_CHAIN,
        settings.sfilter_disposition,
        settings.sfilter_log_level,
        settings.logformat,
        ctx,
    )
    return _rule(_PREROUTING_RAW_CHAIN, expr)


def _sfilter_saddr(proto: str, nets: list[str]) -> _Command:
    """``<proto> saddr`` over the family's source nets — a scalar/prefix for one, an anonymous set
    for a list; each element reuses the ADR-0007 ``_addr_value`` prefix handling."""
    elems = [_addr_value(net) for net in nets]
    right = elems[0] if len(elems) == 1 else {"set": elems}
    return {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "saddr"}},
                      "right": right}}


# ---- tcpflags illegal-flag check (ADR-0063 §2, #381) ------------------------------------

# Shorewall's setup_tcp_flags rejects five nonsensical TCP-flag combinations. Each is one
# `tcp flags & <mask> == <value>` match, emitted with **numeric** mask/value: the symbolic
# `{"|": [<flag>...]}` OR-of-named-flags JSON form is rejected by nft < 1.1 (#381 — it loaded on
# 1.1.x but failed `nft -j -f` on the 1.0.9 CI runner), whereas numbers load on every version and
# normalise to the same ruleset. The classic iptables `--tcp-flags ALL` mask is the six flags
# below (fin,syn,rst,psh,ack,urg); `--syn` examines fin,syn,rst,ack. Family-neutral — one inet
# match per combo covers IPv4 and IPv6 (ADR-0063 §5). Pinned against a real `nft --check` (golden
# fixtures + the `nft`-marked golden tier).
_TCP_FLAG_BITS = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08, "ack": 0x10, "urg": 0x20}
_TCP_FLAGS_ALL = ["fin", "syn", "rst", "psh", "ack", "urg"]


def _flag_bits(flags: list[str]) -> int:
    """The OR of the numeric TCP-flag bits named in ``flags`` (empty ⇒ ``0``, no flags set)."""
    bits = 0
    for flag in flags:
        bits |= _TCP_FLAG_BITS[flag]
    return bits


def _tcpflags_rules(ruleset: Ruleset) -> tuple[list[_Command], list[_Command]]:
    """The ADR-0063 §2 illegal-TCP-flags check for every interface carrying ``tcpflags``, as an
    ``(input, forward)`` pair of rule lists the caller prepends to the head of each base chain —
    ahead of the ADR-0005 established/related accept, so a malformed-flag packet is caught even on
    an already-established flow. Each flagged interface yields, per chain, one gated rule per
    invalid combination (``iifname <if>`` then the flag match then the shared disposition tail).
    Empty when no interface is flagged, so an un-flagged config reproduces the skeleton
    byte-for-byte. The disposition tail is rendered once per chain (its ``%s`` log-prefix slot fills
    with the chain name); tcpflags stays off ``output`` — it gates only forwarded/local ingress.
    """
    settings = ruleset.settings
    flagged = [iface for iface in ruleset.interfaces if iface.tcpflags]
    per_chain: dict[str, list[_Command]] = {"input": [], "forward": []}
    for chain, out in per_chain.items():
        tail = _disposition(
            chain,
            settings.tcp_flags_disposition,
            settings.tcp_flags_log_level,
            settings.logformat,
            f"tcpflags in {chain} chain",
        )
        for iface in flagged:
            gate = _ifname("iifname", iface.name)
            for match in _tcpflags_matches():
                out.append(_rule(chain, [gate, *match, *tail]))
    return per_chain["input"], per_chain["forward"]


def _tcpflags_matches() -> list[list[_Command]]:
    """The five invalid TCP-flag matches (Shorewall ``setup_tcp_flags``), each as the match list
    that precedes the shared disposition tail: null / no-flags, Xmas (FIN+PSH+URG), SYN+RST,
    SYN+FIN, and a new-connection SYN from source port 0 (``tcp sport 0`` added to the flag
    match)."""
    return [
        [_tcpflags_match(_TCP_FLAGS_ALL, [])],
        [_tcpflags_match(_TCP_FLAGS_ALL, ["fin", "psh", "urg"])],
        [_tcpflags_match(["syn", "rst"], ["syn", "rst"])],
        [_tcpflags_match(["fin", "syn"], ["fin", "syn"])],
        [_tcpflags_match(["fin", "syn", "rst", "ack"], ["syn"]), _port_match("tcp", "sport", "0")],
    ]


def _tcpflags_match(mask: list[str], value: list[str]) -> _Command:
    """One ``tcp flags & <mask> == <value>`` match — the flag bits masked by ``mask`` must equal
    ``value``, both emitted as numeric bitmasks (``value == []`` ⇒ ``0``, no-flags-set). Numeric,
    not the symbolic ``{"|": [...]}`` form, so the JSON loads on nft < 1.1 too (#381)."""
    return {
        "match": {
            "op": "==",
            "left": {"&": [{"payload": {"protocol": "tcp", "field": "flags"}}, _flag_bits(mask)]},
            "right": _flag_bits(value),
        }
    }


# ---- inter-zone default-policy rules (ADR-0006) -----------------------------------------


def _policy_rules(ruleset: Ruleset) -> list[_Command]:
    """One nft rule per policy, ordered specific-pair → single-``all`` → ``all all`` last."""
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = {zone.name for zone in ruleset.zones if zone.is_firewall}
    ordered = sorted(ruleset.policies, key=_specificity)
    return [_policy_rule(policy, interfaces, firewalls, ruleset.settings) for policy in ordered]


def _zone_interfaces(zones: tuple[Zone, ...]) -> dict[str, tuple[str, ...]]:
    """Map each zone to its (deduplicated, order-preserving) interface names."""
    return {zone.name: tuple(dict.fromkeys(m.interface for m in zone.members)) for zone in zones}


def _specificity(policy: Policy) -> int:
    """Sort key: 0 = specific zone pair, 1 = one ``all`` side, 2 = ``all all`` (emitted last)."""
    return (policy.source == "all") + (policy.dest == "all")


def _policy_rule(
    policy: Policy,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
    settings: Settings,
) -> _Command:
    ctx = f"policy {policy.source!r} {policy.dest!r}"
    chain, expr = _chain_and_zone_matches(
        policy.source, policy.dest, interfaces, firewalls, ctx
    )
    # A LIMIT:BURST column emits an nft `limit rate` immediately before the verdict/log tail, so
    # under-limit traffic takes the policy action and over-limit traffic falls through past it to
    # the next-less-specific policy / base-chain drop (ADR-0006/0007, #408).
    expr += _rate_limit(policy.rate)
    # A policy logs only when it carries an explicit LEVEL column, and that per-policy level is
    # the emitted syslog level (#321 decision) — Settings.LOG_LEVEL is only a fallback for logging
    # rules with no explicit level, a no-op here. The verdict/log tail is the shared ADR-0063 §4
    # render helper (a policy action is ACCEPT/DROP/REJECT, never CONTINUE, so it always emits a
    # verdict); the prefix %s slots fill with the chain name and the disposition (the action).
    expr += _disposition(
        chain, Disposition[policy.action], policy.log_level, settings.logformat, ctx
    )
    return _rule(chain, expr)


def _chain_and_zone_matches(
    source: str,
    dest: str,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
    ctx: str,
) -> tuple[str, list[_Command]]:
    """Base chain (by the role of ``$FW``) and the per-side interface matches.

    The ADR-0006 zone-matching structure, shared by policy defaults and feature rules (ADR-0007):
    ``$FW`` as source is host ``output``, as dest host ``input``, otherwise ``forward``; each
    non-``all``, non-``$FW`` side matches its zone's interface(s).
    """
    src_fw = source in firewalls
    dst_fw = dest in firewalls
    chain = "output" if src_fw else "input" if dst_fw else "forward"
    expr: list[_Command] = []
    if chain in ("forward", "input") and source != "all" and not src_fw:
        expr.append(_ifname("iifname", _iface_value(ctx, source, interfaces)))
    if chain in ("forward", "output") and dest != "all" and not dst_fw:
        expr.append(_ifname("oifname", _iface_value(ctx, dest, interfaces)))
    return chain, expr


def _iface_value(
    ctx: str, zone: str, interfaces: dict[str, tuple[str, ...]]
) -> str | dict[str, Any]:
    """A single interface name, or an anonymous set when the zone spans several."""
    names = interfaces.get(zone, ())
    if not names:
        raise ConfigError(f"{ctx}: zone {zone!r} has no interfaces to match on")
    return names[0] if len(names) == 1 else {"set": list(names)}


# ---- per-connection feature rules (ADR-0007) --------------------------------------------


def _feature_rules(ruleset: Ruleset) -> list[_Command]:
    """One nft rule per ``Rule``, ordered by ``?SECTION`` then file order, before the defaults.

    Rules are grouped by connection-state section (ADR-0007): the state-gated
    ESTABLISHED → RELATED → INVALID fast-path first, then the ungated NEW rules, stably within
    each. Sorting before the policy fall-through keeps explicit verdicts ahead of the defaults.
    """
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = _firewalls(ruleset)
    rules = _family_gated(ruleset.rules, ruleset.settings.disable_ipv6)
    return _translate_rules(rules, interfaces, firewalls)


def _family_gated(rules: tuple[Rule, ...], disable_ipv6: bool) -> tuple[Rule, ...]:
    """Drop explicitly IPv6-scoped rules under ``DISABLE_IPV6`` (#369); v4 and unguarded ``both``
    rules stay — the base ``meta nfproto ipv6 drop`` is what keeps the surviving ``both`` rules
    from passing IPv6 (ADR-0002). Shared by the running feature rules and the stopped safe state
    (#376) so both gates suppress the same v6-scoped rules."""
    if not disable_ipv6:
        return rules
    return tuple(rule for rule in rules if rule.family is not Family.IPV6)


def _translate_rules(
    rules: tuple[Rule, ...], interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> list[_Command]:
    """Translate a tuple of ``Rule``s to nft commands, ``?SECTION``-ordered (ADR-0007).

    Shared by the running ruleset (``ruleset.rules``) and the stopped safe state
    (``ruleset.stopped_rules``, ADR-0021) so admin rules are compiled family-correctly and
    identically to normal rules.
    """
    ordered = sorted(rules, key=lambda rule: _SECTION_ORDER[_section_of(rule)])
    return [cmd for rule in ordered for cmd in _feature_rule(rule, interfaces, firewalls)]


def _feature_rule(
    rule: Rule, interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> list[_Command]:
    """The nft rule(s) for one ``Rule``; a both-family ICMP rule splits into one per family."""
    ctx = f"rule {rule.action} {rule.source!r} {rule.dest!r}"
    chain, prefix = _chain_and_zone_matches(
        _zone_of(rule.source), _zone_of(rule.dest), interfaces, firewalls, ctx
    )
    prefix += _host_matches(rule.source, rule.dest)
    prefix += _ct_matches(rule)
    verdict = _verdict(rule.action)
    gate = _rate_limit(rule.rate) + _connlimit(rule.connlimit)
    if rule.proto in _ICMP_PROTOS:
        return [
            _rule(chain, [*prefix, match, *gate, verdict])
            for match in _icmp_matches(rule, ctx)
        ]
    return [_rule(chain, [*prefix, *_l4_matches(rule, ctx), *gate, verdict])]


def _rate_limit(rate: RateLimit | None) -> list[_Command]:
    """The nft ``limit rate`` statement for a rule's RATE LIMIT column, or none (ADR-0007).

    Placed immediately before the verdict so traffic under the limit takes the verdict and
    over-limit traffic falls through per nft limit-statement semantics. The burst clause is
    emitted only when the column specified one (nft defaults the burst otherwise). The numeric
    ``rate``/``per`` encoding is the portable form the CI nft tier (1.0.9) accepts (#406)."""
    if rate is None:
        return []
    limit: dict[str, Any] = {"rate": rate.rate, "per": rate.interval}
    if rate.burst is not None:
        limit["burst"] = rate.burst
    return [{"limit": limit}]


def _connlimit(connlimit: ConnLimit | None) -> list[_Command]:
    """The nft ``ct count over <count>`` statement for a rule's CONNLIMIT column, or none.

    Placed in the same statement-before-verdict slot as the rate limiter (ADR-0007 fixed match
    order), after it: it gates the verdict on the simultaneous-connection cap. Emitted as the
    numeric ``{"ct count": {"val": <count>, "inv": true}}`` form (``inv`` is nft's ``over``
    keyword) — the portable JSON the CI nft tier (1.0.9) accepts, mirroring the rate limiter (#407).
    The bare (ungrouped) count is a per-rule global connection cap; the masked/grouped per-source
    form is out of scope here (#416)."""
    if connlimit is None:
        return []
    return [{"ct count": {"val": connlimit.count, "inv": True}}]


# ?SECTION connection-state gating & ordering (ADR-0007). ESTABLISHED/RELATED/INVALID gate on
# ``ct state`` and form the fast-path; NEW (the default for an unsectioned rule) is ungated —
# the ADR-0005 base rules already fast-path established/related, so NEW rules only see new packets.
_SECTION_ORDER = {"ESTABLISHED": 0, "RELATED": 1, "INVALID": 2, "NEW": 3}
_SECTION_STATE = {"ESTABLISHED": "established", "RELATED": "related", "INVALID": "invalid"}


def _section_of(rule: Rule) -> str:
    """The rule's section upper-cased; unsectioned defaults to ``NEW`` (fail fast otherwise)."""
    section = (rule.section or "NEW").upper()
    if section not in _SECTION_ORDER:
        raise ConfigError(
            f"rule {rule.action} {rule.source!r} {rule.dest!r}: unsupported ?SECTION "
            f"{rule.section!r} (ESTABLISHED/RELATED/INVALID/NEW)"
        )
    return section


def _ct_matches(rule: Rule) -> list[_Command]:
    """A ``ct state`` match for a state-gated section; NEW rules add none."""
    state = _SECTION_STATE.get(_section_of(rule))
    return [_ct_state(state)] if state is not None else []


def _ct_state(state: str) -> _Command:
    return {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": state}}


# ICMP is family-correct: ``icmp`` (IPv4) / ``ipv6-icmp`` (IPv6) as the l4proto, ``icmp``/``icmpv6``
# as the payload protocol for a type match. The match itself is the family guard (ADR-0007), so a
# both-family rule splits into one rule per family (ADR-0002) rather than adding a meta nfproto.
_ICMP_PROTOS = ("icmp", "ipv6-icmp")


def _icmp_matches(rule: Rule, ctx: str) -> list[_Command]:
    """One ICMP match per family the rule scopes to.

    ICMP has no source port; the DEST PORT column carries an optional ICMP type. A both-family
    rule yields a v4 ``icmp`` and a v6 ``icmpv6`` match; a family-pinned rule yields only its own.
    """
    if rule.sport is not None:
        raise ConfigError(f"{ctx}: an ICMP rule has no source port")
    v6_flags: tuple[bool, ...] = (
        (False, True) if rule.family is Family.BOTH else (rule.family is Family.IPV6,)
    )
    return [_icmp_match(v6, rule.dport) for v6 in v6_flags]


def _icmp_match(v6: bool, icmp_type: str | None) -> _Command:
    if icmp_type is None:
        return _l4proto("ipv6-icmp" if v6 else "icmp")
    left = {"payload": {"protocol": "icmpv6" if v6 else "icmp", "field": "type"}}
    return {"match": {"op": "==", "left": left, "right": _port_value(icmp_type)}}


def _zone_of(token: str) -> str:
    """The zone part of a ``zone`` or ``zone:host`` token (task #123 narrows on the host)."""
    return token.split(":", 1)[0]


def _host_of(token: str) -> str | None:
    """The host/CIDR part of a ``zone:host`` token, or ``None`` for a bare zone."""
    _, sep, host = token.partition(":")
    return host if sep else None


def _host_matches(source: str, dest: str) -> list[_Command]:
    """``ip``/``ip6`` ``saddr``/``daddr`` narrowing from a ``zone:host`` source/dest (ADR-0007).

    Family comes from the literal (``:`` marks IPv6, ADR-0002); the family-specific match is the
    family guard, so no ``meta nfproto`` is added. Emitted after the interface matches and before
    the L4 matches; source narrows on ``saddr``, dest on ``daddr``. Shared by feature rules and
    conntrack-helper assignment rules (ADR-0041).
    """
    matches: list[_Command] = []
    src_host = _host_of(source)
    if src_host is not None:
        matches.append(_addr_match("saddr", src_host))
    dst_host = _host_of(dest)
    if dst_host is not None:
        matches.append(_addr_match("daddr", dst_host))
    return matches


def _addr_match(field: str, host: str) -> _Command:
    proto = "ip6" if ":" in host else "ip"
    left = {"payload": {"protocol": proto, "field": field}}
    return {"match": {"op": "==", "left": left, "right": _addr_value(host)}}


def _addr_value(host: str) -> str | dict[str, Any]:
    """A bare address (scalar) or a CIDR literal as an nft ``prefix``."""
    if "/" in host:
        addr, length = host.rsplit("/", 1)
        return {"prefix": {"addr": addr, "len": int(length)}}
    return host


def _l4_matches(rule: Rule, ctx: str) -> list[_Command]:
    """tcp/udp protocol & port matches (ADR-0007).

    A proto-only rule matches ``meta l4proto``; with ports we emit a payload match per column
    (``dport`` before ``sport``) — nft folds the protocol dependency back in on load, so the
    bare payload match is the canonical form. A port without a protocol fails fast (ADR-0004).
    """
    if rule.proto is None:
        if rule.dport is not None or rule.sport is not None:
            raise ConfigError(f"{ctx}: a port match needs a protocol")
        return []
    if rule.dport is None and rule.sport is None:
        return [_l4proto(rule.proto)]
    matches: list[_Command] = []
    if rule.dport is not None:
        matches.append(_port_match(rule.proto, "dport", rule.dport))
    if rule.sport is not None:
        matches.append(_port_match(rule.proto, "sport", rule.sport))
    return matches


def _l4proto(proto: str) -> _Command:
    return {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": proto}}


def _port_match(proto: str, field: str, spec: str) -> _Command:
    return {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": proto, "field": field}},
            "right": _port_value(spec),
        }
    }


def _port_value(spec: str) -> int | str | dict[str, Any]:
    """A single port (scalar), a comma-list (anonymous set), or an ``a:b`` range."""
    elems = [_port_elem(elem) for elem in spec.split(",")]
    return elems[0] if len(elems) == 1 else {"set": elems}


def _port_elem(elem: str) -> int | str | dict[str, Any]:
    if ":" in elem:
        low, high = elem.split(":", 1)
        return {"range": [_port(low), _port(high)]}
    return _port(elem)


def _port(token: str) -> int | str:
    """A numeric port as ``int`` (nft's canonical form); a service name passes through verbatim."""
    token = token.strip()
    return int(token) if token.isdigit() else token


def _log(level: str, prefix: str) -> _Command:
    return {"log": {"level": level, "prefix": prefix}}


def _log_prefix(template: str, chain: str, disposition: str, ctx: str) -> str:
    """Render a LOGFORMAT ``template`` into a log prefix, filling its ``%s`` slots (up to two)
    with the ``chain`` name and the ``disposition`` (ADR-0061). Fails fast if the template has
    more slots than we supply, or if the rendered prefix exceeds the kernel limit — the check is
    on the *rendered* string, since substitution can grow it past a within-limit template."""
    parts = template.split("%s")
    slots = (chain, disposition)
    count = len(parts) - 1
    if count > len(slots):
        raise ConfigError(f"{ctx}: LOGFORMAT {template!r} has more than {len(slots)} %s slots")
    prefix = parts[0]
    for i in range(count):
        prefix += slots[i] + parts[i + 1]
    if len(prefix) > _LOG_PREFIX_MAX:
        raise ConfigError(
            f"{ctx}: rendered log prefix {prefix!r} is {len(prefix)} chars, over the "
            f"{_LOG_PREFIX_MAX}-char kernel log-prefix limit"
        )
    return prefix


def _verdict(action: str) -> _Command:
    return {_VERDICTS[action]: None}


def _disposition(
    chain: str,
    disposition: Disposition,
    log_level: str | None,
    logformat: str,
    ctx: str,
) -> list[_Command]:
    """The shared ADR-0063 §4 render-tail for a protective check: an optional ``log`` then the
    verdict. Check-agnostic — parameterised on chain + disposition + log level, so the three
    checks (#380 rpfilter / #381 tcpflags / #382 sfilter) reuse it with only their preceding match
    differing. ``log`` is emitted only when ``log_level`` is set (prefix rendered from ``logformat``
    via :func:`_log_prefix`, its ``%s`` slots filled with the chain name and the disposition,
    length-checked to fail fast); ``CONTINUE`` emits **no** terminal verdict — the matched packet
    falls through the chain (the log line, if any, is still emitted) — otherwise the verdict is the
    :data:`_VERDICTS` keyword for ACCEPT/DROP/REJECT."""
    stmts: list[_Command] = []
    if log_level is not None:
        stmts.append(_log(log_level, _log_prefix(logformat, chain, disposition.value, ctx)))
    if disposition is not Disposition.CONTINUE:
        stmts.append(_verdict(disposition.value))
    return stmts


# ---- conntrack helper objects + assignment rules (ADR-0041) -----------------------------

# A ct helper object's L3 protocol per its family capability (ADR-0040): a v6-capable helper is
# declared once as ``l3proto inet`` (covers both families in the inet table, per the official nft
# example), a v4-only one as ``l3proto ip``. The rule's own family scoping is a separate concern.
_L3PROTO = {Family.BOTH: "inet", Family.IPV4: "ip", Family.IPV6: "ip6"}

# meta nfproto value per the assignment rule's resolved family (ADR-0002); BOTH needs no guard.
_NFPROTO = {Family.IPV4: "ipv4", Family.IPV6: "ipv6"}


def _ct_helpers(ruleset: Ruleset, capabilities: HelperCapabilities) -> list[_Command]:
    """Compile ``conntrack_helpers`` to ``ct helper`` objects + assignment rules (ADR-0041).

    Each entry is resolved against the built-in registry (an unknown name is malformed IR and
    fails closed, ADR-0004) and gated on ``capabilities``: a helper the platform does not provide
    is skipped with a warning, never emitted. The surviving helpers yield one ``ct helper`` object
    per distinct name (emitted first, so it precedes the rule that references it) followed by one
    ``ct helper set`` assignment rule per entry, placed in the base chain the flow traverses.
    """
    available: list[tuple[ConntrackHelper, HelperDef]] = []
    for helper in ruleset.conntrack_helpers:
        hdef = _resolve_helper(helper)
        if not capabilities.provides(helper.name):
            warnings.warn(
                f"conntrack helper {helper.name!r} is not available on the target platform "
                "(capability gating); skipping — no ct helper object or assignment rule emitted",
                stacklevel=2,
            )
            continue
        available.append((helper, hdef))

    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = _firewalls(ruleset)
    objects = _ct_helper_objects(available)
    rules = [_ct_helper_rule(helper, hdef, interfaces, firewalls) for helper, hdef in available]
    return objects + rules


def _resolve_helper(helper: ConntrackHelper) -> HelperDef:
    """The registry entry for ``helper`` — its canonical proto/port + family capability.

    An unknown name never resolves (the parser resolves against the same registry, #220), so
    reaching one here is malformed IR the generator cannot lower: fail closed (ADR-0004).
    """
    hdef = BUILTIN_HELPERS.get(helper.name)
    if hdef is None:
        raise ConfigError(
            f"conntrack helper {helper.name!r}: unknown helper (not in the built-in registry)"
        )
    return hdef


def _ct_helper_objects(
    available: list[tuple[ConntrackHelper, HelperDef]],
) -> list[_Command]:
    """One ``ct helper`` object per distinct helper name, in first-seen order (deduplicated).

    Several rows may attach the same helper with different narrowing; the object is per-table and
    named once, so it is emitted a single time regardless of how many rules reference it.
    """
    objects: list[_Command] = []
    seen: set[str] = set()
    for _helper, hdef in available:
        if hdef.name in seen:
            continue
        seen.add(hdef.name)
        objects.append(_ct_helper_object(hdef))
    return objects


def _ct_helper_object(hdef: HelperDef) -> _Command:
    """The named ``ct helper`` object: type + L4 protocol + capability-derived ``l3proto``."""
    return {
        "add": {
            "ct helper": {
                "family": _FAMILY,
                "table": _TABLE,
                "name": hdef.name,
                "type": hdef.name,
                "protocol": hdef.proto,
                "l3proto": _L3PROTO[hdef.family_capability],
            }
        }
    }


def _ct_helper_rule(
    helper: ConntrackHelper,
    hdef: HelperDef,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
) -> _Command:
    """The ``ct helper set`` assignment rule binding the helper to its matching flow (ADR-0041).

    Reuses the ADR-0006/0007 zone matching (chain + iifname/oifname) and ``zone:host`` narrowing,
    adds a ``meta nfproto`` guard for a family-scoped helper (ADR-0002; a dual-stack helper needs
    none), matches the helper's canonical proto/default port unless the row overrides them, then
    sets the helper. The statement is non-terminal — the packet falls through to normal filtering.
    """
    ctx = f"conntrack helper {helper.name!r}"
    source = helper.source or "all"
    dest = helper.dest or "all"
    chain, expr = _chain_and_zone_matches(
        _zone_of(source), _zone_of(dest), interfaces, firewalls, ctx
    )
    expr += _host_matches(source, dest)
    guard = _NFPROTO.get(helper.family)
    if guard is not None:
        expr.append(_nfproto_match(guard))
    proto = helper.proto or hdef.proto
    dport = helper.dport if helper.dport is not None else ",".join(hdef.ports)
    expr += _nat_l4_matches(proto, dport, ctx)
    expr.append({"ct helper": helper.name})
    return _rule(chain, expr)


def _nfproto_match(nfproto: str) -> _Command:
    return {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": nfproto}}


# ---- mangle: prerouting mark / divert / tproxy rules (ADR-0042) -------------------------

# The mangle chain hooks prerouting at priority mangle (-150) — ahead of dstnat (-100) and the
# routing decision, so a mark is set before a provider's ip rule (ADR-0050) selects a table.
_MANGLE_CHAIN = "prerouting"
_MANGLE_PRIO = -150
_U32_MASK = 0xFFFFFFFF


def _mangle_rules(ruleset: Ruleset) -> list[_Command]:
    """Compile ``mangle_rules`` into the prerouting mangle chain (ADR-0042).

    Emits the chain once (only when there are rules), then one rule per ``MangleRule`` in file
    order — the operator's ordering (e.g. DIVERT before TPROXY) is preserved.
    """
    if not ruleset.mangle_rules:
        return []
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = _firewalls(ruleset)
    commands: list[_Command] = [_mangle_chain()]
    commands += [_mangle_rule(rule, interfaces, firewalls) for rule in ruleset.mangle_rules]
    return commands


def _mangle_chain() -> _Command:
    return {
        "add": {
            "chain": {
                "family": _FAMILY,
                "table": _TABLE,
                "name": _MANGLE_CHAIN,
                "type": "filter",
                "hook": "prerouting",
                "prio": _MANGLE_PRIO,
                "policy": "accept",
            }
        }
    }


def _mangle_rule(
    rule: MangleRule, interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> _Command:
    """One prerouting rule for a ``MangleRule``: match criteria then the non-terminal action.

    Matches the source zone (``iifname``), source/dest host literals (``saddr``/``daddr``) and
    proto/port, plus a ``meta nfproto`` guard for a family-scoped rule. A DEST given as a bare zone
    fails closed — ``oifname`` isn't known at prerouting, so honouring it is impossible and silently
    dropping it would mark more traffic than written (ADR-0004).
    """
    ctx = f"mangle {rule.action} {rule.source!r} {rule.dest!r}"
    expr: list[_Command] = []
    src_zone = _zone_of(rule.source)
    dst_zone = _zone_of(rule.dest)
    _reject_firewall_zone(rule, src_zone, dst_zone, firewalls, ctx)
    if src_zone and src_zone != "all" and src_zone not in firewalls:
        expr.append(_ifname("iifname", _iface_value(ctx, src_zone, interfaces)))
    if dst_zone and dst_zone != "all" and dst_zone not in firewalls and _host_of(rule.dest) is None:
        raise ConfigError(
            f"{ctx}: mangle DEST {dst_zone!r} is a bare zone — the out-interface is unknown at "
            "prerouting; narrow DEST to a host (zone:host) or use '-'",
            path=rule.path,
            line=rule.line,
        )
    expr += _host_matches(rule.source, rule.dest)
    guard = _NFPROTO.get(rule.family)
    if guard is not None:
        expr.append(_nfproto_match(guard))
    expr += _nat_l4_matches(rule.proto, rule.dport, ctx)
    expr += _mangle_action(rule, ctx)
    return _rule(_MANGLE_CHAIN, expr)


def _reject_firewall_zone(
    rule: MangleRule, src_zone: str, dst_zone: str, firewalls: set[str], ctx: str
) -> None:
    """Fail closed on a firewall zone as mangle SOURCE or DEST (ADR-0042, ADR-0004).

    The prerouting mangle chain only sees forwarded/ingress traffic; traffic to or from the
    firewall is routed locally (the ``output`` chain ADR-0042 defers), not seen here. Silently
    dropping such a zone would mark more — or entirely different — traffic than written, the same
    footgun the bare-DEST guard prevents, so reject it with a located error.
    """
    for role, zone in (("SOURCE", src_zone), ("DEST", dst_zone)):
        if zone in firewalls:
            raise ConfigError(
                f"{ctx}: the firewall zone {zone!r} as mangle {role} isn't supported at "
                "prerouting — traffic to or from the firewall is routed locally, not forwarded, "
                "so marking it needs the output chain (deferred, ADR-0042); use a network zone "
                "or '-'",
                path=rule.path,
                line=rule.line,
            )


def _mangle_action(rule: MangleRule, ctx: str) -> list[_Command]:
    """The non-terminal action statement(s): set a mark, or divert/tproxy to a local socket."""
    if rule.action in ("MARK", "CONNMARK"):
        kind = "meta" if rule.action == "MARK" else "ct"
        return [_mark_set(kind, _require(rule.mark, ctx, "a mark value"), rule.mask)]
    if rule.action == "DIVERT":
        # ADR-0051: DIVERT and TPROXY share the single reserved TPROXY_MARK, injected by the
        # generator (not a per-rule mark), so one `ip rule fwmark` delivers established/half-open
        # and new packets locally.
        return [_socket_transparent(), _mark_set("meta", TPROXY_MARK, None), _accept()]
    if rule.action == "TPROXY":
        if rule.family is Family.BOTH:
            raise ConfigError(
                f"{ctx}: TPROXY needs a concrete family — narrow the rule to IPv4 or IPv6 "
                "(tproxy in an inet table selects ip or ip6)",
                path=rule.path,
                line=rule.line,
            )
        return [
            _tproxy(rule.family, _require(rule.port, ctx, "a proxy port")),
            _mark_set("meta", TPROXY_MARK, None),  # ADR-0051: reserved shared mark, not rule.mark
            _accept(),
        ]
    raise ConfigError(f"{ctx}: unsupported mangle action {rule.action!r}")  # parser gates this


def _require(value: int | None, ctx: str, what: str) -> int:
    """Narrow an action parameter the parser guarantees present (defensive, ADR-0004)."""
    if value is None:
        raise ConfigError(f"{ctx}: this action needs {what}")
    return value


def _mark_set(kind: str, value: int, mask: int | None) -> _Command:
    """A ``meta``/``ct`` ``mark set``: a plain value, or a masked read-modify-write (ADR-0042).

    With a mask only the masked bits change: ``mark = (mark & ~mask) | value``.
    """
    key = {kind: {"key": "mark"}}
    if mask is None:
        return {"mangle": {"key": key, "value": value}}
    keep = (~mask) & _U32_MASK
    return {"mangle": {"key": key, "value": {"|": [{"&": [{kind: {"key": "mark"}}, keep]}, value]}}}


def _socket_transparent() -> _Command:
    return {"match": {"op": "==", "left": {"socket": {"key": "transparent"}}, "right": 1}}


def _tproxy(family: Family, port: int) -> _Command:
    return {"tproxy": {"family": "ip" if family is Family.IPV4 else "ip6", "port": port}}


# ---- IPv4 DNAT: nat prerouting + forward accept (ADR-0008) -------------------------------

# nftables standard NAT hook priorities: dstnat for prerouting, srcnat for postrouting.
_DSTNAT_PRIO = -100
_SRCNAT_PRIO = 100


def _needs_nat_table(nat: Nat) -> bool:
    """True for a NAT entry compiled into the ``inet nat`` table.

    Every NAT kind uses it **except** an IPv6 DNAT, which does no NAT (ADR-0002) and compiles to a
    direct forward ``ACCEPT`` (#144) — no nat table / prerouting.
    """
    return nat.family is not Family.IPV6


def _nat_base(ruleset: Ruleset) -> list[_Command]:
    """The nat skeleton — ``inet nat`` table + prerouting/postrouting chains — if NAT is used.

    Unlike the always-present ADR-0005 filter skeleton, the nat plumbing is emitted only when a
    NAT entry actually needs the nat table (ADR-0008); a config whose only NAT entries are IPv6
    DNATs (direct-accept, no NAT) carries no nat table, as does one with no NAT at all.
    ``postrouting`` is part of the fixed pair even for a DNAT-only config, ready for the
    SNAT/MASQUERADE sibling.
    """
    if not any(_needs_nat_table(nat) for nat in ruleset.nats):
        return []
    return [
        _nat_table(),
        _nat_chain("prerouting", _DSTNAT_PRIO),
        _nat_chain("postrouting", _SRCNAT_PRIO),
    ]


def _nat_rules(ruleset: Ruleset) -> list[_Command]:
    """Compile each NAT entry by action: DNAT → prerouting dnat + forward accept (ADR-0008);
    SNAT/MASQUERADE → a postrouting source-NAT rule (ADR-0009)."""
    interfaces = _zone_interfaces(ruleset.zones)
    firewalls = {zone.name for zone in ruleset.zones if zone.is_firewall}
    return [cmd for nat in ruleset.nats for cmd in _nat_entry(nat, interfaces, firewalls)]


def _nat_entry(
    nat: Nat, interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> list[_Command]:
    """Route one ``Nat`` to its generator path; source NAT (ADR-0009) needs no zone context."""
    if nat.action in ("SNAT", "MASQUERADE"):
        return [_snat(nat)]
    return _dnat(nat, interfaces, firewalls)


def _dnat(
    nat: Nat, interfaces: dict[str, tuple[str, ...]], firewalls: set[str]
) -> list[_Command]:
    """Compile one ``DNAT`` by family: v4 NAT (ADR-0008) or v6 direct-accept (ADR-0002, #144)."""
    ctx = f"DNAT {nat.source!r} {nat.dest!r}"
    if nat.action != "DNAT":
        raise ConfigError(
            f"{ctx}: unsupported NAT {nat.action} — only DNAT is compiled here "
            "(SNAT/MASQUERADE #76)"
        )
    if nat.family is Family.IPV4:
        return _dnat_v4(nat, interfaces, firewalls, ctx)
    if nat.family is Family.IPV6:
        return [_dnat_v6_accept(nat, interfaces, firewalls, ctx)]
    raise ConfigError(f"{ctx}: a DNAT must scope to IPv4 or IPv6, not {nat.family.value}")


def _dnat_v4(
    nat: Nat, interfaces: dict[str, tuple[str, ...]], firewalls: set[str], ctx: str
) -> list[_Command]:
    """The nat prerouting dnat rule + filter forward accept for one v4 ``DNAT`` (ADR-0008)."""
    host, _, remap = (nat.to or "").partition(":")
    if not host:
        raise ConfigError(f"{ctx}: DNAT target has no host")
    remap_port = remap or None
    return [
        _prerouting_rule(nat, host, remap_port, interfaces, firewalls, ctx),
        _forward_accept(nat, host, remap_port, interfaces, firewalls, ctx),
    ]


def _dnat_v6_accept(
    nat: Nat, interfaces: dict[str, tuple[str, ...]], firewalls: set[str], ctx: str
) -> _Command:
    """IPv6 service exposure: a plain forward ``ACCEPT`` to the v6 address, no NAT (ADR-0002).

    IPv6 does no NAT, so there is no prerouting rewrite and no nat table (#144): the connection
    already carries its final destination, and we simply admit it through the fail-closed forward
    chain. Reuses the ADR-0006/0007 zone matching; the ``ip6 daddr`` match is the family guard, and
    proto/dest-port match as for a normal v6 rule (ADR-0007). Emitted before the policy defaults
    (as the v4 forward accept is) so the fall-through cannot shadow it.
    """
    if not nat.to:
        raise ConfigError(f"{ctx}: DNAT target has no host")
    chain, expr = _chain_and_zone_matches(nat.source, nat.dest, interfaces, firewalls, ctx)
    expr.append(_addr_match("daddr", nat.to))
    expr += _nat_l4_matches(nat.proto, nat.dport, ctx)
    expr.append(_accept())
    return _rule(chain, expr)


def _prerouting_rule(
    nat: Nat,
    host: str,
    remap_port: str | None,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
    ctx: str,
) -> _Command:
    """``iifname <source> <proto> dport <ext-port> dnat to <host>[:<remap>]`` in nat prerouting."""
    expr: list[_Command] = []
    if nat.source != "all" and nat.source not in firewalls:
        expr.append(_ifname("iifname", _iface_value(ctx, nat.source, interfaces)))
    expr += _nat_l4_matches(nat.proto, nat.dport, ctx)
    expr.append(_dnat_target(host, remap_port))
    return _rule("prerouting", expr, table=_NAT_TABLE)


def _forward_accept(
    nat: Nat,
    host: str,
    remap_port: str | None,
    interfaces: dict[str, tuple[str, ...]],
    firewalls: set[str],
    ctx: str,
) -> _Command:
    """The filter forward accept admitting the post-DNAT connection to the internal host.

    Reuses the ADR-0006/0007 zone matching (iifname source, oifname dest), narrows on the internal
    ``ip daddr``, and matches the effective (remapped, else external) destination port.
    """
    chain, expr = _chain_and_zone_matches(nat.source, nat.dest, interfaces, firewalls, ctx)
    expr.append(_addr_match("daddr", host))
    effective_dport = remap_port if remap_port is not None else nat.dport
    expr += _nat_l4_matches(nat.proto, effective_dport, ctx)
    expr.append(_accept())
    return _rule(chain, expr)


def _nat_l4_matches(proto: str | None, dport: str | None, ctx: str) -> list[_Command]:
    """A ``<proto> dport`` match, a bare ``l4proto`` when portless, or []; a lone port fails."""
    if proto is None:
        if dport is not None:
            raise ConfigError(f"{ctx}: a port match needs a protocol")
        return []
    if dport is None:
        return [_l4proto(proto)]
    return [_port_match(proto, "dport", dport)]


def _dnat_target(host: str, remap_port: str | None) -> _Command:
    """``dnat to <host>[:<port>]``; ``family`` pins it to IPv4 without a ``meta nfproto`` guard."""
    target: dict[str, Any] = {"addr": host, "family": "ip"}
    if remap_port is not None:
        target["port"] = _port_value(remap_port)
    return {"dnat": target}


# ---- IPv4 SNAT/MASQUERADE: nat postrouting source NAT (ADR-0009) -------------------------


def _snat(nat: Nat) -> _Command:
    """One ``inet nat postrouting`` source-NAT rule for a MASQUERADE/explicit SNAT (ADR-0009).

    Matches ``oifname <out_interface>`` then ``ip saddr <source_nets>`` (ADR-0007 order), then the
    source-NAT target: ``masquerade`` (dynamic, to the egress interface's address) or
    ``snat to <addr>`` for an explicit ``SNAT(<addr>)``. Source NAT is IPv4 by construction
    (ADR-0002), so the ``ip saddr`` match is the family guard — no ``meta nfproto``. Unlike DNAT
    there is **no** forward accept: source NAT does not open a new forward path.
    """
    ctx = f"{nat.action} {nat.source_nets!r} {nat.out_interface!r}"
    if not nat.out_interface:
        raise ConfigError(f"{ctx}: source NAT needs an egress interface")
    if not nat.source_nets:
        raise ConfigError(f"{ctx}: source NAT needs a source network")
    expr: list[_Command] = [
        _ifname("oifname", nat.out_interface),
        _saddr_match(nat.source_nets),
        _snat_target(nat.snat_to),
    ]
    return _rule("postrouting", expr, table=_NAT_TABLE)


def _saddr_match(source_nets: str) -> _Command:
    """``ip saddr`` over the source-net list: a scalar/prefix, or an anonymous set for a list.

    ``source_nets`` is IPv4 by construction (ADR-0002); each comma-separated element reuses the
    ADR-0007 ``_addr_value`` prefix handling.
    """
    elems = [_addr_value(net.strip()) for net in source_nets.split(",")]
    right = elems[0] if len(elems) == 1 else {"set": elems}
    return {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                      "right": right}}


def _snat_target(snat_to: str | None) -> _Command:
    """``masquerade`` when ``snat_to`` is ``None``, else ``snat to <addr>``.

    ``masquerade`` translates to the egress interface's own (dynamic) address; the explicit form
    pins a fixed source address (family ``ip``, matching the ADR-0008 ``dnat`` target).
    """
    if snat_to is None:
        return {"masquerade": None}
    return {"snat": {"addr": snat_to, "family": "ip"}}


def _nat_table() -> _Command:
    return {"add": {"table": {"family": _FAMILY, "name": _NAT_TABLE}}}


def _nat_chain(name: str, prio: int) -> _Command:
    return {
        "add": {
            "chain": {
                "family": _FAMILY,
                "table": _NAT_TABLE,
                "name": name,
                "type": "nat",
                "hook": name,
                "prio": prio,
                "policy": "accept",
            }
        }
    }


# ---- base skeleton (ADR-0005) -----------------------------------------------------------


def _table() -> _Command:
    return {"add": {"table": {"family": _FAMILY, "name": _TABLE}}}


def _chain(name: str, policy: str, *, hook: str | None = None, prio: int = 0) -> _Command:
    """A ``type filter`` base chain. ``hook`` defaults to the chain name (the ADR-0005 base
    chains, whose name equals their hook at ``prio 0``); the ADR-0063 ``prerouting_raw`` chain
    passes an explicit ``prio`` to sit at ``priority raw`` (-300)."""
    return {
        "add": {
            "chain": {
                "family": _FAMILY,
                "table": _TABLE,
                "name": name,
                "type": "filter",
                "hook": hook or name,
                "prio": prio,
                "policy": policy,
            }
        }
    }


def _rule(chain: str, expr: list[_Command], table: str = _TABLE) -> _Command:
    return {"add": {"rule": {"family": _FAMILY, "table": table, "chain": chain, "expr": expr}}}


def _ct_established_related() -> _Command:
    return {
        "match": {
            "op": "in",
            "left": {"ct": {"key": "state"}},
            "right": {"set": ["established", "related"]},
        }
    }


def _ifname(key: str, value: str | dict[str, Any]) -> _Command:
    return {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": value}}


def _accept() -> _Command:
    return {"accept": None}
