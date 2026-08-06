# DEVELOPMENT_LOG.md — dig-wallet-backend

High-signal, durable realizations from developing this crate. Concise facts with context — NOT a
change diary.

## Consent decode must require the interpreter, never the builder's claim (#2209)

A spend decode that falls back to the engine-supplied summary when re-derivation fails is fine for a
DISPLAY surface that renders a `verified` flag, but NOT for a pre-sign consent prompt: it silently
degrades from "what the bundle DOES" (re-derived by `verify::analyze`) to "what the untrusted builder
CLAIMS it does" at the exact moment assurance matters, and a caller that forgets to check `verified`
gets a plausible-but-unverified screen. The rule: if two code paths must agree about the MEANING of
something, exactly one may interpret it — the fallback quietly swaps interpreters. Hence two modes:
lenient `decode` (display-only, may be unverified) and `decode_verified` (no fallback, fails closed).
The signing gate (`verify_before_signing`) and the consent prompt both derive from the one interpreter
`verify::analyze`, so the approved screen and the signed bytes share a source by construction.

## chia-wallet-sdk 0.34 — offer requested payments are DIRECT to the payee

In the SDK 0.34 offer model, a take funds the maker's requested payments as ordinary coins created
DIRECTLY to the payee puzzle hashes the offer specifies — they are NOT routed through an intermediate
settlement coin the taker creates + claims. So a taker's requested-payment egress appears as a plain
`CREATE_COIN` to the payee (reviewed as a recipient), while the assets the taker RECEIVES come back to
its own change address. This is why `client::verify` accounts the offered/paid legs the way it does and
why the taker summary lists only the requested payments (what leaves), not the received side.

## Option EXERCISE — two settlement legs, and the builder-enforced-only underlying claim (MR-9)

`dig_options::exercise` (v0.3) builds ONE atomic bundle with, in order: the option singleton spent
through its exercise path (the inner standard layer MELTs it — a magic `CREATE_COIN` amount `-113`,
decoded by the SDK as `Condition::MeltSingleton`, never a value create-coin); the locked underlying (a
`P2OneOfManyLayer` 1-of-2 coin) unlocked via its exercise path, which emits
`CREATE_COIN(SETTLEMENT_PAYMENT_HASH, underlying)` PLUS an `AssertPuzzleAnnouncement` binding the strike
payment to the option's committed requested payment; and TWO settlement legs — the unlocked underlying
claimed to the holder, and the strike paid to the creator.

The sharp edge (the MR-9 stranding surface): consensus forces the STRIKE payment to the creator (via the
underlying's asserted puzzle announcement), but does NOT force the underlying-claim leg back to the
holder — that leg is BUILDER-ENFORCED ONLY. If any path drops or re-routes it, the unlocked underlying
strands on a BARE anyone-can-claim settlement coin (`SETTLEMENT_PAYMENT_HASH`, spendable by anyone with a
`SettlementPaymentsSolution`, no key) for a mempool watcher to steal — while the holder has already paid
the strike.

**The refuted guard (why exercise is REFUSED, not guarded).** The original PR-C approach asserted,
key-aware, that for every unlocked amount an in-bundle claimed-settlement payout of exactly that amount
lands on a WALLET-OWNED puzzle hash before signing (the `assert_option_underlying_reclaimed` / MR-9
guard). A custody audit REFUTED it: proving the reclaim leg is PRESENT in the bundle the wallet signs is
not enough, because the reclaim is not CONSENSUS-forced. The wallet signs only the strike-funding coin;
the underlying's reclaim leg lands on a bare `SETTLEMENT_PAYMENT_HASH` coin that anyone can spend with a
`SettlementPaymentsSolution` (no key). A compromised engine can present a well-formed bundle to pass the
guard, obtain the wallet's strike signature, then broadcast a DIFFERENT bundle that drops/re-routes the
reclaim leg — the strike-funding spend is still valid on its own, so the wallet pays the strike while an
attacker sweeps the underlying. An in-bundle-presence check can never close this: only a consensus
binding (the underlying's exercise puzzle FORCING the reclaim to the holder's puzzle hash, the way it
already forces the strike to the creator) makes exercise safe. That is a `dig-options` builder/puzzle
change (deferred #2245). Until then, exercise is NOT client-seam-signable. The engine still BUILDS a
valid exercise (a raw external key-holder can settle it); only the custody signer refuses. LESSON: for a
leg whose destination the wallet's signature does not itself bind, presence in the signed bundle proves
nothing — require consensus enforcement or refuse.

**Where the exercise refusal actually lives (Case-A, the corrected guard set).** Refusing only the
`P2OneOfManyLayer` underlying leg is NOT sufficient: an attacker can OMIT that leg from the bundle and
still get the wallet to sign the option-singleton melt+message leg (the strip-the-leg attack). The
durable insight is that unlocking the underlying requires a mode-23 (`0x17`) `SEND_MESSAGE`, and the
`OPTION_CONTRACT` puzzle couples that message INSEPARABLY to the singleton MELT — proven by
`chia-sdk-driver-0.34.0` `option_contract.rs::test_incomplete_exercise` (message-without-melt AND
melt-without-message both consensus-reject); `test_transfer_option` proves a plain re-home transfer
succeeds. So consensus already forbids "some other spend unlocks the underlying"; the residual risk is
purely the wallet SIGNING the melt/message leg. `client::verify::analyze` therefore refuses at the
SIGNATURE SOURCE with two guards: (1) any option-singleton spend that does NOT re-home (no odd-amount
`CREATE_COIN` — a melt/exercise or clawback) is refused regardless of the underlying leg's presence;
(2) a transfer's delegated puzzle is held to a default-DENY allowlist (only the re-home `CREATE_COIN`,
its sole `AGG_SIG_ME`, and benign assertions — never a `SEND_MESSAGE`/`RECEIVE_MESSAGE`/`MeltSingleton`/
announcement-CREATE/second value CREATE/unknown opcode). The `P2OneOfManyLayer` refusal is retained as
defense in depth. LESSON: guard the SIGNATURE on the leg that authorizes the dangerous action (here the
melt+message), not the mere presence/absence of a sibling leg — and make the allowlist default-DENY so a
new opcode fails closed. This reasoning is pinned to `chia-sdk-driver 0.34.0` / `chia-puzzles 0.20.3`;
a future SDK/puzzle bump must re-verify the message ⟺ melt coupling.

Transfer is unaffected: it re-homes the singleton through the inner standard layer (the sole signed
`AGG_SIG_ME` binds the destination) and touches no builder-enforced-only leg — so it stays signable.

Conservation consequence (still relevant for TRANSFER): the option builders emit NO `RESERVE_FEE`
(excess funding is an implicit fee). So option (transfer) bundles need IMPLICIT-fee conservation
(`fee = in − out`), NOT the strict `in == out + reserve_fee` used for XCH/CAT/offer sends.

## Option MINT is not client-decodable from coin spends alone (#2243)

The on-chain `OptionMetadata` carries only `expiration_seconds` + `strike_type` — NOT the
`creator_puzzle_hash` or `underlying_amount` that `OptionUnderlying` needs — so the client cannot
re-derive the locked-underlying puzzle hash from a mint's coin spends. Combined with the mint summary
modelling the underlying as a plain output to `owner_ph` (a structural egress on-chain), the mint has a
cross-seam summary-reconciliation gap the client verify cannot close alone. Mint therefore stays refused
at the signer; the reconciliation decision is tracked in #2243.
