# DEVELOPMENT_LOG.md — dig-wallet-backend

High-signal, durable realizations from developing this crate. Concise facts with context — NOT a
change diary.

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
the strike. So the client signer MUST assert, key-aware, that for every unlocked amount an in-bundle
claimed-settlement payout of exactly that amount lands on a WALLET-OWNED puzzle hash before signing.

Conservation consequences: the option builders emit NO `RESERVE_FEE` (excess funding is an implicit
fee), and the melted 1-mojo singleton has no output. So option bundles need IMPLICIT-fee conservation
(`fee = in − out`, the melted singleton excluded from the ledger), NOT the strict
`in == out + reserve_fee` used for XCH/CAT/offer sends. And every settlement egress in an exercise is
reclaimed IN-BUNDLE (both legs), so the egresses are intermediate plumbing — netted out of the reviewable
sink bucket by matching each created settlement coin id to an in-bundle claim.

## Option EXERCISE review summary lists what LEAVES, not what is received

The signer's summary gate hides wallet-owned outputs (they are change). The unlocked underlying returns
to the exercising holder (the wallet), so it is change — the exercise review summary must therefore list
the STRIKE paid to the creator (what leaves) + the implicit fee, NOT the underlying. The pre-PR-C engine
summary listed the underlying-to-owner, which the signer's gate rejected; PR-C changed
`build_exercise_option`'s summary to the strike-to-creator so signer and engine reconcile.

## Option MINT is not client-decodable from coin spends alone (#2243)

The on-chain `OptionMetadata` carries only `expiration_seconds` + `strike_type` — NOT the
`creator_puzzle_hash` or `underlying_amount` that `OptionUnderlying` needs — so the client cannot
re-derive the locked-underlying puzzle hash from a mint's coin spends. Combined with the mint summary
modelling the underlying as a plain output to `owner_ph` (a structural egress on-chain), the mint has a
cross-seam summary-reconciliation gap the client verify cannot close alone. Mint therefore stays refused
at the signer; the reconciliation decision is tracked in #2243.
