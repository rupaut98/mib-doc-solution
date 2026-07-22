# Technical Memo — MIB Intake Pipeline

## Approach

The pipeline is a classical document-engineering system: PyMuPDF for the native
text layer, Tesseract for rasterized pages, RapidFuzz for closed-vocabulary
normalization, and a mined rule cascade for adjudication. No ML models, no
network, no LLM/VLM anywhere in the runtime.

**Trusted text first.** Every page's text layer is read span-by-span; spans that
are pure white, under 6pt, injection-patterned (`SYSTEM:`, `answer key`,
`BARCODE PAYLOAD`), or watermark-sized are dropped before parsing. On the
training set the hidden white 5pt layer is a perfect inversion trap: 188/188
packets that carry a hidden "answer key" contradict the true adjudication, so
filtering by span attributes neutralizes the entire injection family without
needing to understand its content.

**OCR only where needed.** A page whose visible text is footer-only (~30 chars)
is rasterized at 200 DPI grayscale and read with Tesseract PSM 11 + PSM 6; pages
whose key fields still resist get one escalation pass at 300 DPI with two
binarization thresholds. Roughly 30% of pages are image-only; the rest never pay
OCR cost. Well within the 6 s/PDF budget on 4 vCPUs.

**Closed vocabularies.** Every enum-ish field (12 species, 13 home worlds, 5
visa classes, 10 purposes, 4 fee states, 8 risk flags) is fuzzy-snapped to its
vocabulary, which converts most OCR noise into exact matches. Snake_case risk
flag tokens survive OCR unusually well and are scanned order-independently
across the whole page.

**Measured evidence precedence.** Where sources conflict, the winner was
measured on train rather than assumed: registry > biometric > sponsor letter >
intake. The intake form is the deliberately corrupted source — it loses every
conflict against registry/biometric (21/21 and 13/13 on train) — so the
"primary record" is trusted last, the reverse of the manual's listed order.
Bracketed damage sentinels (`[NAME CUT OUT]`) are dropped, and printed manual
corrections override the fields they correct.

**Adjudication as a mined cascade.** The field manual is incomplete by design;
the rules were completed from the labeled examples, as the manual invites. The
cascade (first match wins): adjudicator-note `Finding:` line (162/162 on train);
unambiguous colored stamp (conflicting stamps ⇒ NEEDS_REVIEW, 9/9); disqualifying
flags ⇒ DENIED; TRANSIT-7 ⇒ DENIED; unpaid fee ⇒ DENIED (DIP-1 not exempt);
revoked sponsor (3 public + 3 inferred: SPN-9090/7331/2718) non-DIP ⇒ DENIED;
Wolf-1061c non-DIP ⇒ DENIED; stale arrival ⇒ DENIED; then review gates (missing
arrival, unknown fee, review-only flags, unreadable flag evidence) ⇒
NEEDS_REVIEW; else APPROVED. Embargo home worlds (TRAPPIST-1e, Eris Relay) imply
`planetary_embargo` (50/50 on train, DIP-1 included).

Two inferences deserve honest flags. The staleness rule is implemented as an
absolute cutoff (2026-01-02) because packet receipt dates are not extractable;
it approximates the manual's relative 180-day rule and would need re-fitting if
the receipt epoch shifts. The fee receipt's Amount+Waiver pair ($809/N-A ⇒ paid,
$0/DIP-WAIVER ⇒ waived) predicts the true fee status perfectly on train and
overrides misprinted status words — a deliberate bet that the amount is the
generator's ground truth, not the label text.

**Uncertainty-aware approval.** A packet whose biometric slip (the only source
of risk flags) exists but resisted OCR — or that contains unclassifiable image
pages that could be the slip — cannot be safely approved; it routes to
NEEDS_REVIEW. This gate, plus requiring trusted-tier evidence before any
deny-rule fires on an OCR-derived value, holds catastrophic false approvals to
the statistical floor: the residue is packets whose deny evidence was never
printed in the packet at all.

**Calibration.** Confidence is the smoothed empirical accuracy of the decision
path that fired, keyed additionally by an evidence signature
(slip seen / flags readable / unclassified pages) for the uncertain paths. This
is exactly what the Brier score rewards: honest probabilities, including 0.4-0.6
confidences on the genuinely ambiguous buckets.

## Known failure modes

Packets whose disqualifying flag evidence is simply absent (no biometric slip
anywhere) are approved by policy and lost; the training set says this is
irreducible from visible evidence. Severely smeared slips still occasionally
read as flag-free. The staleness epoch and revoked-sponsor list are enumerated,
not derived, so novel test-only entries in either would be missed.

## With another week

A stamp/seal-shaped region detector with targeted crop OCR for the worst 5% of
slips; deriving the staleness epoch from printed receipt dates when available;
per-field confidence outputs; and a small held-out harness to re-fit the
empirical confidence table without touching decision logic.
