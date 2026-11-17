# Specification

This is what every implementation of `@forgesworn/qr` (TypeScript now,
Kotlin and Rust later) must do, so that the same input gives the same
symbol byte for byte. `vectors/encode-vectors.json` is the test of it.
Section numbers refer to ISO/IEC 18004:2015.

## Input

- Text is a sequence of Unicode code points; lone surrogates become
  U+FFFD. Byte segments carry the UTF-8 of their code points, so no
  segment boundary falls inside a character.
- Bytes are encoded as given, always as one byte segment.
- The data is a string or a byte array and nothing else; anything else is
  an argument error (`TypeError`). `null` options mean no options, as
  omitted options do. Level, mode, version, `minVersion` and mask outside
  their ranges are argument errors (`RangeError`). Kotlin is typed and
  checks the ranges alone.

## Mode

Bytes, text with a mode named by the caller, and the empty string are one
segment: bytes and the empty string in byte mode (the empty string as a
byte segment of count 0), named-mode text in that mode, which must hold
every character. Kanji mode is not produced.

Other text is split into numeric, alphanumeric and byte segments with
the fewest bits, worked out exactly in whole bits as follows.

- A digit `0-9` may go in any mode; any other character of
  `A-Z space $ % * + - . / :` in alphanumeric or byte; anything else in
  byte only.
- A segment costs 4 bits of mode indicator, the count field (width by
  version band below), and its data: numeric `10 * floor(n / 3)` plus 0,
  4 or 7 for `n mod 3` = 0, 1, 2; alphanumeric `11 * floor(n / 2)` plus 6
  if `n` is odd; byte 8 per UTF-8 byte. `n` is the segment's characters
  (bytes in byte mode).
- Count field widths are numeric 10, 12, 14; alphanumeric 9, 11, 13; byte
  8, 16, 16 for versions 1-9, 10-26 and 27-40. The segmentation is chosen
  for one band at a time, and a symbol uses the one for its version's
  band, a fixed version included: the same text can split differently at
  versions 9 and 10, or 26 and 27.
- The ECI designator (below) is left out of the cost. It appears only
  with a byte segment, and a fewest-bits segmentation has a byte segment
  only when some character is outside the alphanumeric set, when every
  segmentation has one; so it cannot change the choice.
- Count field limits never bind: a segment whose count overflows its
  field cannot fit the capacity of any version in that band.

Among the segmentations with the fewest bits, the one chosen has the
fewest segments; among those, the one whose mode per character, read from
the start, is earliest in the order numeric, alphanumeric, byte at the
first character where two differ. Adjacent segments never share a mode.
The result is unique, so every port gives the same segment list and bit
stream. Some consequences: `abc123` is one byte segment (byte `abc` plus
numeric `123` costs the same 60 bits at versions 1-9, but takes two
segments); a run of six or seven digits between byte characters splits
off at versions 1-9 only, and a run of eight at versions 1-26 only.

The symbol reports its segments in order, each as a mode and a count, and
its `mode` as the widest among them: byte if any segment is byte, else
alphanumeric if any is, else numeric. For text that needs no named mode
this is the mode the encoder used before it mixed segments.

With `eci: true` and at least one byte segment, the stream starts with
one ECI designator, `0111` and assignment 26 (UTF-8) as 8 bits (section
7.4.2), before the first segment, whatever its mode. It covers every
byte segment after it. A symbol with no byte segment never carries one.

## Version and level

Level M unless the caller names one. The version is the smallest, from
`minVersion` (default 1), whose data capacity holds the stream (ECI if
any, then every segment's header and data) for the segmentation of that
version's band. A requested version that cannot hold the data is an
error, never a silent upgrade. A requested version below `minVersion` is
an argument error (`RangeError`, `IllegalArgumentException` in Kotlin),
not a capacity error.

Input that no version can hold is a capacity error before any segmentation
or bit stream is built, so its cost does not grow with the input. With
`highest` the requested version, else 40, and `available` the data bits of
`highest` at the level less the 4-bit mode indicator, the longest input
that can fit is, rounded down, in bytes for bytes and for byte mode (text
counted in UTF-16 code units, which are never more than its UTF-8 bytes)
`(available - count field) / 8`; in numeric mode `(available - count
field) * 3 / 10`; in alphanumeric mode `(available - count field) * 2 /
11`; and for text with no named mode `(available - narrowest count field)
* 3 / 10`, each count field at the band of `highest`. At version 40 and
level L that is 2,953 bytes, 7,089 digits and 4,296 alphanumeric characters,
and 7,089 code units for unrestricted text. These are upper bounds, never
cut-offs for what fits: every length they allow still goes through the
exact check above. The error is the same as for any other data that does
not fit. Argument errors (an unknown mode, a mode other than byte for
bytes) are raised first. For a named mode the length check comes before the
content check, so text too long for the mode that also holds characters
outside it is a capacity error, not a `RangeError`.

## Bit stream and error correction

The segments in order, each its 4-bit mode indicator (numeric `0001`,
alphanumeric `0010`, byte `0100`), count and data (section 7.4.3 to
7.4.5), after the ECI designator if there is one. Then a terminator of
up to four zero bits, zero bits to a byte boundary, then
pad bytes `0xEC`, `0x11` alternately (section 7.4.10). Codewords split into
blocks as Table 9 gives (group 2 blocks hold one more data codeword);
Reed-Solomon over GF(256) with polynomial `0x11D`, generator roots
`α^0 .. α^(n-1)`. Data codewords are interleaved by index across blocks,
then error correction codewords the same way.

## Matrix

Finder patterns with separators, the dark module at (8, size - 8),
alignment patterns at every pair of Annex E centres except those on a
finder, timing patterns on row and column 6, then format and version
areas reserved. Data fills two-module columns from the bottom right,
upward first, skipping column 6 and every reserved module; remainder
bits are light before masking.

Format information is `(level bits << 3 | mask)` with level bits L=01,
M=00, Q=11, H=10, BCH(15,5) with generator `0x537`, XOR `0x5412`. Bit
`i` (least significant first) goes at the i-th of (8,0) (8,1) (8,2) (8,3)
(8,4) (8,5) (8,7) (8,8) (7,8) (5,8) (4,8) (3,8) (2,8) (1,8) (0,8), as
(x, y), and again at (size - 1 - i, 8) for `i < 8` or (8, size - 15 + i)
otherwise. Version information (version 7 and up) is BCH(18,6) with
generator `0x1F25`; bit `k` (least significant first) goes at
(k / 3, size - 11 + k % 3) and its transpose.

## Mask

Unless the caller names one, every mask 0-7 is applied to the finished
symbol (format and version information included) and scored with the four
penalty rules of section 7.8.3: N1 = 3 per run of five or more same-colour
modules plus one per module beyond five, rows and columns; N2 = 3 per 2x2
same-colour block, overlapping; N3 = 40 per `1011101` with four light
modules before or after, rows and columns; N4 = 10 per whole 5 per cent
that dark modules deviate from half, rounded down. The lowest score wins;
ties go to the lower mask.

One choice the standard leaves open: for N3, four light modules that would
lie outside the symbol do not count (the quiet zone is not scored). The
reference encoder makes the same choice, so masks chosen here match it.

## Output

A square of `17 + 4 * version` modules, row-major, 1 for dark, with no
quiet zone. Renderers add the quiet zone; the default is four modules.
`isDark(x, y)` is false for any coordinate outside the square, negative,
too large or (in TypeScript) not an integer, as the quiet zone is light.

Renderers are not covered by the vectors and need not match byte for byte
across ports, but must keep these properties: the quiet zone is light;
a canvas or bitmap renderer puts module edges on whole pixels (edge of
module `i` at `round(i * width / side)`); a terminal renderer packs two
module rows per line with U+2580 (upper half), U+2584 (lower half), U+2588
(full) and space, inking light modules by default.

The native Rust SVG and terminal renderers require an unmodified code from
the encoder. They check `2 * margin + size` before rendering and panic with
an explicit dimension-overflow error if it cannot be represented by `usize`;
neither multiplication nor addition may wrap. This does not impose a new
margin cap or alter representable renderings. Terminal output grows
quadratically with the side, so callers must bound untrusted margins and
account for normal allocation limits.

### Embedded fixed-buffer Rust encoder

`forgesworn-qr-embedded` (`rust/embedded`) is a separate `no_std` encoder for versions
1–8, all four levels, optional UTF-8 ECI and automatic or explicit masks.
Its default build offers raw-byte encoding and `encode_simple_text`, which
uses one numeric segment for a non-empty digit string, one alphanumeric
segment for other non-empty text wholly in that alphabet, otherwise one
UTF-8 byte segment. The empty string is one empty byte segment. This explicit
single-mode API is not the main encoder's optimal text API.

The optional `optimal` feature adds `encode_text` with a separate caller-owned
`TextPlanner`. Its version, segmentation cost, mask and module matrix follow
the encoder rules above exactly. Raw-byte and single-mode encoding need no
planner even when the feature is enabled. Existing encoder APIs and vectors
are unchanged. Named-mode overrides, decoding and renderers are outside this
crate. The runtime has no dependencies and bundles the standard tables and
this specification, checked against the originals in CI. A separate, unpublished
conformance harness uses the main encoder and shared vectors as test oracles;
those dependencies and fixtures are not part of the distributed crate. Both
the source crate and its extracted distribution run through that harness.

Its options add an explicit maximum version (default 8); minimum version
defaults to 1. An exact version must be inside that inclusive range. Invalid
version ranges and masks, short output slices and capacity failures return
distinct errors. A capacity failure never silently exceeds the maximum.
The early length check bounds text by the best-case numeric capacity in UTF-8
bytes and raw input by byte capacity, before constructing a plan.

The caller supplies a 301-byte `Workspace` and an output slice of at least
301 bytes: 602 bytes of caller buffers. The optional planner adds 980 bytes
on the measured host. Interleaved codewords and the reserved-module map reuse
the same scratch buffer; mask candidates are applied and undone in the output.
The Reed-Solomon phase also has 57 bytes of local arrays, wiped on drop.
These figures exclude scalar locals, call frames, input and compiler spills;
they are not a whole-stack bound.
Modules are packed into bits; callers draw through `Symbol::is_dark` rather
than a byte-per-module array. A symbol borrows the output exclusively and is
not cloneable. Workspace and planner arrays are wiped before and after each
ordinary return, including errors. Planner decisions are also cleared before
the Reed-Solomon and matrix stages. Errors clear the entire output slice;
dropping a successful symbol clears that slice. Volatile stores and a compiler
fence protect these buffer writes from dead-store elimination. These guarantees do not cover
borrowed input, compiler temporaries, registers, padding, panic, power loss or
deliberately forgotten objects. They do not establish a whole-device secret
erasure guarantee.

## Vectors

`vectors/encode-vectors.json` holds 148 symbols produced with an
independent reference encoder, pinned by version and hash in
`scripts/generate-vectors.sh`. Each gives the input and options, the
version, mask, widest mode, segment list, stream length in bits before
the terminator, and the module rows. They cover every version at full
capacity, version 23 at both level H and level L (where the blocks are
of two sizes), every mask, every level, all three modes, both count field
band edges, the empty string, UTF-8 with ECI, every ordered pair of
modes in a mixed stream, three modes in one stream, ties, mixed
segments either side of versions 9/10 and 26/27 (chosen and fixed),
multi-byte UTF-8 with digit runs, ECI with and without a byte segment,
and payment-URI shapes at every level. The reference encoder is a
development-time oracle only and is not part of the package.

What the oracle backs, and what it does not:

- Oracle-backed: given a segment list, the bit stream (mode indicators,
  count fields, data encoding), terminator, padding, Reed-Solomon
  blocks, interleaving, matrix and mask penalties come from the
  reference encoder's own routines, called from a generator compiled into
  its encoder package. The ECI designator and the loop over masks are
  written in the generator, as those routines are private. Every
  single-segment symbol (all are ASCII or use ECI) also matches the
  reference encoder's public encode call module for module.
- Not oracle-backed: the segment lists. The generator works them out with
  its own implementation of the rule above, written apart from either
  port. They are checked independently: against every per-character mode
  assignment for short strings in all three bands; against a search over
  every segment boundary for every vector text up to 1500 characters and
  for random text of about 300 characters;
  against the reference encoder's own minimal-segmentation mode for ASCII
  text without ECI (never more bits nor a larger version, and fewer bits
  on one vector, `mixed-three-modes`, 254 against 256); and by an
  independent decoder reading mixed symbols back, with and without ECI.
- The choice among segmentations with equal bits (the tie-breaks) is this
  specification's own; only the bit count and version are compared with
  the reference encoder's minimal mode, which need not break ties the
  same way.

## Encoder details

What the sections above leave open, as the Rust port's author found on
writing it from them; `vectors/encode-vectors.json` fixes each.

1. Arguments are checked in this order, and the first failure is the
   error: the data's type, the level, the mask, the version, `minVersion`,
   a version below `minVersion`, the mode against the data, and only then
   whether the data fits.
2. The empty string is one segment of no characters: of the named mode
   when one is named, otherwise a byte segment.
3. The terminator is four zero bits, or as many as the version's data
   capacity leaves room for.
4. Function patterns are laid down in this order: the three finder
   patterns with their separators, the dark module, the alignment
   patterns, the timing patterns, the format and version areas. An
   alignment pattern is left out when its centre module is already taken,
   which is so at (6, 6), (size - 7, 6) and (6, size - 7); the pairs of
   centres are taken row by row. A timing module already taken by an
   alignment pattern is left as that pattern has it; timing modules run
   from 8 to size - 9, dark at even places.
5. Data fills pairs of columns from the right: columns size - 1 and
   size - 2, and so on down to 8 and 7, then 5 and 4, 3 and 2, 1 and 0.
   In each row of a pair the right module is filled before the left.
6. With x the column and y the row, a data module is turned over when its
   mask pattern's condition holds; function modules are never masked:
   - 0: `(x + y) mod 2 = 0`
   - 1: `y mod 2 = 0`
   - 2: `x mod 3 = 0`
   - 3: `(x + y) mod 3 = 0`
   - 4: `(floor(y / 2) + floor(x / 3)) mod 2 = 0`
   - 5: `(x y) mod 2 + (x y) mod 3 = 0`
   - 6: `((x y) mod 2 + (x y) mod 3) mod 2 = 0`
   - 7: `((x + y) mod 2 + (x y) mod 3) mod 2 = 0`
7. N3 is scored at every place where the seven modules `1011101` lie
   wholly inside the symbol along a row or a column: 40 when the four
   modules before them are inside the symbol and light, or the four after
   are, and 40 only once when both are. Places that overlap are each
   scored.
8. The version information is the version in its top six bits and the
   BCH remainder in the twelve below, with no mask pattern applied to it.

The renderers are not specified to the character: an SVG or a terminal
drawing may differ between ports as long as it shows the same modules.
The Rust port matches the TypeScript's strings because it was easy to.

## Decoder

The decoder is not bound by the vectors in the same way: ports may find
codes differently, but must return the same payload for any symbol they
read. A port that follows the pipeline below exactly can be held to
`vectors/conformance.json` a stage at a time, results and work counts
included, and the evidence gathered on this pipeline that it does not read
wrong text then applies to it; the Kotlin port and the Rust front end do.
The sections after the list give the detail that takes. The TypeScript
pipeline:

1. Luminance: RGBA to grey as `(77 R + 150 G + 29 B) >> 8`, with alpha
   blended onto white, so a code drawn on a transparent canvas reads.
2. Binarisation: 8x8 blocks; each block's threshold is the mean of the
   block averages in the 5x5 blocks around it; a block with a range of 24
   or less borrows its neighbours' level. Pictures under 40 pixels a side
   use one global threshold.
3. Finders: row scans for 1:1:3:1:1 runs, each checked down the column,
   back across the row and along a diagonal, with a strict and then a looser
   ratio tolerance. Back across the row the total must be within 40% of the
   row's; down the column it may be up to twice or half the row's, since
   perspective stretches a finder more one way than the other. Centres
   within a module of each other merge.
4. Triples: three finders whose module sizes are within a factor of three.
   The top-left is the corner opposite the longest side. Each side from it
   is measured in modules: its length over the module size along it, from
   the dark-light-dark runs at both ends. The two sides must be at least 10
   modules, differ by at most 25% of the longer, and meet at an angle whose
   cosine is at most 0.5. Triples rank by that cosine plus that difference,
   less 0.01 for each sighting of the three finders (up to 15); the cross
   product puts the top-right finder on the right.
5. Size and alignment: size is the mean of the two sides in modules, plus
   7, rounded to `1 (mod 4)`. A projective map through the three centres
   weights each side by the square root of the ratio of its end module
   sizes (taken as 1 outside 0.5 to 2), so it follows perspective; equal
   sizes give the parallelogram. From version 2, alignment candidates are
   found near where that map, and the parallelogram, put the pattern, with
   runs sized from the map there; they are ranked by how well the 5x5
   pattern around each matches along the map's local axes or the
   parallelogram's, whichever matches better. The last resort is the
   parallelogram's fourth corner, as for a code seen head-on, then the map's
   fourth corner when it is a pixel or more away, so following perspective
   only adds attempts. Sizes four and eight modules either side are retried.
6. Sampling: a perspective map from module centres to the picture, then
   format and version information, unmasking and Reed-Solomon correction
   (section 7.5 and annex B). A failed read is retried transposed, for
   mirrored codes, and the whole search is repeated on the inverted
   picture. A block that needed more corrections than Table 9 gives as its
   capacity fails the read: the table withholds p of a block's check
   codewords to catch a misdecode, so a block corrects half of the rest,
   which is 2 errors of 7 check codewords at version 1 level L and 4 of 10
   at 1-M and 2-L. Reed-Solomon alone would correct 3, 5 and 5 there, and
   a patch of noise is about a thousand times likelier to pass that way.
   The one codeword withheld at 1-Q, 1-H and 3-L leaves their capacity as
   it would be, and no other symbol withholds any. A symbol whose data
   codewords are all zero after correction
   reads as nothing, here, in the second look and in `decodeModules`: all
   zeros pass Reed-Solomon, so that is what a texture matching the mask
   pattern (a checkerboard for pattern 0, stripes for 1 and 2, a screen's
   moire) corrects to, and its first four bits would parse as a terminator
   with no text. No encoder following section 7.4 writes it: a mode
   indicator or a pad codeword always follows. An empty payload written as
   a segment of no characters, as `encode('')` writes it, still reads.
7. Segments: numeric, alphanumeric, byte, kanji (kept as Shift_JIS bytes),
   hanzi (kept as GB2312 bytes), ECI, structured append and FNC1 (both
   reported; see below).
   Byte text is UTF-8 under ECI 26, Latin-1 under ECI 1 or 3, and with
   no ECI in force UTF-8 when it is valid UTF-8 and Latin-1 otherwise. Kanji and the other ECIs follow
   "Text for kanji and other ECIs" below. A byte run with no ECI in force
   that is not valid UTF-8 is Shift_JIS, not Latin-1, when it passes the
   test under "Shift_JIS without an ECI" below.
8. Second look: only when steps 3 to 7 have found nothing in either
   polarity. See below.
9. Reduced size: only when the second look has found nothing too, the
   picture shrunk and searched again. See below.
10. Inverted luminance: after all those attempts fail, and only when the
    requested polarity includes light modules on dark, re-threshold the
    luminance inverse when flat local blocks may have hidden the code.
    See "Inverted luminance fallback" below.
11. Version-directed recovery: after all earlier attempts fail, relocalise
    saved full-resolution triples whose agreeing format and version copies
    identify a different size. Strict reads use only the remaining budgets.
    See "Version-directed recovery" below.
12. Ranked overflow: after version-directed recovery also fails, screen
    previously ranked full-resolution triples beyond the first six using
    agreeing format and version copies. See "Ranked overflow recovery" below.
13. Curved-map recovery: after all earlier attempts fail, retry retained
    full-resolution maps anchored by an exact version word. A bounded late
    alignment pass may repair predictions missed on the first sweep.
    See "Curved-map recovery" below.
14. Deferred mesh reading: after earlier paths fail, validate retained mesh
    grids before their timing and edge corrections. See step 14 below.
15. Unattempted curved map: after earlier paths fail and the original four
    second looks are exhausted, try one retained map never refined at full size.
16. Conflicting format headers: after earlier paths fail, try one separately
    retained map with exact version evidence and uniquely stronger format evidence.
17. Ordinary-only curved map: after earlier paths fail, give one retained map
    that received only ordinary refinement the late alignment pass.
18. Conflicting version peer: after earlier paths fail, refine one map with an
    exact matching version word, a weak contradictory peer and agreeing formats.
19. Alternate grid reading: after earlier paths fail, validate one retained
    orientation and format hypothesis using an already sampled refinement grid.
20. Refined header rediscovery: after earlier paths fail, validate the first
    different strict format hypothesis discovered on a failed refinement grid,
    then its existing same-call mesh if that final-grid read fails.

### Reusable camera decoder

The TypeScript `createDecoder()` helper returns an independent synchronous
`Decoder` with `decode(image, options?)` and `reset()`. Its input validation,
options and result fields are those of `decode`. Every call validates the
whole input and reads its current pixels. It keeps its own luminance working
buffer and a rectangle, never caller buffers or a cached payload. Returned
payloads remain valid after subsequent calls and reset.

After a successful read, a following frame of the same dimensions first
searches a padded rectangle around the previous symbol, provided that rectangle
covers at most half the frame. Coordinates in the returned location refer to
the full input image. If the rectangle does not read, the whole frame is
searched in the same call. A failed full-frame read forgets the rectangle;
changed dimensions also discard it. Options, including polarity, apply anew
on every call. `reset()` forgets the rectangle and releases references to
working storage; it is safe to call repeatedly.

This opt-in helper favours a code near the last successful location when a
frame contains several codes. Cropping can change local thresholds and finder
estimates, so its location and chosen code need not equal a fresh `decode`
call. Each crop uses the same decoding and correction rules; a previous result
is never evidence that the current frame is readable. The stateless pipeline
and its conformance work counters are unchanged. The additional cropped search
has the same work caps as an ordinary call on that smaller picture.

### Optional WebAssembly adapter

The separate `@forgesworn/qr/wasm` entry exports `wasmUrl`, the bundled asset's
URL, and `loadWasm(bytes)`, which asynchronously instantiates caller-supplied
`Uint8Array` or `ArrayBuffer` bytes without fetching anything. The module must
implement ABI version 2, including the `qr_text.decode` host import. The default TypeScript entry does not import it.

Each instance exposes synchronous `encode`, `decode` and `decodeModules` with
the corresponding TypeScript input shapes, options and public result fields.
Encoding follows the same segmentation, version and mask rules. Decoding
uses the host character sets with the same rules as TypeScript. The packaged
Rust `host-text` feature asks the host during each kanji/hanzi character or
non-native ECI run, before accepting the symbol. This preserves segment
boundaries, ECI changes and rejection of invalid hanzi cells; raw bytes remain
unchanged. The callback receives borrowed input and a bounded Rust-owned
UTF-8 output buffer, never calls back into the module and retains no memory
views. Unsupported host character sets follow the platform fallback below.
Standalone Rust and its default WASM build retain their table-free contract
and ABI 1; they are distinct from the packaged ABI 2 module.

Input bytes are copied to private reusable linear memory. Native result handles
are freed on success or JavaScript extraction failure. Returned byte and module
arrays are independent copies. `reset()` frees reusable input storage and leaves
the instance usable; it need not shrink linear memory. `dispose()` frees input
storage and releases references to the instance; subsequent encoding, decoding
and reset throw. Disposal is idempotent. `memoryBytes` reports the current
linear-memory size, or zero after disposal, not a guarantee about when garbage
collection occurs. Instances share no mutable state. The adapter applies the
stateless decoder pipeline for `decode`. Its `createDecoder()` method returns
an opt-in tracked `Decoder` following the camera rules above. Sessions have
independent rectangles and share their parent's reusable native input storage;
strided crops copy only their visible pixels into that storage. Session reset
forgets only that session's rectangle. Parent reset frees input storage and
invalidates every session's rectangle before its next read. Parent disposal
invalidates all sessions: their `decode` and `reset` methods then throw. Session
creation also throws after disposal. No session retains a previous payload.

### Arithmetic

Real numbers are IEEE 754 doubles, and each expression is evaluated in the
order written. A length is `sqrt(dx * dx + dy * dy)`, never a library
`hypot`, whose last place differs between platforms. Rounding to a whole
number is `floor(x + 0.5)`. Sorts keep the order of equal items.

The Kotlin port stores luminance in bytes, read as unsigned values from 0
to 255. An exactly sized, packed greyscale input is borrowed for the
synchronous decode call without modification or retention afterwards.
Padded rows and inputs with unused trailing bytes are copied into a packed
plane. ARGB conversion, inversion and reduced pictures also produce byte
planes; reduction sums remain integers until the specified final rounding.
This representation does not change luminance values, stage results or work
counts.

TypeScript and Kotlin use five local counters per cross-check, retaining
each port's number type and arithmetic order. Kotlin reuses the
module-sampling buffer within each picture-size search. The active module
region is reset before every use. This buffer is local to the decode call;
returned payloads and retained retry locations do not refer to it.

### Binarisation, exactly

Step 2, as `vectors/conformance.json` checks it (`bits`).

1. A picture under 40 pixels on either side has one threshold,
   `(min + max) / 2` over all its pixels, and when `max - min` is under 24
   no pixel is dark.
2. Otherwise there are `ceil(width / 8)` by `ceil(height / 8)` blocks.
   Block (bx, by) covers the 8 x 8 pixels from `min(8 bx, width - 8)`,
   `min(8 by, height - 8)`, so the last block of a row or column overlaps
   the one before it.
3. Levels, taken block by block along each row, top row first. A block's
   level is the mean of its 64 pixels. If its `max - min` is 24 or less it
   is flat: its level is `min / 2`, and when it has a block above and a
   block to its left, `around = (above + 2 left + above-left) / 4` from the
   levels already taken, and the level is `around` if `min < around`.
4. A block's threshold is the mean of the 25 levels of the 5 x 5 blocks
   centred on (`bx` held to 2 .. across - 3, `by` held to 2 .. down - 3):
   near an edge the window moves in, it is not cut. The 25 are summed a row
   at a time, left to right, top row first, and divided by 25.
5. A pixel is dark when it is at or below its block's threshold. Where
   blocks overlap, the later block in the order of 3 decides.

A picture whose luminance values are all identical cannot contain a finder
pattern at any reduction. The decoder may stop immediately after recognising
that case, before constructing the binary picture. This applies after RGBA
conversion and alpha blending, and is recomputed for every call.

### Finder scan, exactly

Step 3, as `vectors/conformance.json` checks it (`finders`), run once with
tolerance 0.5 and once with 0.8 in each polarity.

1. Rows `skip - 1`, `2 skip - 1`, ... are scanned, with
   `skip = floor(height / 200)` held to 1 .. 3.
2. Along a row, five counts hold the lengths of dark, light, dark, light,
   dark runs. A dark run is added to the dark place in hand, moving on to
   the next dark place if a light run was counted last. A light run is
   added to the next light place, unless the fifth count is in hand: then
   the five are tested (3 and 4) with `end` the x of that light run's first
   pixel. If they pass, the counts are cleared and the light run less its
   first pixel becomes the second count, with the first count zero; a light
   run of one pixel leaves all five zero, and the next dark run is the
   first count. If they fail, the third, fourth and fifth counts become the
   first, second and third, and the light run the fourth. A row that ends
   with the fifth count in hand is tested with `end = width`.
   Equivalently, complete dark/light/dark/light/dark windows can be read
   directly from row boundaries. Their starting run advances by two after
   rejection or six after acceptance; initial light runs cannot begin a
   candidate, and a final dark run still ends at `width`.
   TypeScript and Rust find the same row boundaries four and eight adjacent
   byte comparisons at a time respectively, using two little-endian words
   and XOR. Each non-zero byte emits one boundary in left-to-right order,
   then is cleared in full; remaining pixels are compared individually.
   Row boundaries and work counts are unchanged.
3. Ratio test with a tolerance: all five counts non-zero and their total at
   least 7; with `module = total / 7` and `slack = module * tolerance`, each
   outer count is under `slack` from `module` and the centre count under
   `3 slack` from `3 module`.
4. A row sighting that passes the ratio test is checked three ways, each a
   walk from a start pixel: back through the dark centre, then a light run
   while it is no longer than `limit`, then a dark run likewise; then
   forward from the pixel after the start through the rest of the centre, a
   light run while it is shorter than `limit`, and a dark run likewise. The
   walk fails if a light run leaves the picture, if a backward run exceeds
   `limit` or a forward one reaches it, or if the centre passes
   `2 total` (on the diagonal, `32 (limit + 1)`), where `total` is the row
   sighting's. Its five counts must pass the ratio test, and the walk gives
   the centre as `end - c4 - c3 - c2 / 2` from the start, `end` being the
   steps forward to the first pixel past the last run. `steps` counts the
   five counts of every walk, failed ones too.
   - Down the column through (`floor(cx)`, y), where
     `cx = end - c4 - c3 - c2 / 2` from the row and `limit` is the row's
     centre count: fails if its total is `2 total` or more, or half of
     `total` or less. It gives `cy`.
   - Back across the row through (`floor(cx)`, `floor(cy)`), same limit:
     fails if `5 |its total - total| >= 2 total`. It gives `cx` again, as
     `floor(cx)` plus the walk's centre.
   - Down the diagonal (1, 1) through (`floor(cx)`, `floor(cy)`), with
     twice the limit and the tolerance plus 0.25; no test of its total.
5. A sighting that passes has module size `total / 7`. It merges into the
   earliest stored candidate within one of its module sizes in x and in y
   whose module size is within 1, or within a quarter of the candidate's:
   x, y and module size become running means, `(old * count + new) /
   (count + 1)`, and the count goes up. Otherwise it is stored with count
   1. Candidates are filed by where they now lie in 16-pixel cells, column
   `min(floor(width / 16), floor(max(0, x) / 16))` and row
   `floor(max(0, y) / 16)`, and only the cells the square of one module
   size around the sighting touches are looked in; `compared` counts every
   candidate looked at.
6. The candidates are returned most-sighted first, equal counts in the
   order first stored.

### Triples, exactly

Step 4, as `vectors/conformance.json` checks it (`triples`).

1. The pool is the first 12 candidates of the finder scan, in its order.
   Every three of them are considered, by their places i < j < k with i
   slowest and k fastest.
2. A three is dropped when the largest of its module sizes is more than 3
   times the smallest.
3. With a, b, c the three in pool order: the top-left is a when side bc is
   at least as long as ab and as ca; else b when ca is at least as long as
   ab; else c. The other two are then (b, c), (c, a) or (a, b).
4. Each side from the top-left is counted in modules: its length over the
   module size along it (below). The three is dropped unless both counts
   are 10 or more; a count that is not a number drops it.
5. With u and v the two sides as vectors from the top-left, and `one` and
   `other` their counts: `cos = |u . v| / |u| / |v|` and
   `mismatch = |one - other| / max(one, other)`. The three is dropped when
   `cos > 0.5` or `mismatch > 0.25`.
6. When `u.x * v.y - u.y * v.x` is negative the two are exchanged, so the
   top-right comes before the bottom-left.
7. The score is `cos + mismatch - 0.01 * min(the three counts of sightings
   added, 15)`. Triples are returned lowest score first, equal scores in the
   order considered.

The module size along the line from finder P to finder Q is
`(run(P, Q) + run(Q, P)) / 14`, or the other run over 7 when one of them
is not a number.

`run(P, Q)` is the length of the dark, light, dark stretch through P's
centre along that line. From `s = (floor(P.x), floor(P.y))` a walk goes
towards `t = (floor(Q.x), floor(Q.y))`, and another the same distance the
other way, towards `o = s - (t - s)` brought inside the picture: with
`scale` starting at 1, a coordinate of o below 0 makes it at most
`s / (s - o)` in that coordinate, one at or past the picture's size makes
it at most `(size - 1 - s) / (o - s)`, and o becomes
`floor(s + (o - s) * scale)` in each coordinate. The run is the forward
walk plus the backward walk less 1, and not a number if either is not.

A walk from s to t steps one pixel at a time along the longer axis of the
line (x and y are exchanged first when `|t.y - s.y| > |t.x - s.x|`), from s
to t inclusive, with `error = -dx / 2` raised by `dy` each step and, when
it passes 0, the other coordinate moved one towards t and `error` lowered
by `dx`; the walk ends if that coordinate is already t's. It ends too on
leaving the picture. Along it a light pixel is awaited, then a dark one,
then a light one, each wait beginning after the pixel that ended the last. The
walk's value is the distance from s to the pixel that ends the third wait,
`sqrt` of the squares of the two differences; if the walk ends during the
third wait, the distance from s to one step past t along the longer axis;
otherwise it is not a number.

### Size and sampling maps, exactly

Step 5, as `vectors/conformance.json` checks it (`triples[].size` and
`placements`). TL, TR and BL are the three finder centres.

1. `across` and `down` are the module sizes along TL to TR and TL to BL.
   There is no size, and no map, unless `(across + down) / 2 >= 1`.
2. `size = floor((|TL TR| / across + |TL BL| / down) / 2 + 0.5) + 7`,
   then moved to 1 (mod 4): up 1 from a remainder of 0, down 1 from 2,
   down 2 from 3. A retry uses the size it is given in place of this. Maps
   are made only for sizes 21 to 177.
3. `wr = sqrt(run(TL, TR) / run(TR, TL))` and
   `wd = sqrt(run(TL, BL) / run(BL, TL))`, each taken as 1 outside 0.5 to 2
   or when not a number. With `steps = size - 7`, the module point (x, y)
   measured from TL's centre lies at
   `(TL + a (wr TR - TL) + b (wd BL - TL)) / w` with `a = x / steps`,
   `b = y / steps`, `w = 1 + a (wr - 1) + b (wd - 1)`: the perspective
   point.
4. The fourth corner is tried at `P = TR - TL + BL` and then at
   `C = the perspective point (steps, steps)`, the second only when it is
   a pixel or more from the first.
5. From size 25, alignment centres are looked for. `G` is the perspective
   point `(steps - 3, steps - 3)` and `F = TL + (1 - 3 / steps) (P - TL)`;
   the estimates are G, and then F when it is more than
   `(across + down) / 2` from G. `u` and `v` are the perspective points
   `(steps - 2, steps - 3)` and `(steps - 3, steps - 2)` less G;
   `u0 = (TR - TL) / steps`, `v0 = (BL - TL) / steps`. With
   `det = |u.x v.y - u.y v.x|`, a module's run is
   `wide = det / max(|u.y|, |v.y|)` along a row and
   `tall = det / max(|u.x|, |v.x|)` down a column.
6. For a reach of 4, then 8, then 16 modules, and for each estimate E in
   turn, the window search (7) gives candidates in its order. One within
   `(across + down) / 4` of a candidate already scored is passed over.
   Each other is scored (8) along u and v and along u0 and v0, keeping the
   better, with `away` its distance from the nearer estimate. No wider
   reach is tried once a candidate has scored 23 or more. Those scoring 20
   or more are kept, best score first, then least `away`, then the order
   scored; the first four are used.
7. The window search: with `m = max(wide, tall)` and
   `radius = ceil(reach * m)`, the window runs from
   `floor(E - radius)` to `ceil(E + radius)` in each coordinate, cut to the
   picture, and is skipped when it is narrower or shorter than `3 m`; its
   pixels are added to `scanned`. Each row is taken from its top, left to
   right, after passing any dark run the window's left edge cuts. Its runs
   then alternate light, dark, light, the last ending at the window's right
   edge. Whenever a light run ends a light, dark, light three whose
   lengths are each less than `0.6 wide` from `wide`, `cx` is the centre
   of the dark run, and the column through `floor(cx)` is walked from that
   row: up and down through the dark run, then through the light runs
   beyond, none leaving the window. If those three lengths are each less
   than `0.6 tall` from `tall`, `cy` is the centre of the column's dark
   run, and (cx, cy) joins the first stored candidate within `m` of it in
   both coordinates, as a running mean with its count raised, or is stored
   with count 1. The candidates are returned in order of their distance
   from E in units of `m`, with 3 added for a count of 1, equal values in
   the order stored.
   These overlapping triples may be read directly from row boundaries,
   advancing by two runs each time and retaining the clipped first and
   last light runs.
   Rust and Kotlin may omit a stored candidate from later merge lookup when, at the
   first accepted observation on row `y`, `lower = y - ceil(tall)`, its
   centre `f.y` is below `lower`, and `abs(f.y - lower) > m`. Accepted
   centres on that row and later rows cannot match it, so it cannot move
   back into range. The complete candidate vector, insertion order, running
   means, returned order and work counts are retained; equality at the
   distance boundary is retained in lookup.
8. The score of a centre along steps `u` and `v` is the most, over the
   scales 0.85, 1 and 1.15, of the 25 modules (i, j) from -2 to 2 each
   that match: the pixel at `floor(centre + (i u + j v) * scale)` is dark
   exactly when `max(|i|, |j|)` is not 1. A point outside the picture is
   light.
9. The maps, in the order tried: one through each alignment centre kept,
   then one through each fourth corner. A map takes the module points
   (3.5, 3.5), (far, 3.5), A and (3.5, far), with `far = size - 3.5`, to
   TL, TR, the target and BL: for an alignment centre
   `A = (size - 6.5, size - 6.5)`, for a corner `A = (far, far)`.
10. Its matrix is `S(picture points) x adjoint(S(module points))`, a 3 x 3
    product with each entry's three terms added left to right. For four
    points p0 to p3, with `d3 = p0 - p1 + p2 - p3`, `d1 = p1 - p2`,
    `d2 = p3 - p2`, `den = d1.x d2.y - d2.x d1.y`,
    `g = (d3.x d2.y - d2.x d3.y) / den` and
    `h = (d1.x d3.y - d3.x d1.y) / den`, S is, row by row,
    `p1.x - p0.x + g p1.x`, `p3.x - p0.x + h p3.x`, `p0.x`;
    `p1.y - p0.y + g p1.y`, `p3.y - p0.y + h p3.y`, `p0.y`; `g`, `h`, 1.
    When d3 is zero in both coordinates it is `p1.x - p0.x`,
    `p2.x - p1.x`, `p0.x`; `p1.y - p0.y`, `p2.y - p1.y`, `p0.y`; 0, 0, 1.
    The adjoint of the rows (a, b, c), (d, e, f), (g, h, i) is
    `ei - fh`, `ch - bi`, `bf - ce`; `fg - di`, `ai - cg`, `cd - af`;
    `dh - eg`, `bg - ah`, `ae - bd`.
11. Module (x, y) is sampled at
    `((m0 X + m1 Y + m2) / w, (m3 X + m4 Y + m5) / w)` with
    `w = m6 X + m7 Y + m8`, `X = x + 0.5` and `Y = y + 0.5`.

### The search, exactly

Steps 3 to 6 as one loop, which fixes `result` and `work`.

1. In each polarity the option allows, the picture first and then its
   inverse, and for tolerance 0.5 and then 0.8: the finder scan, the
   triples, and the first 6 of them.
2. For each triple, the maps at its own size are made. The estimate is the
   size of the first of them; with none, the size of step 5 when it is 181
   or 185; otherwise the triple is passed over.
3. For the estimate and then 4 below, 4 above, 8 below and 8 above it, the
   maps at that size are made (the first size's are not made twice), and
   each in turn is sampled and read.
4. Before a map is sampled, one is taken from the frame's 720 and from the
   size's own allowance (the whole 720 at full size, 30 at a reduced
   size; step 10 shares a further allowance of 30 across its sizes), and
   `maps` is counted, and `reduced` at a reduced size. With
   either at nothing, the search of that polarity ends there, whatever
   maps and triples were left.
5. Sampling: each module (x, y) of the size is the pixel at the floor of
   its sample point, light when that point is outside the picture.
   Sampling may be deferred until a module is requested and its value
   retained for subsequent requests, including transposed reads and the
   format and version checks for keeping a second-look candidate.
6. The grid is read as below; if it does not read, it is read transposed,
   module (x, y) taken from (y, x), and a read then is `mirrored`. The
   first read ends the search, with the three finder centres and the
   alignment centre of its map as the location.

### Reading a symbol, exactly

What `decodeModules` does to a grid, and step 6 to each sampled one;
`vectors/conformance.json` checks it (`symbols`).

The native Rust `decode_modules` entry returns `None` for an illegal grid
size or a buffer shorter than the grid. It checks the legal size range and
step before multiplying the size, including for values near `usize::MAX`;
invalid dimensions must not overflow or panic.

1. The size is 21 to 177 and 1 (mod 4). The version is as "Version
   information" says. Its two blocks are read most significant bit first:
   for k from 17 down to 0, with `i = floor(k / 3)` and `j = k mod 3`, the
   bottom-left copy's bit is module (i, size - 11 + j) and the top-right
   copy's is module (size - 11 + j, i).
2. The two copies of the format word are read most significant bit first,
   bit i from 14 down to 0. The first copy's bit i is the module at place i
   of (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
   (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8). The second
   copy's is module (size - 1 - i, 8) for i under 8, and
   (8, size - 7 + (i - 8)) otherwise. The format is the nearest of the 32
   format words, taken in the order of levels L, M, Q, H and within each
   masks 0 to 7, within 3 bits of either copy: the first copy is compared
   with all 32 and then the second, and a word replaces the one in hand
   only when it is strictly nearer. With none within 3 bits the grid does
   not read.
3. The bit stream is the data modules in the order the encoder places them
   (two columns at a time from the right, the pair stepping left over
   column 6, upwards first and then alternately, the right module of each
   pair first, function modules passed over), the first eight times the
   version's total codewords of them. A bit is 1 when its module, dark as
   1, differs from the mask pattern's value there. Codewords fill most
   significant bit first.
4. The codewords are dealt back into blocks: data codeword i of each block
   in turn, for i from 0 up, a block joining only while it has one; then
   check codeword i of each block in turn. Table 9 gives, for the version
   and level, the check codewords a block and the two groups of blocks, the
   second with one more data codeword than the first; its values, and the
   alignment pattern centres of Annex E, are in `vectors/conformance.json`
   under `tables`.
5. A block reads when some codeword of its Reed-Solomon code (GF(256) by
   `0x11D`, generator roots 2^0 to 2^(check codewords - 1)) differs from
   it in e places with `2 e` no more than its check codewords; there is at
   most one, and the block becomes it. With none the grid does not read,
   and it does not read when e is past the block's capacity under step 6
   of the pipeline. `corrected` is the sum of e over the blocks.
   Implementations may extract and correct each block directly from its
   interleaved positions and stop at the first failing block; this changes
   neither acceptance nor the resulting data and correction count.
6. The data codewords of the blocks, in block order, are the data. All
   zero, the grid does not read.
7. Segments are parsed from the first bit while 4 bits or more remain; the
   count's length goes by the version: 1 to 9, 10 to 26, 27 to 40.
   - `0000` ends the data.
   - `0001`, numeric: a count of 10, 12 or 14 bits; each three digits 10
     bits and at most 999; a last two 7 bits and under 100; a last one 4
     bits and under 10.
   - `0010`, alphanumeric: a count of 9, 11 or 13 bits; each pair 11 bits
     and under 2025, the first character `floor(v / 45)` and the second
     `v mod 45`; a last one 6 bits and under 45.
   - `0100`, bytes: a count of 8, 16 or 16 bits, then the bytes.
   - `1000`, kanji: a count of 8, 10 or 12 bits; each character 13 bits,
     v, standing for the Shift_JIS pair
     `(floor(v / 0xC0) << 8 | v mod 0xC0)` plus `0x8140` when that is under
     `0x1F00`, else plus `0xC140`.
   - `1101`, hanzi: as "Text for kanji and other ECIs" says.
   - `0111`, ECI: a byte `0xxxxxxx` is the assignment; `10xxxxxx` and one
     more byte give 14 bits; `110xxxxx` and two more give 21; any other
     first byte and the grid does not read.
   - `0011`, `0101` and `1001`: structured append and FNC1, as below.
   - Any other mode, a value past the limits above, or data that ends
     inside a segment: the grid does not read.
8. `bytes` is the digits and characters of numeric and alphanumeric
   segments as ASCII, byte segments as they are, and the pairs of kanji
   and hanzi. `text` is made run by run, a run being the bytes between one
   ECI designator, kanji or hanzi character and the next, as step 7 of
   the pipeline and the sections on text say.

### Second look

While the search runs, each map whose straight and transposed reads both
fail is a candidate if its two format copies, as sampled in step 6, lie
within 2 bits of the same format word, in the same orientation. The
distance of a word is the larger of its distances from the two copies, and
the word and orientation taken are those of least distance: on a tie the
straight orientation before the transposed, and within one the first word
in level and mask order. A map is no candidate when its version information, read in that
orientation as in Version information, decodes to a version of another
size; when neither copy decodes the map stays a candidate, and the
version never chooses a size or adds a read. The 4 candidates with the
smallest such distance are kept, earliest first on a tie. A random grid
passes this test with a chance of about 32 x (121 / 32768)^2 x 2, under
1 in 1000.

Once both polarities have found nothing, each kept candidate is read once
more, in order:

1. A probe gives a point's darkness: the binariser's threshold for the
   pixel the point falls in, less the grey there, interpolated bilinearly
   between pixel centres (at `i + 0.5`); negated on the inverted picture.
   Positive is dark. A point outside the picture is light.
2. Mesh, from version 7, whose alignment patterns form a lattice of n by n
   centres (n of 3 or more, Annex E): the three lattice points at the finders,
   (6, 6), (`size - 7`, 6) and (6, `size - 7`), are placed by the map with no
   offset. The others are taken in order of their lattice steps to the nearest
   of those three (the least of `q + r`, `n - 1 - q + r` and `q + n - 1 - r`
   for lattice column q and row r), then row by row. Each is given a
   prediction, the mean offset of its four lattice neighbours already placed,
   and is looked for at every offset from it up to 3 modules either way, in
   quarter modules: at each, the 25 module centres of the pattern are probed
   through the map, and the offsets where the most of them have the pattern's
   colour (dark centre, light ring, dark ring) are kept, along with that
   count. The pattern is found when at least 24 of the 25 match, the kept
   offsets lie within three quarters of a module of their mean along each
   axis, and that mean is at least a quarter module inside the window; its
   offset is then the prediction plus that mean. Otherwise it is doubtful and
   its offset is the prediction alone. With none found the map is left as it
   is. Otherwise each map point (x, y) is moved by the offsets at the four
   corners of the lattice cell it falls in, interpolated bilinearly, with x
   and y held to the first and last lattice centres beyond them, and the steps
   below use the moved map. The mesh reads function patterns only, never data
   modules.
3. Timing: along row 6, from column 8 to `size - 9`, each module's run of
   the colour it should have is found near where the last module's centre
   was (starting at 0): the nearest point of that colour within 12/16 of a
   module either side, in sixteenths, then extended a sixteenth at a time,
   at most 1.6 modules either way. A run under 0.4 or over 1.6 modules
   measures nothing; otherwise its midpoint is the module's offset, and the
   next module starts from it. Each offset becomes the median of itself and
   its two neighbours' (those measured), gaps are filled linearly between
   their neighbours (from 0 at the finders), and the same is done down
   column 6. Module `(x, y)` then sits at map point `(x + column offset of
   x, y + row offset of y)`.
4. Edges: at those points every module is sampled with the probe. For each
   pair of neighbouring modules, across or down, that differ, the edge is
   looked for from the first centre towards the second in sixteenths: the
   first sample of the other colour, interpolated linearly with the one
   before it, less a half, is that edge's offset in modules (none if the
   first centre is not its own colour). The offsets along each boundary
   between two columns (or rows) are fitted by least squares to a line in
   the row (or column) index, zero with fewer than three. Each module moves
   by the mean of the lines on its two sides (one at the symbol's edge).
5. The moved centres are sampled with the probe and read as in step 6, in
   the orientation the candidate's format copies agreed in only. The result
   counts only if its level and mask are the ones they agreed on.

The first such read that passes is the result, with the candidate's
location, polarity and orientation. Nothing else is relaxed: format,
version, Reed-Solomon and segment checks are those of step 6.

### Second look, exactly

What the section above leaves open; `vectors/conformance.json` checks it
through the `result` and `work` of the pictures that need a second look.

1. Candidates are kept for one size at a time: the picture, and each
   reduced size, starts with none, and looks again only at its own. The 4
   second looks are for the frame, shared by every size. A candidate goes
   into the list after the last one whose distance is no greater, and the
   list is cut to 4. Both polarities of a size are searched before any
   second look, and their candidates share the one list.
2. The probe at (x, y): outside the picture, or with a coordinate that is
   not a number, it is -1 in either polarity. Otherwise, with
   `fx = x - 0.5` and `fy = y - 0.5`: `x0 = floor(fx)` held to
   0 .. width - 1, `x1 = min(width - 1, x0 + 1)`, `ax = fx - x0` held to
   0 .. 1, and the same down; the grey is
   `(g(x0, y0) (1 - ax) + g(x1, y0) ax) (1 - ay) +
   (g(x0, y1) (1 - ax) + g(x1, y1) ax) ay`, and the probe is the
   threshold of the pixel (`floor(x)`, `floor(y)`) less that grey, negated
   on the inverted picture. A pixel in the last 8 columns takes the last
   block of its row of blocks, and one in the last 8 rows the last row of
   blocks. Dark is above zero.
3. The mesh takes the lattice points in order of their steps to the
   nearest finder and then of `row * n + column`. A point's prediction is
   the mean offset of those of its left, right, upper and lower
   neighbours that have been placed, at a finder, found or doubtful
   alike, and zero with none. Offsets are tried row by row, from -12 to 12
   quarter modules down and within each across. A higher score than any
   before starts the kept set afresh; an equal one joins it. With `mx` and
   `my` the kept offsets' means in quarter modules, the pattern is found
   when the score is 24 or 25, no kept offset is more than 3 quarters from
   the mean along either axis, and `|mx|` and `|my|` are 11 or less. For
   every lattice point but the three at the finders `probed` grows by
   25 x 25 x 25, found or not, and `meshes` grows by one when any is
   found.
4. After all alignment searches, mark each measured node (state 2) trusted.
   The three synthetic lattice corners are not measurements: the actual
   finder centres are at module indices `(3, 3)`, `(size - 4, 3)` and
   `(3, size - 4)`. For each corresponding corner cell, fit its synthetic
   corner only when all three other nodes are measured. Evaluate that cell's
   bilinear weights at the actual finder centre, using the actual centre
   spacings. In row-major order, sum each other node's weight times its
   offset; the fitted corner offset is the negative sum divided by its own
   weight, separately for x and y. A non-finite or zero divisor, or a
   non-finite fitted value, leaves the corner unchanged. Mark a fitted
   corner trusted without changing its state or the measured-node count.
   Fits never become search anchors; measured alignment offsets are unchanged.

   A point (x, y) of the bent map lies in the lattice cell found for each
   coordinate apart: initially hold the coordinate to `0 .. size - 1`,
   and select the first cell whose upper centre is not below it, with the
   first or last cell used beyond the lattice. A point on a centre belongs
   to the cell below it; `s` and `t` are its fractions across and down.
   When either coordinate lies outside the lattice and any of the cell's
   four nodes is untrusted, recompute both cells and fractions with each
   coordinate held to the first and last lattice centres, as before.
   Trusted outer cells therefore continue linearly to legal module centres;
   unsupported outer cells retain the previous clamp. The offset is
   `(1 - t) ((1 - s) o00 + s o10) + t ((1 - s) o01 + s o11)` in each of x
   and y, o being the cell's four corner offsets, and it is mapped as
   (x, y) itself plus that offset, not the held coordinates. Fitting preserves
   the finder anchors up to floating-point roundoff and changes interpolation
   inside those three corner cells as well as outside the lattice. Different
   sampled modules can change the reported correction count or which valid
   map supplies the optional alignment location.
5. The timing walk measures along the line from one module's centre to
   the next one's, in units of that step. For module k from 8 to
   `size - 9`, dark when k is even: the seed is the last measured offset
   (0 at first) if the probe there has the module's colour; if not, for
   1 to 12 sixteenths in turn, that far below it and then that far above.
   With no seed the module is not measured. The run is extended a
   sixteenth at a time, downwards while it is less than 1.6 below the seed
   and upwards while less than 1.6 above; its width is its two ends'
   difference plus a sixteenth, and it measures nothing under 0.4 or over
   1.6. Light is a probe of zero or less.
6. The median of a module and its two neighbours, of those measured, is
   the larger when there are two. An unmeasured module between the nearest
   values l to its left and r to its right, modules 0 to 7 and the last 8
   counting as 0, is `lv + ((rv - lv) * (k - l)) / (r - l)`.
7. An edge is looked for at 0 to 16 sixteenths of the way from the first
   centre to the second. With `previous` the last probe of the first
   module's colour and `d` the first of the other, the fraction is
   `previous / (previous - d)`, held to 0 .. 1, or a half when they are
   equal, and the offset is the sixteenths before it plus that fraction of
   one, less a half. All 17 of the first colour is no edge.
8. The line through a boundary's points (index, offset), taken in order of
   index: with n points and sums `sx`, `sy`, `sxx`, `sxy`, the slope is
   `(n sxy - sx sy) / (n sxx - sx sx)`, zero when that divisor is zero,
   and the value at t is `(sy - slope sx) / n + slope t`.
9. Module (x, y) moves across by the mean of the lines of the boundaries
   on its left and right, evaluated at y, or by the one line it has at the
   symbol's edge; down likewise, evaluated at x. It is read at the map
   point `(x + column offset + that, y + row offset + that)`.

### Reduced size

### Reduced size

A code whose modules are many pixels wide can carry texture inside them
(scan lines, a screen's moire, print grain) that the binariser of step 2
breaks into shapes of its own, so steps 3 to 8 find nothing. Once they
have, in every polarity asked for, the picture is shrunk by a factor f of
8, then 4, then 2, and steps 2 to 8 run on the reduced picture as on the
full one; the first read ends the search.

1. Shrink: applied to the luminance plane of step 1. The reduced picture is
   `floor(w / f)` by `floor(h / f)` pixels; the columns and rows left over
   at the right and bottom are dropped. Each reduced pixel is
   `(sum + floor(f * f / 2)) div (f * f)` of the f x f pixels it covers,
   in integers.
2. A factor is skipped when either reduced side is under 21 pixels: a
   version 1 symbol is 21 modules a side, and the search needs at least a
   pixel a module, so nothing smaller can hold one.
3. Work: maps come out of the frame's one cap of 720 (see Bounded work),
   what the full size and the factors before have left of it, and each
   factor takes at most 30 of them; once none are left the pass stops.
   Second looks come out of the frame's 4, shared by every size. The 30
   keeps noise within the work bound below; a code that needs more than 30
   maps at one size is not read at that size.
4. Gate: at reduced size a read, in step 6 or in the second look, counts
   only if both of its format copies, sampled in the orientation it was
   read in, lie within 2 bits of the format word of its decoded level and
   mask. Format words are at least 7 bits apart, so no other word is as
   near. A read that fails the gate is no read, and no transposed read and
   no candidate follow from that map.
   Before ordinary symbol reading wherever this gate applies, the two
   format copies are checked in both orientations. If neither orientation
   has a shared format word within 2 bits, the map is rejected before
   sampling data or correcting codewords: it could neither pass the gate
   nor become a second-look candidate. If either orientation agrees, the
   original read order and post-read gate still apply. This does not apply
   to ordinary full-size reads, and does not change map or work counts.
5. The `inversion` option holds as at full size. The location returned is
   in full-picture coordinates: coordinates are continuous, pixel i covering
   `[i, i + 1)`, so a point `(x, y)` in the reduced picture is `(x f, y f)`
   in the full one.

### Inverted luminance fallback

Step 10 runs only after steps 2 to 9 return no result, when `inversion` is
`both` or `inverted`, and the shared map allowance is not exhausted. It
requires a full-size picture of at least 40 pixels on both sides, at least
one flat 8 x 8 block under the binarisation rule, and an overall luminance
range greater than 24. Uniform and near-uniform pictures, and pictures with
no flat blocks, skip this pass.

The flat-block level assumes light background. Simply flipping the binary
picture cannot reverse that assumption. The fallback instead replaces each
luminance value v with `255 - v` and computes fresh thresholds. It searches
normal polarity on this inverse at full size, then factors 8, 4 and 2 under
the reduced-size rules. Every size, including full size, requires both
format copies to agree under the gate in Reduced size, rule 4.

The entire fallback shares one allowance of 30 maps across its sizes, taken
from the same remaining frame allowance of 720; second looks use whatever
remains of the frame's four. It stops when either map allowance is exhausted.
Candidates and second-look sampling use the inverse luminance consistently.
Returned locations refer to the original full picture, `mirrored` retains
the sampled orientation, and `inverted` is true. Earlier successful results
take priority and remain unchanged. `reduced` counts maps sampled at reduced
size in this fallback too.

### Version-directed recovery

Step 11 runs only after every earlier search and second look has failed.
During the original full-resolution binary search, a failed map may provide
a size hint when both format copies agree under the existing agreement rule,
and, in that orientation, both version blocks independently decode within
three bit errors to the same version, different from the map's size. Neither
reduced pictures nor the inverted-luminance fallback supply hints.

Keep at most four hints in first-seen order. Hints with the same three ordered
finder centres, target size and polarity are duplicates. After the earlier
passes fail, rebuild the original full-resolution binary picture and locate
each saved triple at exactly `17 + 4 * version`, without neighbouring size
retries. Both normal and inverted binary hints retain their original polarity.
Each map read requires the strict format agreement used at reduced sizes.
Failed eligible maps enter the existing second-look queue, with its normal
distance ordering; second looks also require strict format agreement.

This pass uses at most 30 maps from the frame's remaining allowance and only
its remaining second looks. A queued second look remains eligible after the
map allowance is exhausted. It collects no further hints and increases
neither frame cap. Earlier successful results therefore keep priority. Grid
decoding and symbol parsing still reject a mismatching version; this pass
creates new picture maps rather than resizing a sampled grid.

### Ranked overflow recovery

Step 12 runs only after steps 2 to 11 return no result. When the original
full-resolution binary search finishes trying the selected six triples in a
pass, retain its ranked list if more triples remain. Reduced pictures and the
inverted-luminance fallback do not supply lists. Retain the original pass order,
rank order and binary polarity; do not rescan for finders.

With map allowance remaining, rebuild the original binary picture. Inspect
each retained list from its seventh triple onwards. Triples with identical
three ordered finder centres and polarity are duplicates, even across passes.
For each unseen triple, compute only the original corner maps at the estimated
size, in their usual order, without an alignment search or neighbouring sizes.
Invalid sizes and geometry produce no maps.

Probe each corner map for both format copies under the existing agreement
rule, then both version copies in the format's orientation. The version copies
must independently decode within three bit errors to the same version. A
qualifying map admits full location at exactly `17 + 4 * version`, whether or
not that size differs from the estimate. Admit each ordered triple, polarity
and target size only once. Full maps and queued second looks require strict
format agreement and all ordinary version, Reed-Solomon and segment checks.
Keep second-look candidates in their existing distance order.

One local allowance of 30 maps includes both header probes and full-map reads;
each also consumes one of the frame's remaining 720 maps. Check the allowance
before computing the full locations. Header probes count as maps even though
they sample only headers. Invalid geometry consumes no maps, but the finite
retained ranked lists bound the number of such probes. Queued second looks use
only the frame's remaining four and remain eligible after map exhaustion.
This pass collects no additional lists or version hints. Earlier successes
retain their result, ordering and work counts.

### Curved-map recovery

Step 13 runs only after steps 2 to 12 return no result. During failed reads
of original full-resolution binary maps, retain a separate list of at most
four candidates. Reduced pictures and other recovery passes do not add to this
list; the full-size inverted-luminance fallback has its own list below. No new
finder, size or map search is performed by this recovery.

Check straight and then transposed orientations separately. From version 7,
at least one version copy must be an exact BCH codeword for the map's existing
size. An independently decodable peer, within the ordinary three-error radius,
must identify the same version. At least one format copy must decode within
that radius, and any independently decodable peer must identify the same error
correction level and mask. This evidence admits a retry, never a result.

Rank candidates by the smaller format distance, retaining encounter order on
a tie. Identical size, projective matrix coefficients, polarity, orientation,
level and mask identify a duplicate. Retain only four; this list never displaces
the ordinary second-look queue. After every earlier recovery fails, process it
in order using only the frame's remaining second looks, even if map allowance
is exhausted. Stop at the first successful strict read.

The full-size inverse-luminance fallback in step 10 retains a separate list of
up to four maps under the same admission, ranking and duplicate rules. It may
retain a map before step 10's ordinary two-copy format gate refuses it; this
does not relax that gate for an ordinary read. Only maps already charged to
step 10's shared 30-map allowance qualify, never its reduced-size maps. Keep
the original-luminance list first. If that list also fails and second looks
remain, refine the inverse-luminance list against the same inverted luminance
and its own thresholds, then report a successful result as inverted. The lists
share the frame's four-second-look cap and add no map searches.

Each candidate first uses the ordinary alignment mesh. Then freeze its accepted
alignment states and offsets. Visit only nodes that were predicted, in the
original lattice traversal order, at most once more. Search each of the left,
right, up and down rays for its nearest two accepted alignment nodes; finder
anchors and predicted nodes are not measurements. Choose the pair whose nearer
node is closest in module coordinates, then whose farther node is closest,
then ray order. Extrapolate both offsets linearly using the actual alignment
centre spacing. Without such a pair, leave the node unchanged.

Search the same three-module window at quarter-module steps around that
prediction. The existing 24-of-25 match, spread and window-edge tests remain
unchanged. Accept a successful late measurement; on failure preserve the
original offset. Newly found nodes never become anchors in this pass. Retain
all initially accepted nodes. Bilinear mesh interpolation, timing walks and
edge refinement are unchanged. Count every additional pattern search in
`probed`, and count the resulting mesh once.

The result must pass the ordinary version, Reed-Solomon and segment rules,
match the admitted level and mask, and have both final format copies within
two errors of that word. Earlier successful reads keep their results, ordering
and work counts; their meshes still use only one pass.

### 14. Read retained meshes after all earlier paths fail

A second look can move a readable alignment mesh away from the module centres
when its timing walk follows nearby data instead of the timing pattern. If a
second look formed a mesh but its final refined read fails any of that path's
acceptance checks, sample the same mesh directly once. Retain its owned module
grid, size, admitted level and mask, orientation, public polarity and location.
Do not repeat alignment searches or timing and edge refinement. A second look
that formed no mesh retains nothing.

Only after every return path in steps 1 to 13 fails, try these saved grids in
their original second-look order. Both format copies must agree with the saved
level and mask within two errors; the ordinary version, Reed-Solomon and segment
checks must pass, and the decoded level and mask must match the saved values.
The first such read returns. All earlier successful results, including their
correction counts and locations, keep priority unchanged.

Locations from reduced images are multiplied by their reduction factor, as for
an ordinary read. Grids sampled from inverse luminance report inverted polarity
even when that internal pass sampled dark modules normally. Retain no image
closures: each saved grid owns its bytes and the resolved public metadata.

### 15. Retry one unattempted curved map after exhaustion

The first four second looks can be spent on maps whose header evidence was
plausible but whose grid size or placement was wrong. Remember those four
attempted candidates with their reduction factor and luminance basis. Only
after every earlier return path, including step 14, fails, and the original
second-look allowance is exhausted, inspect the retained curved maps from
step 13: original luminance first, then inverse luminance, each in its
existing retained order.

Choose the first candidate with a projective matrix that was never attempted
at full size in the same luminance basis. Equality requires identical matrix
coefficients, size, orientation, polarity, error-correction level and mask.
A reduced-size attempt does not exclude a full-size map. Matrix-less maps are
ineligible; do not approximate equality of arbitrary projection functions.
These are existing candidates admitted by an exact matching version word and
non-conflicting readable headers; no new map search or admission gate is added.

Try only that one candidate, using the strict second look and its deferred
alignment pass from step 13. If its final refined read fails, directly sample
and validate its mesh as in step 14. Both final format copies must match the
admitted level and mask within two errors, and ordinary version, Reed-Solomon
and segment checks must pass. Return immediately after this candidate, even
when it fails; do not try the rest of either queue. Resolve its full-size
location and public inverted polarity as for earlier reads.

Every earlier successful result, including its location, correction counts and
other metadata, retains priority. This terminal retry explicitly raises the
maximum number of second looks from four to five; the original four attempts
and their scheduling remain unchanged.

### 16. Retry one map with conflicting format headers

During the existing full-size curvature collection points, inspect both
orientations as before. A separate candidate may be retained when the sampled
size has an exact matching version word, every independently readable version
peer agrees, and both format copies decode but disagree. The stronger format
copy must be within zero, one or two bit errors of its word, and the weaker
copy exactly three errors from a different word. Ties and all other conflicts
are ineligible. Use the stronger copy's error-correction level and mask only
as a refinement hypothesis; this does not admit a decoded result.

Keep one slot across the original and inverse-luminance collection order.
Retain the first two-versus-three candidate until the first zero/one-versus-three
candidate replaces it. Once a zero/one candidate is retained, never replace it.
Only projective maps qualify. Store its luminance basis and candidate metadata;
do not retain a sampling closure or add it to an earlier refinement queue.
Normal, non-conflicting curvature collection continues unchanged. Reduced
images, version retries and overflow recovery do not collect this slot.

Only after every earlier return path, including step 15, fails, attempt this
single retained candidate in its own luminance basis. Use the strict second
look and deferred alignment pass, then the strict direct mesh read from step 14
if needed. Both final format copies must agree with the selected level and mask
within two errors; ordinary version, Reed-Solomon and segment validation remain
mandatory. Resolve location and public polarity as for earlier full-size reads.
No second candidate is attempted when this one fails.

The conflicting header evidence excludes the same map, orientation, level and
mask from the earlier two-copy admission and non-conflicting curvature queues.
Its new retry therefore does not repeat an earlier identical full-size attempt.
Earlier successful results and all their metadata retain priority. This raises
the total maximum from five to six second looks, with the original four and
step 15 retaining their existing scheduling.

### 17. Give one ordinary-refined map the late alignment pass

An ordinary second look does not include step 13's late frozen-anchor search.
Remember the refinement phase of each earlier second look, including steps 15
and 16, in at most six attempted-candidate records. Append terminal records only
after their existing selection, so the earlier scheduling is unchanged.

After every earlier return path, including step 16, fails, inspect the retained
step 13 curvature queues: original luminance first, then inverse luminance,
each in its existing order. Select the first projective map with an ordinary
full-size attempt and no late full-size attempt. Match matrix coefficients,
size, orientation, polarity, error-correction level, mask and luminance basis
exactly, as in step 15. A reduced attempt does not count as a full-size attempt.
These maps already passed the existing exact-version and non-conflicting-header
admission; do not collect new candidates or search for new maps.

Try only that candidate with the strict second look and late alignment pass.
If the final refined read fails, validate its direct mesh as in step 14. Both
format copies must agree with the selected level and mask within two errors;
ordinary version, Reed-Solomon and segment checks remain mandatory. Return
after this one attempt even when it fails. Resolve full-size location and
public inverted polarity as for earlier reads.

All earlier successful results and metadata retain priority. This raises the
maximum to seven second looks; the original four and steps 15 and 16 keep their
existing scheduling. Remembering an attempt does not retain a new image plane
or sampling closure.

### 18. Refine one map with conflicting version evidence

During the existing full-size map collection, inspect an orientation only after
its ordinary curvature admission has rejected it. Before any version-peer map
has been retained, require a projective map of a valid version 7–40 size with:

- one version copy exactly equal to the codeword for the sampled size;
- its other copy independently BCH-decoding to a different version at exactly
  three bit errors;
- both format copies independently BCH-decoding within three errors to the same
  error-correction level and mask.

Retain the first qualifying map in actual collection order, across the original
and inverse-luminance bases. Keep its orientation, polarity, level, mask, minimum
format distance and luminance basis. Do not replace it, grow a queue or search
for another map. Existing curvature and format-conflict collection, ranking and
all earlier successful return paths remain unchanged.

After all earlier recovery paths, including step 17, fail, attempt this map
only if it has no matching full-size late attempt. Match matrix coefficients,
size, orientation, polarity, level, mask and luminance basis exactly. Ordinary
attempts do not exclude it. Record step 17's actual late attempt after its
selection, extending the attempt ledger to seven records.

Use the strict second look with late frozen-anchor alignment. If that read
fails, validate its direct mesh as in step 14. Both final format copies must
agree with the selected level and mask within two errors. Ordinary version,
Reed–Solomon and segment checks remain unchanged; there is no new requirement
that both final version words be exact. Return after this one attempt, even on
failure, with the same full-size location and public-polarity handling as the
other terminal recoveries.

One retained slot suffices for this policy: all earlier late candidates come
from gates which reject a decoded version copy contradicting the sampled size.
The same matrix, orientation, polarity and full-size luminance basis sample the
same header. Thus the retained class cannot later match an earlier late attempt;
the final identity check remains defensive. An ordinary attempt may match and
is intentionally allowed. This proof must be revisited if those gates change.

### 19. Read an alternate hypothesis from an existing grid

During a full-size late refinement, after its final grid fails to read, consider
the existing curvature queue for the same luminance basis, in queue order.
Require the same size, finite homography coefficients and polarity, but a
different combination of mirrored orientation, error-correction level and mask.
Exclude an alternate that already received a matching full-size late attempt.
Keep the first eligible alternate only, together with that failed final grid
and its direct mesh grid if the existing call already captures one. Introduce
no image sampling or mesh capture. The queues and attempt history do not change
during refinement; selecting the eligible alternative before refinement is
equivalent provided it is retained only after the final read fails.

Every earlier successful return keeps priority. Invalidate the saved alternate
if it subsequently receives a matching full-size late attempt, including the
eighth attempt in step 18. Match geometry, luminance basis, polarity, orientation,
level and mask. An invalidated slot is never replaced by another alternative.

After all earlier paths fail, validate the saved final grid under the alternate
orientation. Require both format copies to agree within the existing strict
radius, and ordinary version, Reed–Solomon and segment validation with matching
level and mask. If it fails, apply the same checks once to the saved mesh grid,
when present. Try no further candidate. Return the alternate's full-size
location and public inverted polarity as for earlier reads.

This adds at most two strict symbol validations, including possible
Reed–Solomon work, outside the existing `Work` counters. It adds no finder,
map, alignment probe, image sample or secondary attempt. Retention may occur
before an earlier path eventually succeeds; only these extra symbol reads wait
until every earlier path fails.

### 20. Rediscover a header on an existing refined grid

During each existing full-size late refinement, inspect its failed final grid
until one eligible hypothesis has been retained. Only versions 7–40 qualify.
Read the grid first in the refinement's original mirrored orientation, then
in the opposite orientation. In each orientation require both format copies
to agree with the same format word within two bits each. Keep the first
combination of orientation, error-correction level and mask that differs from
the refinement's original hypothesis. Retain that grid, location, polarity and
luminance basis. Do not replace, invalidate or backfill the slot, even if a
later refinement uses the same hypothesis or the eventual symbol read fails.

If that same refinement invocation already has a mesh collector and delivers
its existing direct mesh after selecting the slot, retain that mesh too. Forward
the original collector in its original order. Never introduce a collector or
sample a mesh for this purpose. A slot present before an invocation starts must
not receive that invocation's mesh; absent delivery does not permit backfilling
from another call. The retained mesh uses the selected final grid's hypothesis,
location, polarity and luminance basis, without rediscovering a header on it.

After every earlier path, including step 19, fails, validate the retained final
grid once. Only if that read fails, validate its retained same-call mesh once,
if available. Each read requires strict format agreement and ordinary version,
Reed–Solomon and segment validation with the selected error-correction level
and mask. Return the full-size location and public inverted polarity as for
earlier reads. The existing version validation applies unchanged; this step
adds no new version-header acceptance rule.

This adds at most sixteen orientation-specific header checks across the eight
existing late attempts and two strict symbol validations outside the `Work`
counters. It introduces no image sampling, mesh capture, alignment search,
map or second look. Earlier successes, including the retained final-grid read,
retain priority. They may have paid the bounded header checks and retention
before succeeding.

### 21. Read a quadratic surface from a fully measured sparse lattice

During an existing full-size late second look, retain the first mesh whose
alignment lattice has three rows and three columns and whose six non-finder
nodes were all measured successfully. These are versions 7–13. Retain the
original location, candidate orientation, polarity and luminance basis, plus
copies of its nine horizontal and nine vertical offsets immediately after
alignment searches finish and before the existing bilinear corner fit. The
three finder-corner entries are synthetic, not alignment measurements. No
new search or sampling occurs during retention. Never replace or backfill
this descriptor, including when its eventual fit or read fails.

After all earlier paths, including both step-20 reads, fail, form one tensor
quadratic interpolant from these offsets. For lattice coordinates c[0..2],
the one-dimensional weight of node i at z is the product over j != i of
(z-c[j])/(c[i]-c[j]); the weight of node (i,j) is the horizontal weight times
the vertical weight. Preserve all six measured offsets exactly. Jointly solve
the three synthetic corner offsets (indices 0, 2 and 6, row-major) so the
interpolated offset is zero at the actual finder centres (3,3), (size-4,3)
and (3,size-4), separately for each offset component. These are module indices;
the original projective map still applies its half-module centre convention.

Use three-by-three Gaussian elimination, choosing the greatest absolute pivot
in the remaining rows, retaining the earlier row on ties. Normalise each pivot
row across all four augmented columns, then eliminate that column from every
other row in order. A zero or non-finite pivot, or a non-finite fitted
corner, ends this recovery. Expected data never selects a descriptor or enters
the fit. The six measured nodes remain fixed throughout.

Recompute thresholds for the retained original or inverse-luminance image.
At each legal module centre, interpolate the two offsets, add them to its
module indices and project through the retained original map. Sample once
using the existing bilinear greyscale probe and candidate polarity. This is
one new grid; do not apply a timing walk or edge refinement to it.

Inspect this grid in the original candidate orientation, then the opposite
orientation. Select the first orientation whose two format copies agree with
one format word within two bits each, using the existing level/mask order.
The selected tuple may equal or differ from the earlier candidate. Perform
one ordinary symbol read only after this strict selection; require its level
and mask to match. Version, Reed–Solomon, zero-data and segment validation
remain unchanged. A failed symbol read ends the recovery without trying the
other orientation or a later descriptor. Return the retained full-size location
and the selected orientation and public polarity.

Earlier successes retain priority and their complete results, although they
may have paid for one offset snapshot. The terminal image sampling and symbol
read are separate from the eight legacy second-look attempts and are not
counted by their existing Work fields. Equal counters do not imply equal CPU
work, latency or allocation.

### Bounded work

The search's work grows about in step with the picture's pixels, whatever
the picture shows, under these caps. The first two cannot lose a read
that the uncapped search would make; the counts in the others are limits,
and a picture with more finder-like shapes than they allow may hide a code
among them.

- Finder candidates are filed by 16-pixel cell, so merging a sighting
  compares it only with candidates stored in the cells within a module of
  it. The earliest such match takes the sighting, as with a full scan.
- A cross-check stops once the dark centre run is longer than any that
  could pass: twice the row's whole pattern back along the row or down the
  column, and 32 times one more than the run limit on the diagonal.
- The 12 finders seen most often form triples, and the best 6 triples are
  located, in each of four passes (strict and looser tolerance, on the
  picture and on its inverse).
- Each triple is tried at 5 sizes, each giving at most 4 alignment maps and
  2 corner maps: at most 720 maps for the whole search, each sampling at
  most size x size modules, straight and transposed. The reduced sizes of
  step 9 take theirs from the same 720, at most 30 each; step 10 takes at most
  30 more from what remains, shared by its sizes. Step 11 takes at most
  30 remaining maps across all saved version hints. Step 12 shares a further
  allowance of 30 remaining maps between header probes and full reads of
  admitted overflow triples. Only sizes from 21 to
  177 give maps. An estimate of 181 or 185, past 177 by no more than the
  retries reach, still has its retries tried, and those of 177 or less
  give maps; any other estimate outside 21 to 177 gives none.
- Each size searches for the alignment pattern in square windows reaching
  4, 8 and then 16 modules around at most two estimates, clipped to the
  picture, stopping after the first reach that finds a near-perfect match.
- The original second-look allowance reads at most 4 maps again, at every size together,
  each sampled three times
  (timing, edges, final) plus one sixteenth-step search per timing module
  and per boundary between unlike modules.
- The ordinary mesh probes at most 46 lattice points a second look (version
  40 has 49, three of them at the finders), each at 25 x 25 offsets of 25
  modules. Step 13 may search predicted nodes once more, for a conservative
  bound of 92 pattern searches per second look and 5,750,000 points across
  the original four attempts,
  each interpolating four pixels, whatever the picture's size. Frames using
  only ordinary meshes retain the 2,875,000-point bound.
- Boundary continuation adds one trusted flag per lattice node (at most 49)
  and three four-node corner fits. It adds no image probes, map searches,
  alignment searches or refinement passes.
- Step 14 retains at most four grids, one per existing second look: at most
  125,316 module bytes plus their metadata. Capturing them adds at most 125,316
  grey probes per frame, each interpolating four pixels, after failed refined
  reads. Final failure adds at most four format checks and symbol reads. These
  probes are separate from the alignment-search `probed` counter; no map,
  alignment search or second look is added. A later successful existing path
  may still have paid for earlier grid captures, but never for deferred reads.
- Step 15 adds at most one terminal second look, for a total of five. With at
  most two searches at each of 46 alignment points, 25 by 25 offsets and 25
  module probes per offset, the conservative total alignment-probe bound is
  7,187,500. This also adds one ordinary mesh/timing/edge refinement, using the
  same per-attempt limits as earlier second looks; no finder or map search is
  added. Its optional direct mesh capture adds at most 31,329 grey probes,
  each interpolating four pixels, and one strict grid read. These grey probes
  are not included in `Work.probed`.
- Step 16 adds one further terminal attempt, raising the maximum to six and
  the conservative alignment-search bound to 8,625,000 probes. It adds no finder
  or map search. Its mesh/timing/edge refinement uses the same per-attempt
  limits; optional direct capture adds at most 31,329 grey probes and one strict
  grid read. The six optional captures together add at most 187,974 grey probes,
  separate from `Work.probed`.
- Step 17 adds at most one further terminal attempt, raising the maximum to
  seven and the conservative alignment-search bound to 10,062,500 probes.
  It adds no finder or map search. Its optional direct mesh capture adds at most
  31,329 grey probes and one strict grid read; all seven optional captures add
  at most 219,303 grey probes, separate from `Work.probed`.
- Step 18 adds at most one terminal attempt, raising the maximum to eight and
  the conservative alignment-search bound to 11,500,000 probes. It adds no finder
  or map search. Its optional direct mesh capture adds at most 31,329 grey probes
  and one strict grid read; all eight captures add at most 250,632 grey probes,
  separate from `Work.probed`.
- Step 19 leaves the eight-attempt and 11,500,000-alignment-probe limits
  unchanged. Its saved final/mesh pair occupies at most 62,658 module bytes.
  Conservatively, step 14's four retained grids, this pair and one subsequent
  step 15–18 temporary grid retain at most 219,303 module bytes together.
  Ports may copy the selected existing mesh for ownership without resampling;
  this bound includes that copy. Bounded metadata includes seven grid records,
  seven attempted-candidate records with phase flags, one format-conflict
  candidate, one version-peer candidate and one alternate candidate with its
  invalidation flag. This excludes active refinement buffers and allocator or
  garbage-collector capacity. Earlier successful paths avoid later terminal
  attempts, but may pay bounded header-classification, candidate retention and
  attempt-recording costs before they succeed.
- Step 20 retains at most one additional final/mesh pair of 62,658 module bytes,
  bringing the conservative combined retained-grid bound to 281,961 module
  bytes plus metadata. Ports may share ownership with earlier retained grids
  when they refer to the same arrays. The one candidate record and its two grid
  references do not change the eight-attempt, 720-map or
  11,500,000-alignment-probe limits. This bound excludes active refinement
  buffers and allocator or garbage-collector capacity.

- Step 21 retains 18 double-precision offsets (144 logical bytes) and bounded
  candidate/location metadata, without retaining another grid during earlier
  paths. It adds one terminal threshold computation, at most 69 x 69 = 4,761
  bilinear greyscale probes, two orientation-specific header inspections and
  one symbol read. These are outside the legacy Work counters. The terminal
  active grid uses at most 4,761 module bytes, with fit/weight temporaries and
  the existing threshold block buffers; none is a peak-heap bound. The legacy
  eight second looks, 720 maps and 11,500,000 alignment probes are unchanged,
  with this one separately bounded terminal sampling pass in addition.

When the global or current per-look map allowance is exhausted, that search
stops before further finder, triple or location work. A successful final map
still returns first, and the existing queue remains available for second looks.
Ordinary reduced sizes reset their allowance as specified above; the inverted
luminance fallback keeps its shared allowance. Search steps, candidate
comparisons and alignment-window areas are counted only for searches actually
performed; maps and second-look work keep their existing accounting.

The caps on maps and the original second looks are the same with steps 9 to 14
as without them,
but a frame where nothing reads at full size goes on to be shrunk,
binarised and searched at up to three reduced sizes (at most a third more
pixels in all), so such a frame costs more than it did. A frame qualifying
for step 10 may additionally search its inverse luminance and up to three
reductions; the uniform/near-uniform and no-flat-block gates avoid that work
when the polarity-sensitive flat-block rule cannot help.
Step 11 only rebuilds the original binary picture when a retained version
hint and remaining map allowance exist; its additional location work is
counted like ordinary location work, and its maps are full-resolution maps.
Step 12 rebuilds the binary picture only when a retained overflow list and
remaining map allowance exist. It retains references to existing ranked data
until the frame completes and adds corner geometry work for unselected triples;
it does not repeat finder scans. Alignment work is counted only after agreeing
headers admit a full location.
Step 13 stores at most four map references and header results per luminance
basis: eight across the original and inverse lists, still sharing four second
looks. The existing inverse luminance can remain live through later recovery,
retaining up to width x height bytes for longer. It recomputes thresholds only
when an admitted map and a second look remain; it needs no new binary image or
finder scan. The extra alignment sweep is bounded as above. Header checks
during original failed reads and full-size inverse-luminance fallback reads
add a fixed number of module samples per map; the existing Work counters do
not measure these samples.

All three ports count this work for their tests (pixels stepped in
cross-checks, stored candidates compared, pixels in alignment windows,
maps sampled, maps read again by the second look, those read through a
mesh, points the mesh probed, maps sampled at reduced size) without exposing the
counter: a picture of finder patterns on a 10-pixel pitch, or of 1:1:3:1:1
stripes, costs under 1.5 counted steps a pixel at 800x800 and at
1600x1600, and noise stays within the map cap, the second look's and the
mesh's.

### Version information

Below version 7 the size alone gives the version. From version 7 the two
18-bit version blocks are read and decoded to the nearest version code
within three bit errors, trying both copies and taking the closer (on a
tie the bottom-left copy, tried first, wins). When a
copy decodes, its version is the symbol's, and it must agree with the size
(`17 + 4 * version`); a disagreement makes that sampled grid unreadable,
never an in-place resize. Step 11 may separately locate a new picture map
from stronger, agreeing two-copy evidence. When neither copy decodes, the
version is the one the size implies.
Reed-Solomon, format information and the data's own structure still have to
pass, so a grid of the wrong size does not yield text this way.

### Structured append and FNC1

A structured-append header (mode 0011: a 4-bit index counting from 0, a
4-bit total less one, an 8-bit parity) is reported as `structuredAppend`
with `index`, `total` (1 to 16) and `parity`. The decoder reads one symbol
alone: `text` and `bytes` hold that symbol's part only, and joining parts is
the caller's job. Only the first header in a symbol counts. Index and total
are reported as read, even when the index is not below the total.

FNC1 in first position (mode 0101, the GS1 format) is reported as `fnc1`
with `position` `first`. FNC1 in second position (mode 1001) is followed by
an 8-bit application indicator, reported as `applicationIndicator`, a
string: 0 to 99 are two digits (`05`, `37`), 165 to 190 and 197 to 222 are
the letter whose ASCII code is the value less 100. Any other value makes
the symbol unreadable. Only the first FNC1 indicator counts.

From the indicator onwards, an alphanumeric segment is rewritten before it
joins the payload: within the segment, `%%` becomes `%` and a lone `%`
becomes the group separator U+001D. The segment is rewritten alone, so a
`%` ending one segment and a `%` starting the next are two separators.
Numeric and byte segments are untouched, and so is everything before the
indicator. `bytes` holds the rewritten data, so it always equals `text`
encoded as UTF-8 for alphanumeric and numeric data. A reference decoder
does the same for first position; it does not read the second-position
application indicator at all, so there is none to compare against.

Both fields are absent, not null, for an ordinary symbol.

### Text for kanji and other ECIs

`bytes` never depends on a character set: it holds the symbol's data bytes
(kanji as Shift_JIS pairs, hanzi as GB2312 pairs, see step 7). Only `text` does, and `text` is
produced with the platform's own decoders (`TextDecoder` in JavaScript,
`java.nio.charset.Charset` on the JVM). No port bundles tables, apart from
the 32 bytes of Windows 1252 below.

Every port must agree on these:

- ECI 26 is UTF-8, decoded by hand with each ill-formed byte as U+FFFD. ECI 1
  and 3 are Latin-1, byte for byte.
- ECI 27 and 170 are ASCII: a byte below 0x80 is that character, any other
  byte is U+FFFD.
- A kanji-mode character is its Shift_JIS pair decoded alone; if the platform
  returns U+FFFD for the pair, or has no Shift_JIS, the character is a single
  U+FFFD. The ECI in force before a kanji character stays in force after it.
- Hanzi mode (1101, GB/T 18284) must carry subset indicator 0001, GB2312;
  any other subset makes the symbol unreadable. The character count has the
  kanji count's length, and each 13-bit value `v` is the pair: lead byte
  `v / 0x60` plus 0xA1 below 0x0A, else plus 0xA6, and low byte `v % 0x60`
  plus 0xA1. A lead byte outside A1-A9 and B0-F7, or a low byte above FE,
  makes the symbol unreadable. The pair is decoded alone as GB 18030; a
  pair that decodes to U+FFFD or to a private-use character makes the
  symbol unreadable too, and so do the twelve cells A6D9-A6DF, A6EC, A6ED,
  A6F3, A8BC and A8BF, which tables of different editions read
  differently. The other empty GB2312 cells that GBK fills (small Roman
  numerals, the euro sign, vertical forms, some pinyin) read as GB 18030
  gives them; 7479 of the 8192 values read. The JVM falls back to GBK,
  which agrees on every value read; a platform with neither gives U+FFFD
  for each character, as for kanji. The ECI in force
  stays in force after a hanzi character.
- ECI 4 to 18 except 14 (ISO 8859-2 to -16 less -12, which does not exist;
  so ECI 13 is ISO 8859-11, 15 is -13, 16 is -14, 17 is -15, 18 is -16),
  with bytes 0x80 to 0x9F always the C1 control of the same value, and in
  ECI 13 the bytes the set leaves undefined (DB to DE and FC to FF) as
  U+FFFD. ECI 21 and 22 (Windows 1250 and 1251) with the bytes the code page
  leaves undefined (1250: 81 83 88 90 98; 1251: 98) as U+FFFD.
- ECI 23 is Windows 1252, read by hand, since platforms have differed on it:
  a byte outside 0x80 to 0x9F is the Latin-1 character of the same value,
  and bytes 80 to 9F are U+20AC, undefined, 201A, 0192, 201E, 2026, 2020,
  2021, 02C6, 2030, 0160, 2039, 0152, undefined, 017D, undefined, undefined,
  2018, 2019, 201C, 201D, 2022, 2013, 2014, 02DC, 2122, 0161, 203A, 0153,
  undefined, 017E, 0178, with each undefined byte as U+FFFD.
- ECI 20 is Shift_JIS, 24 Windows 1256, 25 UTF-16BE, 28 Big5, 29, 31 and 32
  GB 18030 (a superset of GB 2312 and GBK), 30 EUC-KR, 33 UTF-16LE. Ill-formed
  input becomes U+FFFD, and a leading byte order mark is kept.
- An ECI with no entry above, and any ECI whose character set the platform
  lacks, is never guessed at: the symbol has said what its bytes are, and
  reading them as something else would be a wrong text. Under one of the
  single-byte sets (ECI 4 to 13, 15 to 18, 21, 22 and 24), which are all
  ASCII below 0x80, those bytes are their ASCII characters and every other
  byte is U+FFFD. Under any other ECI every byte is U+FFFD. `bytes` and
  `eci` still hold what the symbol carries, for a caller that can read it.
- What is left to the platform is which of the sets above it has, and
  their exact mapping tables; a platform's tables may differ from another's
  for rare code points. The JVM lacks ISO 8859-10 and -14 on a standard
  JDK, for instance, Node 22 lacks ISO 8859-16, and the Rust port has none
  but the ones read by hand.

`test/charsets.json` records the JavaScript platform's text for every
13-bit kanji value and every 13-bit hanzi value (U+0000 where it makes the
symbol unreadable), every byte of each single-byte set and a few multi-byte
and UTF-16 samples. The Kotlin tests read the same file; with
`windows-31j` for Shift_JIS, `x-windows-950`, `GB18030`, `x-windows-949` and
`x-iso-8859-11` they agree on all of it, apart from the two sets the JDK lacks.

### Shift_JIS without an ECI

Many codes carry Shift_JIS in byte mode with no ECI. For a byte run with no
ECI in force (each run between kanji characters or ECI designators is judged
alone) that is not valid UTF-8, a port decides between Shift_JIS and Latin-1
by this rule, which uses byte shapes only.

Scan left to right. A byte below 0x80 ends any run of katakana or of
double-byte characters. A byte from 0xA1 to 0xDF is a half-width katakana and
extends the katakana run. A byte from 0x81 to 0x9F or 0xE0 to 0xEF is a lead:
it must be followed by a trail from 0x40 to 0x7E or 0x80 to 0xFC, and the two
together are one double-byte character that extends the double-byte run (and
ends a katakana run). Any other byte of 0x80 or more (0x80, 0xA0, 0xF0 to
0xFF), a lead at the end of the run and a lead with any other trail rule
Shift_JIS out at once. If nothing rules it out, the run is Shift_JIS when it
has three katakana in a row, or three double-byte characters in a row, or any
double-byte character whose lead is 0x81 to 0x9F (those are control
characters in Latin-1, so they do not occur in Latin-1 text). Otherwise it is
Latin-1.

When the run passes, its text is the platform's Shift_JIS reading of the whole
run; if the platform lacks Shift_JIS, or the reading holds U+FFFD, the text is
Latin-1 as before. `bytes` is unchanged.

Judged ambiguous and read as Latin-1: one or two katakana-range bytes alone
(a lone `A5` is a yen sign, and `B1 B2` is two Latin-1 symbols), and a short
double-byte run led by 0xE0 to 0xEF. Judged ambiguous and read as Shift_JIS:
three high symbols or capitals in a row from 0xA1 to 0xDF, such as `C0 C9 C8`.

## Decode fixtures

`vectors/decode-frames/` holds 48 synthetic frames as 8-bit greyscale PNG,
and `vectors/decode-frames.json` gives each one's exact text, the drawing
parameters, and whether this decoder and an independent decoder read it
when the frames were made. The last 12 are at steep perspective, the far
edge 50 to 70% of the near one, with the narrowed edge on each side of the
symbol in turn (`turn`, quarter turns of the grid). A port must read every
frame marked `"typescript": true`. The frames are drawn by
`test/fixtures.test.ts` (`QR_WRITE_FIXTURES=1` regenerates them); every
payload in them is made up.

A second, separate set holds real photographs of QR codes with known contents,
taken from open-source test collections that were assembled for other
decoders; `vectors/photos.json` lists the sources, pinned commits and licences.
The images are not committed. `npm run fetch-photos` downloads them into
`vectors/photos-cache/`, checks each against its SHA-256, and converts them to
8-bit greyscale PNG so every port reads the same pixels; the tests skip when
that cache is absent. Expected text is compared exactly as stored, with no
trimming and no newline normalisation, and a photograph counts as read only
when the text is identical. Reading a photograph as the wrong text fails the
test; the number of photographs read may not fall below the recorded floor
(`ratchet.typescript`). Other decoders are tuned on these collections, so the
set supports no comparative claim. It is a regression bar and a first check
against real optics, nothing more.

No false reads: `test/false-reads.test.ts` and `FalseReadsTest.kt` build
the same 240 damaged symbols from one seeded generator: 160 with one block
damaged a few codewords past its parity (finders, timing and format left
whole, so the second look runs on them), 40 with a rectangle of the data
region turned over, and 40 with modules flipped anywhere. They span
versions 1 to 12 and all four levels, a third of them version 1. Each is drawn
straight with noise, some mirrored or inverted. Every one must read as
nothing or as its own text, and every one damaged past its parity as
nothing. Frames with no symbol (noise, flat, stripes, a checkerboard and a
lattice of finder patterns) must read as nothing. A further 30, from a
seed of their own, are of versions 7 to 40, one block a few codewords past
its parity, drawn bent by a lens (`bent` in `test/photo.ts`); each must read
as nothing, and the second look must have read nearly all of them through a
mesh. Another 10, also from a seed of their own, are of version 40, damaged
the same way and drawn bent so that nearly every one's size estimate runs
past 177; each must read as nothing, and most must reach the mesh through
the retries below the estimate. `test/symbol.test.ts` and `SymbolTest.kt`
hold a block to the capacity Table 9 gives it: at versions 1 to 3 and three
larger symbols, that many errors in every block read and one more reads as
nothing. `test/zero.test.ts` and `ZeroTest.kt` build
symbols of nothing but zero codewords, under all eight masks, at versions
1, 2, 5 and 7, undamaged and with every block damaged up to what it can
correct; each must read as nothing as modules and in a picture, straight
and mirrored, dark on light and light on dark, while an empty payload and
payloads of zero bytes that leave whole blocks zero must read back.

The reduced-size pass has dedicated TypeScript and Kotlin tests, from seeds of
their own. 200 symbols of versions 1 to 4, one block one to three
codewords past what Table 9 lets it correct, and 100 with 4 to 16% of modules flipped anywhere, drawn at
16, 24 or 32 pixels a module with noise, some mirrored or inverted: each
must read as nothing or its own text, every one damaged past that as
nothing, and on every one of those the counter must show maps sampled
at reduced size; on nearly all, maps were left and every factor's picture
held a finder triple, so each factor was searched. Symbols of nothing but
zero codewords, at versions 1, 2 and 5, all eight masks, 16 and 24 pixels
a module, must read as nothing with the pass reached. Larger frames with
no symbol (noise, coarse noise, finder patterns at 8 and 16 pixels a
module, text-like glyphs, a checkerboard) must read as nothing. A close-up
with a dark scan line every third row across 24-pixel modules reads only
through the pass, at the finder centres in full-picture coordinates, and
in the polarity the `inversion` option allows; the shrink's rounding and
dropped remainder are checked on small pictures.
