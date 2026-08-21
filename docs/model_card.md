# Model Card — GraphCodeBERT Verifier (Layer 3)

## Supported language scope

The model (Layer 3) only supports **C, C++, Java** (`SUPPORTED_ML_LANGUAGES` in
`verifier/__init__.py`). Layer 2 (Tree-sitter rules) additionally supports
**Python** (`rules/python/python_sinks.scm`) — Python candidate sinks are
still scanned by Layer 1+2 and appear in the SARIF output
(`ml_verified=false`, `severity="warning"`, with an explanatory
`properties.note`), but are NOT filtered for false positives by Layer 3, so
confidence is much lower than a C/C++/Java finding that went through the
model. The CLI also prints a summary warning line whenever a scan has
candidates in this group (see `pipeline.build_ml_unsupported_warning`).

## Training data

## Performance (accuracy, precision, recall, F1)

### Independent evaluation on the SVEN dataset — 2026-08-19

**Data source:** [SVEN dataset on HuggingFace](https://huggingface.co/datasets/bstee615/sven)
(repo_id `bstee615/sven`, 803 before/after pairs, manually verified by
humans). **This is NOT the original test set used at training time**
(the original test.csv stored on Google Drive is no longer accessible and
cannot be recovered) — SVEN was chosen as a substitute because it is an
INDEPENDENT dataset that has NEVER been used at any step in this model's
training pipeline (no data leakage risk). Full, reproducible process via
`scripts/evaluate_sven.py`:

1. Download both splits (train 720 + val 83 = 803 rows) directly from HuggingFace Hub.
2. Filter to only keep rows whose `file_name` has a C/C++ extension (Python
   is outside the model's scope — see the "Supported language scope"
   section); excludes 381 rows outside C/C++ and 4 degenerate before/after
   pairs (empty or identical).
3. Build a binary test set: `func_src_before` → label=1 (vulnerable),
   `func_src_after` → label=0 (fixed) — 836 examples, already balanced 50/50
   per language thanks to the 1-to-1 pair structure (c: 362/362, cpp: 56/56).
4. Run `ONNXVerifier.predict_batch()` with the model + threshold **left
   as-is** at `weights/model.onnx` + `weights/threshold_config.json` — NO
   retraining, NO re-tuning/re-calibrating the threshold at this step.

**Results:**

| Language | n | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| C | 724 | 283 | 285 | 77 | 79 | 0.4972 | 0.4982 | 0.7818 | 0.6086 |
| C++ | 112 | 55 | 54 | 2 | 1 | 0.5089 | 0.5046 | 0.9821 | 0.6667 |
| **Combined C+C++** | **836** | **338** | **339** | **79** | **80** | **0.4988** | **0.4993** | **0.8086** | **0.6174** |

**Interpretation:** Recall is high (78-98%) — the model rarely misses a
real vulnerability. But precision is around 50% (close to random guessing)
on BOTH languages, especially C++ where the model almost always predicts
label=1 (TN is only 2/56, meaning almost every FIXED function is still
labeled "vulnerable"). This result **matches and quantifies at a much
larger scale** the issue already recorded in the "Systematic false
positives on safe buffer/format functions (C/C++)" section below
(previously only 9 hand-written samples + 13 samples from `sds` — here it's
836 examples from an independent, diverse, human-labeled source). The
conclusion is unchanged: the current model is very good at NOT missing
vulnerabilities (high recall), but its effectiveness at filtering false
positives (Layer 3's main goal in the cascade) is close to zero on C/C++
with the current threshold.

**Java:** no independent local evaluation dataset exists for this language
at this step — SVEN doesn't have enough clean Java data to break out
separately, and we are NOT fabricating numbers. A separate independent
Java dataset is needed for a future evaluation.

#### Reconciling the numbers

The internal figure measured at training time before (estimated ~89-91%
for C, after subtracting the effect of leakage) and the SVEN figure
measured above (~50%, close to random guessing) differ enormously — this
needs explaining, and it needs to be clear which number to trust.

**Reason for the gap:** the earlier "~89-91%" figure was **not measured
directly** on a clean test set — it was an **indirect inference**, based on
a simplifying assumption from the measured leakage rate
(duplicate/near-duplicate overlap between train and test) at the time, then
estimating backward roughly what performance "without leakage" would be.
This is an indirect estimate, not an actual measured result on data the
model had truly never seen in any form. By contrast, the SVEN figure above
is **directly measured evidence** — real inference, run on a completely
independent data source (never appearing at any step of the training
pipeline), manually labeled by humans.

**Conclusion:** THE SVEN NUMBERS (~50% precision) SHOULD BE CONSIDERED A
MORE TRUE REPRESENTATION of the model's ability to generalize to unseen
code, compared to the internal ~89-91% figure — the internal figure is at
risk of being inflated by near-duplication between train/test drawn from
the same source (same coding style, same project, sometimes the same
function differing by only a few lines), causing the model to "memorize"
rather than actually learn the safe/vulnerable boundary.

**Practical implication:** with ~50% precision on C/C++ in its current
state, **Layer 3 should NOT be used as the basis for automated decisions**
(e.g. automatically blocking a PR just because Layer 3 assigned label=1) —
doing so would incorrectly block roughly half of clean PRs. Layer 3 should
only be used in the role it was designed for in the 4-layer cascade: a
**signal to prioritize manual review** (helping a reviewer know which
finding to look at closely first), not an automated filter that can be trusted at its current threshold.

### Testing on real CVEs — 2026-08-18

The first time there is experimental evidence on a publicly disclosed
vulnerability (CVE), rather than only on hand-written samples. Process:
clone the real repo at the exact commit **before** the patch (verified via
the GitHub REST API, not just relying on a summary), run `vulneracheck
scan` on the file containing the bug, cross-check the code line against the
real fix commit.

| CVE | Project | CWE | File:line | Sink | Confidence | Result |
|---|---|---|---|---|---|---|
| CVE-2023-42801 | moonlight-stream/moonlight-common-c | CWE-120 | `src/Misc.c:88` | `strcpy` | **0.9347** | Correctly detected |
| CVE-2026-44713 | mcdope/pam_usb | CWE-78 | `src/tmux.c:59` | `popen` | **0.9389** | Correctly detected |

**Recall on the test set: 2/2 (100%).**

**This is a very small sample (n=2) — NOT enough to generalize into an
official recall figure for the model.** The real significance of this
result is: this is the **first experimental evidence** that the verifier is
capable of detecting real vulnerabilities in real production code (not just
hand-written fixtures), not a statistically reliable recall benchmark. A
much larger CVE set (dozens to hundreds of cases) would be needed before an
official recall figure could be published.

## Runtime performance (scan time) — 2026-08-18

Measured on CPU (no GPU), FP32 model ~476MB.

- **Fixed overhead per run**: ~15-20s (loading the ONNX session + tokenizer), independent of the number of files/candidates.
- **Marginal cost at Layer 3**: ~0.45s/candidate (measured linearly at
  N=10/30/60 candidates: 5.42s/13.48s/26.59s), **after the batch bug fix**
  (see below).
- **Before the bug fix**: `predict_batch()` merged ALL candidates from an
  entire scan into a single ONNX Runtime call, using `padding=True` (padded
  to the longest item in the batch). Because Layer 2 extracts the full
  function as the snippet (which can be very long — one real case measured
  17,305 characters), the larger the batch, the more likely it catches a
  long snippet, causing cost to grow **non-linearly**: N=200+ candidates
  did not complete after several minutes (tried a 3-5 minute timeout).
  Fixed by adding `MAX_BATCH_SIZE = 32` (`verifier/inference.py`) —
  fixed-size chunking instead of one giant batch. After the fix: 229
  candidates completed in 103s (matching the linear rate measured at small N).
- **Real measured end-to-end time** (full CLI, including overhead):

  | Scenario | Files | Candidates | Time |
  |---|---|---|---|
  | 1 file | 1 | 5-8 | 12-26s |
  | Small directory | 4 | 13 | 16.5s |
  | Medium directory (after the bug fix) | 34 | 229 | 1m58s |

**Implication for CI/CD**: suitable for running as a **scheduled job**
(e.g. a nightly full-repo scan). **NOT YET suitable as a gate blocking
every PR** if it rescans the entire repo each time on a large codebase —
several minutes per run is too slow for a PR check that needs a fast
response. The planned direction for the next step: **diff-based scanning**
(only scan the files/hunks changed in the PR instead of the whole repo)
rather than trying to further optimize Layer 3's raw speed.

## Known limitations and risks

### Systematic false positives on safe buffer/format functions (C/C++) — confirmed 2026-08-18

**Symptom:** The model assigns high confidence (>0.5, mostly >0.7, many
cases ~0.97) and `label=1` ("VULNERABLE") to calls to
`strncpy`/`snprintf`/`memcpy`/`printf`-family that were used **correctly,
with a clear size bound**, well outside the `uncertain_zone` of both `c`
(`[0.52, 0.68]`) and `cpp` (`[0.02, 0.18]`) — meaning the model isn't
"unsure", it's confidently wrong.

**Investigation:** The initial suspicion was that the 2 original samples
(`bounded_copy.c`/`.cpp`) were hand-written too minimally (just 1 short
`main`/`copy_input` function), very different from the real coding style
taken from GitHub commits in the training data. To distinguish "a
systematic issue" from "noise from 2 specific samples", 5 more diverse safe
samples were added — longer, with standard includes, natural variable
names, real surrounding logic (parsing config, validating a return value,
error handling) — plus 1 idiomatic C++ sample that uses no raw buffers at
all (`std::vector`/`std::string`, with the bound taken from a real `.size()`):

| File | Sink | Usage | Confidence | Label |
|---|---|---|---|---|
| `safe/c/bounded_strncpy_realistic.c` | `strncpy` ×2 | Bounded by the real destination buffer, with parsing/validation around it | 0.967 | 1 (VULNERABLE) |
| `safe/c/bounded_strncpy_realistic.c` | `printf` | Prints an already-parsed value, unrelated to the buffer | 0.771 | 1 (VULNERABLE) |
| `safe/c/validated_snprintf.c` | `snprintf` | Checks the return value to detect truncation | 0.778 | 1 (VULNERABLE) |
| `safe/c/validated_snprintf.c` | `fprintf` | Writes a log to stderr, no un-validated input | 0.694 | 1 (VULNERABLE) |
| `safe/cpp/bounded_strncpy_realistic.cpp` | `strncpy` ×2 | Similar to the C version | 0.969 | 1 (VULNERABLE) |
| `safe/cpp/validated_snprintf.cpp` | `snprintf` | Similar to the C version | 0.852 | 1 (VULNERABLE) |
| `safe/cpp/idiomatic_string_buffer.cpp` | `memcpy` | **No raw buffer at all** — copies into a `std::vector<char>` already `resize()`d exactly to `payload.size()`, with the bound taken from the actual source/destination size | 0.870 | 1 (VULNERABLE) |

**Result: 9/9 (100%) of the new candidates were flagged with high
confidence, label=1**, including the idiomatic C++ case with no bug pattern
to compare against at all (just 1 `memcpy` call whose bound is 100% correct
relative to the real container size).

**Further reinforced with evidence from real production code — 2026-08-18:**
scanned the [`antirez/sds`](https://github.com/antirez/sds) library (Simple
Dynamic Strings — the string library used in Redis, authored by Salvatore
Sanfilippo, no CVE history, 15+ years of real-world use). Result: **13/13
(100%) findings** (`memcpy`, `memset`, `memmove`, `printf`, confidence
0.96–0.99) — after manually reading each real line of code, **all 13/13
were false positives**: every call is preceded by an allocation/
`sdsMakeRoomFor()` step that guarantees sufficient size, or is a safe
literal format string. No exceptions. This is stronger evidence than the
9/9 hand-written samples above, since it was measured on real production
code, not a self-made fixture — completely ruling out "noise from how the
sample was written" as an explanation.

**Conclusion: this is a systematic issue with the model, not noise/an
artifact of 1-2 specific samples.** The model seems to have learned a
correlation between **the mere presence** of a C buffer/format family
function name (`strncpy`, `snprintf`, `memcpy`, `printf`-family) and the
"vulnerable" label, rather than learning the semantics of "is the bound
actually correct". The most likely hypothesis: skewed (imbalanced) training
data — not enough "negative" examples (these functions used correctly,
with clear validation/bounds) relative to "positive" examples (used
incorrectly, unbounded).

**Real-world impact:** With the current thresholds for C (`0.6`) and C++
(`0.1`), most C/C++ code using these functions — even when used correctly —
still gets `label=1` from the model. Since `LOW_CONFIDENCE_CWE_CATEGORIES`
was added at the reporting layer (`reporting/__init__.py`), findings in
this CWE group are forced to display as `level="warning"` instead of
`"error"` in SARIF — this is a **noise-level mitigation**, NOT a root-cause
fix: Layer 3 is still incorrectly assigning `label=1` to almost every call
in this group, only the consequence (displayed severity) is toned down,
while the number of incorrect findings stays the same. The cascade's real
value (filtering false positives from Layer 2) is close to zero for this
sink group on C/C++.

**What has NOT been done (deliberately, pending a decision)**: the model
was not modified, the threshold was not modified — only evidence gathering
and display-level mitigation at the reporting layer. Possible directions
for a future fix: (1) review/augment the training data with more
"used correctly" examples specifically for the C buffer/format group, (2)
re-calibrate the C/C++ threshold based on the real confidence distribution
on a more diverse test set (not just vulnerable samples) — real data from
`sds` is now available as a reference, (3) consider adding a feature/signal
beyond raw text (e.g. whether an explicit bound computation exists) if
(1)+(2) aren't enough.

### False-negative gap in Layer 2 (Tree-sitter rule) — discovered 2026-08-18, fixed 2026-08-18

**Note: this is a risk in the OPPOSITE direction from the false positive
issue above — missing a real bug, not reporting a fake one — do not conflate the two issues.**

While choosing a "clean" repo to test the false-positive rate, tried the
[`ludocode/mpack`](https://github.com/ludocode/mpack) library before
choosing `sds`. mpack's core files (`mpack-reader.c`, `mpack-writer.c`,
`mpack-node.c`) make real calls to `memcpy`/`malloc`/`realloc` (confirmed
via `grep`), but `vulneracheck scan` returned **0 candidates** for these files.

**Cause:** mpack defines its own wrappers around libc functions
(`mpack_memcpy`, `mpack_realloc`, ...) instead of calling
`memcpy`/`realloc` directly. Layer 2's `.scm` rule at the time only matched
identifier names **exactly** (`#match? @sink.name "^(memcpy|memmove|...)$"`)
— `mpack_memcpy` doesn't match this regex even though it's fundamentally
still a raw memory-copy call, carrying the same risk as a bare `memcpy`.

**Impact (before the fix):** Any codebase that defines its own wrapper for
a buffer/memory/format function (very common in large C codebases — often
to add logging, instrumentation, or a portability layer) would **slip
through Layer 2 entirely**, never forwarded to Layer 3, never appearing in
SARIF even though there's a real bug inside. This is a false negative at
the most absolute level — not "low confidence", but "never scanned at all".

**How it was fixed:** Changed the `#match?` predicate throughout
`rules/c/c_sinks.scm` and `rules/cpp/cpp_sinks.scm` (every CWE group, both
the qualified `std::` and unqualified versions) from the exact-match
`"^(...)$"` to `"(^|_)(...)($|_)"` — requiring the sink name to be a
**component separated by an underscore** in the called function's name,
without needing to match the whole name exactly. Catches `mpack_memcpy`,
`my_strcpy_wrapper`, `safe_malloc`, etc., while **not** matching a function
name that just happens to contain an adjacent substring (e.g. `mallocator`,
`freetype_init` — no underscore separator, so no match). There is a
regression test for both directions
(`test_parse_file_detects_wrapper_function_names`,
`test_parse_file_does_not_match_unrelated_function_names` in
`tests/unit/test_parsers.py`).

**Acceptable trade-off:** broader matching = more potential false positives
at Layer 2 (more candidates forwarded to Layer 3) — consistent with Layer
2's high-recall philosophy throughout the project (the `malloc`/`calloc`
rule already applied similarly broad matching logic before, albeit for a
different reason); Layer 3 (verifier) is where precision filtering happens, not Layer 2.

**Remaining limitation at the time (not solvable by name-based regex):** A
wrapper named in a way that **doesn't contain** the original sink name as a
component at all (e.g. `safeCopy` doesn't contain `strcpy`/`memcpy` in any
form) would still be missed — this is an inherent limitation of the
identifier-name-matching approach, only solvable through real alias/type
analysis (outside the scope of a simple Tree-sitter query at Layer 2). A
wrapper named in camelCase/PascalCase without underscores (e.g.
`mpackMemcpy`) was ALSO still missed AT THE TIME — fixed in the update below (2026-08-19).

### Extending wrapper matching to camelCase/PascalCase — fixed 2026-08-19

**Context:** The 2026-08-18 fix above (`"(^|_)(...)($|_)"`) only caught
wrappers separated by underscores (`mpack_memcpy`). A wrapper named in
camelCase/PascalCase — no underscores, "humps" separated by capitalizing
the first letter of each word (e.g. `mpackMemcpy`, `safeStrCpy`,
`MemcpyWrapper`) — still slipped through Layer 2 entirely, the same "never
scanned" kind of false negative as the gap fixed the day before, just a
different naming convention.

**How it was fixed:** Added a second `#match?` branch (joined by `|`) to
EVERY pattern in both `rules/c/c_sinks.scm` and `rules/cpp/cpp_sinks.scm`
(every CWE group, both the qualified `std::` and unqualified versions —
except `delete`/`delete[]`, since that's a keyword node, not a function
call by identifier name, so name-matching doesn't apply):
`"(^|[a-z0-9_])(?=[A-Z])(?i:...)($|[A-Z]|[^a-zA-Z0-9])"`. Meaning of each
part: the left boundary is start-of-string/lowercase letter/digit/`_`
(NOT an uppercase letter — avoids matching 2 adjacent uppercase letters
like an acronym, e.g. does not match `XStrcpy`); immediately after the left
boundary must be an uppercase letter (`(?=[A-Z])`, a lookahead that doesn't
consume a character — precisely meaning "the first letter is uppercase,
right after a word boundary"); matches the sink name case-insensitively via
the scoped group `(?i:...)` (so `StrCpy` — both "humps" capitalized —
still matches `strcpy`, not just the `Strcpy` form with only the first
letter capitalized); the right boundary is end-of-string/next uppercase
letter (a new hump)/a non-alphanumeric character. The sink token list is
unchanged, no need to write a separate capitalized version.

Tree-sitter's `#match?` regex engine supports lookahead and a scoped
case-insensitive group `(?i:...)` — verified experimentally using the
project's real `tree_sitter` binding (actual Python `Query`/`QueryCursor`,
not just documentation) before being written into the rule.

**Verification results:** Catches `mpackMemcpy`, `safeStrCpy`,
`MemcpyWrapper`, `wrapper_Strcpy` (mixed underscore + camelCase). Does NOT
falsely match `mallocator`, `freetype_init`, `somestrcpycall` (all
lowercase, no case-transition point for the camelCase branch to catch, no
`_` for the snake_case branch to catch), `myStructCpy` (doesn't contain a
contiguous `strcpy` substring — `Struct` ≠ `Str`+`cpy`), or `XStrcpy`
(preceded directly by an uppercase letter, not a valid word boundary).
Regression test in `tests/unit/test_parsers.py`
(`test_parse_file_detects_camelcase_wrapper_function_names`), and confirms
the total number of candidates scanned on `samples/` did not decrease
compared to before the fix (`tests/integration/test_pipeline.py`).

**Remaining limitation (not solvable by name-based regex):** A wrapper
named in a way that **doesn't contain** the original sink name as a
component at all, in any capitalization/separation form (e.g. `safeCopy`
doesn't contain `strcpy`/`memcpy` in any form) would still be missed — this
is an inherent limitation of the identifier-name-matching approach, only
solvable through real alias/type analysis (outside the scope of a simple
Tree-sitter query at Layer 2).

## Model update process
