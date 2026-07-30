# Chimera

Chimera is a proof of concept detection system for polymorphic and metamorphic malware. It does not use signature matching. It uses structural analysis, statistical behavior modeling, and controlled execution instead. 

## 1. Core Problem

Signature based antivirus checks a file's fingerprint against a database of known bad fingerprints. This fails against two specific classes of malware.

**Polymorphic malware** keeps its payload code identical across every copy, but re-encrypts that payload with a new key each time it spreads. The file's fingerprint changes, the actual malicious logic does not. Every copy still needs a small decryptor stub, a piece of unencrypted code that runs first and decrypts the real payload into memory before execution.

**Metamorphic malware** goes further. It rewrites its own instructions on every generation, using register renaming, block reordering, dead code insertion, and instruction substitution. There is no encryption and no decryptor stub. The bytes are different every time, but the control flow and functional behavior stay equivalent.

Chimera does not compare files against a database of known malware. That approach still only catches variants of things already seen. Instead, each module targets a property that a given malware class cannot remove without losing function.

## 2. High Level Architecture

Chimera runs two independent detection tracks in parallel, plus one shared confirmation stage.

```
                 ┌─────────────────────┐
                 │      main.py         │  ← orchestrator, no detection logic
                 └──────────┬───────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                        │
 ┌──────▼───────┐                         ┌──────▼────────┐
 │ polymorphic/  │                         │ metamorphic/   │
 │  track        │                         │  track         │
 └──────┬───────┘                         └──────┬────────┘
        │                                        │
        └───────────────────┬────────────────────┘
                            │
                 ┌──────────▼───────────┐
                 │ sandbox_isolation.py  │  ← runtime confirmation
                 └──────────────────────┘
                            │
                 ┌──────────▼───────────┐
                 │       shared/         │  ← logger, utils, model_storage
                 └──────────────────────┘
```

## 3. Polymorphic Track

Three independent checks, each targeting one property a polymorphic sample cannot avoid.

### 3.1 `entropy_scanner.py` — payload randomness

Encryption produces output that is statistically close to random. Ordinary code and text are not random; they have predictable byte distributions. Shannon entropy quantifies this on a scale of 0 to 8 for byte data.

The scanner splits a file into fixed size chunks (256 bytes by default) and computes entropy per chunk rather than for the whole file. A file with a large clean section and one small encrypted payload would average out to a misleadingly low score if measured whole. Per-chunk scanning catches the payload specifically, regardless of how much clean wrapper code surrounds it. A file is flagged as likely packed if the ratio of high-entropy chunks crosses a configured threshold (`ENTROPY_THRESHOLD`, default 7.2).

**Why this works against polymorphism specifically:** the encryption key changes every generation, but encrypted output is always high entropy regardless of the key used. This check does not care what the key was.

### 3.2 `api_sequence_model.py` — behavioral anomaly detection

This module scores the *order* in which a process calls system/API functions, not the file's bytes at all.

The raw sequence is converted into a fixed-length numeric vector using n-grams (pairs of consecutive calls by default), so it can be fed into a model:

That vector is scored with **Isolation Forest** (`sklearn.ensemble.IsolationForest`):

Isolation Forest is unsupervised — it is trained only on vectors from known-clean programs. It works by randomly partitioning the feature space; anomalous points get isolated in fewer splits than normal points, which is what the model uses as its anomaly score. No labeled malware is required at training time.

**Why this works against polymorphism specifically:** the file's on-disk signature is meaningless to this check. It only sees runtime behavior, which tends to stay consistent across encrypted variants of the same underlying malware family.

### 3.3 `decryptor_stub_scanner.py` — direct stub detection

Every polymorphic sample needs an unencrypted decryptor stub, and stubs are usually built from a small set of common patterns — most commonly a short loop containing an XOR instruction that both encrypts and decrypts the payload.

This uses Capstone to disassemble the file into real x86 instructions first, then scans a sliding window for the XOR-plus-backward-jump pattern. No machine learning involved — this is a fast, deterministic rule.

**Why this works against polymorphism specifically:** the stub logic itself is one of the only parts of a polymorphic sample that has to stay recognizable, because it must be decodable by the CPU without any decryption step of its own.

## 4. Metamorphic Track

Three checks, all built on the premise that rewritten code preserves structure and category-level behavior even when exact instructions change.

### 4.1 `opcode_graph.py` — control flow graph extraction

Uses `angr` to load a binary and build its control flow graph (CFG) — a graph where nodes are basic blocks of code and edges are possible jumps between them. Rebuilt as a `networkx.DiGraph` for further analysis:

Also provides `graph_similarity_score()` using `nx.graph_edit_distance` for cases where you do want to compare two graphs directly (e.g. two generations of the same known family).

**Why this works against metamorphism specifically:** obfuscation techniques rewrite instructions, but they generally cannot change the program's fundamental branching logic without changing what the program actually does.

### 4.2 `cfg_structural_analysis.py` — standalone structural scoring

This does not compare against any other sample. It scores a single CFG on its own shape.

High branch density (many edges relative to nodes) and a high ratio of dead-end blocks (reachable but going nowhere) are both signatures of code that has been deliberately obfuscated — junk branches and dead code inserted purely to confuse analysis, not to serve program logic.

**Why this works against metamorphism specifically:** this needs zero prior samples of the malware family. It works on any single file in isolation, which matters because metamorphic variants may share no code with each other at all.

### 4.3 `hmm_behavior.py` — category-level Hidden Markov Model

Instead of modeling exact instructions, this maps every instruction to one of five broad categories (arithmetic, memory, control_transfer, logic, other) and models the *sequence of categories* with a Hidden Markov Model:

**Why this works against metamorphism specifically:** register renaming and instruction substitution change the exact mnemonic (`mov` vs `lea`, for example) but usually keep the instruction in the same functional category (both are `memory` operations). Category-sequence modeling is invariant to exactly the kind of substitution metamorphic engines rely on.

## 5. Shared Confirmation Stage — `sandbox_isolation.py`

Static analysis (all six checks above) never actually runs the sample. This module does, for a bounded window, inside an isolated environment, using `psutil` to watch real process behavior:

`flag_dangerous_behavior()` then checks for thresholds crossed — a spike in open file handles (possible mass encryption / ransomware behavior) or a spike in network connections (possible C2 beaconing).

This step exists because static structural signals, however good, are still inference. Runtime behavior is direct observation. It is the highest-risk part of the pipeline (it executes the sample), so it is the one component that must run inside a disposable, network-isolated VM, never in the WSL development environment.

## 6. Shared Layer

| File | Responsibility |
|---|---|
| `shared/logger.py` | One shared logging config; every module writes through it |
| `shared/utils.py` | `calculate_entropy()`, file reading, disassembly helper, sample listing |
| `shared/model_storage.py` | pickle-based save/load for trained models |
| `config.py` | Every threshold and path in one place (`ENTROPY_THRESHOLD`, `CFG_BRANCH_DENSITY_THRESHOLD`, etc.) |

Nothing detection-specific lives here — only what more than one track needs.

## 7. Orchestration — `main.py`

Contains zero detection logic. It only calls each check in sequence and merges results:

This is the seam that keeps detection logic and coordination logic separate — changing a threshold or swapping a model never touches this file.

## 9. Environment Boundaries

- **Development** (writing/running code on harmless test files): WSL2 on Windows.
- **Real malware handling** (downloading, unzipping, sandbox execution): a separate, disposable VirtualBox VM, snapshotted before every run, network adapter disabled during any monitored execution.

WSL is not treated as a strong enough isolation boundary for live samples, since it still shares kernel-level resources with the Windows host in some respects. The two environments are never merged.
