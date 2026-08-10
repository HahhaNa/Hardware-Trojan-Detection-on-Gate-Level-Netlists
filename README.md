# Hardware Trojan Detection on Gate-Level Netlists

A bidirectional graph neural network that finds malicious circuitry in gate-level Verilog
netlists without needing a trusted "golden chip" for comparison.

The model takes a flattened gate-level netlist, decides whether it contains a hardware
Trojan, and if so points out which specific gates belong to it. The problem is treated as
node classification on a circuit graph, where each gate is a node and each net is a
directed edge.

Submitted to the 2025 ICCAD CAD Contest, Problem A, where it received an Honorable
Mention. The work was also part of a six-person comparative study that won 1st place at
the NTHU CS Department Project Competition.

![Python](https://img.shields.io/badge/python-3.10-blue)
![PyTorch](https://img.shields.io/badge/pytorch-2.2-ee4c2c)
![PyG](https://img.shields.io/badge/torch--geometric-2.6-3c8dbc)
![License](https://img.shields.io/badge/license-MIT-green)

## Installation

Requires Python 3.10.

```bash
git clone https://github.com/HahhaNa/Hardware-Trojan-Detection-on-Gate-Level-Netlists.git
cd Hardware-Trojan-Detection-on-Gate-Level-Netlists
python3.10 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

That is all you need for evaluation. The pretrained model and all 30 contest designs are
included in the repository, so there is nothing else to download and no GPU required.
Yosys is only needed if you want to convert your own RTL, which is covered below.

Note that `torch==2.2.2` is pinned because it is the last release with prebuilt macOS
x86_64 wheels. On Linux with CUDA you can use a newer `torch` and install the matching
`torch-geometric` wheel from https://data.pyg.org/whl/.

## Quick start

All scripts resolve paths relative to `src/`, so run them from there.

```bash
cd src
python evaluate_iccad.py
```

This scores all 30 designs in about 70 seconds on CPU and prints:

```
  - Precision: 0.9059
  - Recall: 0.7494
  - F1 Score: 0.8203
  - Total points: 69.6651 / 80.0000  (87.08%)
```

A per-design breakdown is written to `results/evaluation_results.csv`.

To run it on your own netlists, put the `.v` files in a directory and point at it:

```bash
python evaluate_iccad.py --data-dir /path/to/your/netlists
```

Inputs need to be flattened to the contest's primitive gate set (`and`, `or`, `nand`,
`nor`, `not`, `buf`, `xor`, `xnor`, `dff`). If you have RTL instead, see
[Converting your own RTL](#converting-your-own-rtl).

## Results

Official 2025 CAD Contest evaluation:

| Metric | Score |
| --- | --- |
| Circuit-level accuracy | **93.3%** (28 / 30 designs) |
| Gate-level precision (avg) | 88.3% |
| Gate-level recall (avg) | 78.6% |
| Gate-level F1 (avg) | **80.5%** |

The checkpoint included here scores slightly differently on the 30 public release designs,
since the contest submission used a different decision threshold:

| Metric | Value |
| --- | --- |
| Circuit-level accuracy | 27 / 30 (90.0%) |
| Gate-level precision | 0.9059 (micro), 0.8827 (avg) |
| Gate-level recall | 0.7494 (micro), 0.7429 (avg) |
| Gate-level F1 | 0.8203 (micro), 0.7833 (avg) |
| Score | 69.67 / 80 (87.1%) |

The three mistakes are one missed Trojan (`design19`) and two false alarms on clean
designs (`design28` and `design29`). Per-design breakdowns for this and earlier runs are
in [`results/`](results/).

One caveat worth stating clearly: these are in-domain numbers rather than held-out
generalization. The augmented training set is generated from these same 30 designs. The
30 original netlists are kept out of training and used as the test split, but perturbed
variants of them are not. Performance on unfamiliar circuit families will be lower.

## How it works

There are two main difficulties with this problem. Trojan gates make up a very small
fraction of any netlist, roughly 1 in 8 and much worse on large designs, so a model that
predicts "clean" everywhere already looks good on accuracy. On top of that, the contest
provides only 30 designs, which is not enough to train a GNN without overfitting almost
immediately.

This approach handles both with data augmentation and loss shaping rather than with a
more complicated architecture.

### Data augmentation

Two generators turn the 30 base designs into roughly 13,000 training circuits.

`data_augmentation.py` rewrites 5 to 25 percent of the gates in each netlist into
logic-equivalent forms, turning `xor` into `nand` plus `not`, `or` into `nor` plus `not`,
and so on. Four strategies are available (`progressive`, `clustered`, `type_focused` and
`mixed`), and Trojan labels are carried through the rewrite so they stay correct. This is
plain text-level netlist manipulation and does not invoke a synthesis tool.

`trojan_insertion.py` splices payloads from `data/TrojanDef` into clean benchmark
circuits. It uses a `tj_` naming prefix to avoid collisions and XOR gates to combine
Trojan outputs with victim wires. Each payload is inserted into at most 8 clean circuits
so the corpus stays varied.

Together these teach the model to recognize a Trojan as a structural pattern that survives
logic-equivalent rewriting, instead of memorizing particular gate spellings.

### Node features

Each gate gets a 30-dimensional feature vector.

| Index | Feature |
| --- | --- |
| 0-8 | Gate-type one-hot (`and`, `or`, `nand`, `nor`, `not`, `buf`, `xor`, `xnor`, `dff`) |
| 9 | Fan-in |
| 10-14 | DFF attributes: is-DFF, async-low reset, non-default set, clock binding, reset present |
| 15-17 | Fan-out, plus in/out degree normalized by circuit size |
| 18-20 | PageRank, clustering coefficient, betweenness centrality |
| 21-23 | Inverse distance from primary inputs, to primary outputs, and from the nearest DFF |
| 24 | XOR/XNOR density in the local neighborhood |
| 25 | Multiple-DFF connectivity |
| 26 | High-degree neighbor count |
| 27 | Reconvergent fanout indicator |
| 28 | Unusual fanout pattern, a covert-channel heuristic |
| 29 | Feedback-loop membership |

Features 24 to 29 come from EDA domain knowledge. Comparator-style trigger logic tends to
be XOR-heavy, sits far from primary I/O, and looks structurally different from the
surrounding datapath. Features 18 to 20 let graph centrality find important nodes on its
own, which scales better than listing anomaly indicators by hand.

Features are standardized with a `StandardScaler` fitted during training. It ships as
`models/feature_scaler.pkl` and is version-controlled alongside the weights, since
evaluation has to use the same scaler.

### Model architecture

`ImprovedBiGCN` is a 4-layer bidirectional graph network. Every layer passes messages both
along signal flow and against it, then concatenates the two views:

* Even layers use `SAGEConv` forward and `GATConv` (4 heads) backward
* Odd layers use `GATConv` (4 heads) forward and `SAGEConv` backward
* Each layer is followed by `LayerNorm` and a learned per-node attention gate
* Outputs from all layers are aggregated residually, then passed to a per-node classifier

Going in both directions helps because Trojan evidence appears in both. Trigger conditions
propagate forward from rare input combinations, while payload effects are easier to trace
backward from the corrupted outputs. Alternating SAGE and GAT gives each direction access
to both neighborhood averaging and learned attention.

Hidden dimension is 96 with dropout 0.3.

### Handling class imbalance

```python
WeightedFocalLoss(alpha=0.111, gamma=2.0, pos_weight=8.0)
```

Focal loss scales down easy examples by `(1 - p_t)^gamma` so the many easy clean-gate
predictions stop dominating the gradient. `alpha` rebalances the two classes and
`pos_weight` puts extra weight on Trojan gates to match the 1:8 ratio. Batches are also
built at a 2:1 Trojan-to-clean ratio, so imbalance is handled during sampling as well as
in the loss.

### Decision threshold

The per-gate threshold is not left at 0.5. It is re-searched on the validation split every
5 epochs to maximize F1, and the best value is saved in the checkpoint (0.85 for the
released model). At inference time `--min-trojan-gates` acts as a false-alarm guard, so a
design is only reported as Trojaned once enough gates cross the threshold. This suppresses
isolated spurious hits on clean circuits.

Training uses AdamW with initial LR 1e-4 and weight decay 5e-5, OneCycleLR with max LR
1e-3 and 30 percent warmup, batch size 64, gradient clipping at norm 1.0, for 60 epochs.

## Usage

### Evaluation options

| Flag | Default | Purpose |
| --- | --- | --- |
| `--model` | `../models/best_model_augmented.pth` | Checkpoint to load |
| `--data-dir` | `../data/release_official` | Directory of designs to score |
| `--output` | `../results/evaluation_results.csv` | Report path |
| `--threshold` | from checkpoint | Per-gate decision threshold |
| `--min-trojan-gates` | `10` | Gates needed before a circuit is called Trojaned |

### Training

The augmented corpus is not included in the repository because of its size (about 2.3 GB),
so it has to be regenerated first. Step 1 takes a while.

```bash
# 1. Perturb the official designs into a large augmented corpus
python data_augmentation.py \
    --input_dir ../data/release_official \
    --output_dir ../data/augmented_heavy \
    --strategy mixed --num_augmentations 20

# 2. Optional: splice TrojanDef payloads into the hand-written clean circuits
python trojan_insertion.py

# 3. Train
python train_bigcn.py --epochs 60 --batch-size 64 --hidden-dim 96
```

Checkpoints are written to `models/`. Use `--use-cache` to reuse encoded features between
runs, and `--resume` to continue from `models/training_checkpoint.pth`.

### Converting your own RTL

This is the only part that needs an external tool, namely
[Yosys](https://github.com/YosysHQ/yosys) (`brew install yosys`).

```bash
python netlist_converter.py my_design.v -o my_design_converted.v
```

It runs Yosys synthesis and maps the result down to the contest's primitive gate set. Add
`--detect-trojan` to diff a `TjFree.v` and `TjIn.v` pair and produce the Trojan gate
labels.

### Error analysis

```bash
python debug_predictions.py
```

Writes per-gate scores and confusion details for each design into `results/debug_results/`.

## Project structure

```
.
├── src/                        # All Python sources
│   ├── train_bigcn.py          # Model definition and training loop
│   ├── evaluate_iccad.py       # Contest-style evaluation, writes CSV report
│   ├── evaluate_iccad_sage.py  # Same, for the SAGE-only variant
│   ├── encode_features.py      # Netlist to 30-dim per-gate feature tensors
│   ├── netlist_converter.py    # RTL Verilog to primitive gate-level, via Yosys
│   ├── trojan_netlist_converter.py
│   ├── data_augmentation.py    # Logic-equivalent netlist perturbation
│   ├── trojan_insertion.py     # Splices TrojanDef payloads into clean circuits
│   └── debug_predictions.py    # Per-gate prediction dumps for error analysis
├── models/
│   ├── best_model_augmented.pth       # Main released checkpoint
│   ├── best_model_augmented_sage.pth  # SAGE-only variant
│   └── feature_scaler.pkl             # StandardScaler fitted at training time
├── data/
│   ├── release_official/       # Contest designs 0-29 with reference answers
│   ├── raw_trusthub/           # TrustHub PIC16F84 T100-T400 benchmarks
│   ├── TrojanDef/              # 10 standalone Trojan payloads
│   └── self_data/trojan_free/  # 18 hand-written clean circuits
├── results/                    # Evaluation CSVs and metric reports
└── requirements.txt
```

## Dataset

| Directory | Contents | Included |
| --- | --- | --- |
| `data/release_official` | 30 contest designs. 0-9 have known Trojans, 10-19 have unique random Trojans, 20-29 are clean. Includes `result*.txt` reference answers. | yes |
| `data/raw_trusthub` | TrustHub PIC16F84 T100/T200/T300/T400, original and converted | yes |
| `data/TrojanDef` | 10 standalone Trojan payloads used for insertion | yes |
| `data/self_data/trojan_free` | 18 hand-written clean circuits (ALU, barrel shifter, CRC32, FIFO and others) | yes |
| `data/self_data/trojan` | 540 circuits produced by `trojan_insertion.py` | generated |
| `data/augmented_heavy` | About 13k augmented netlists, 2.3 GB | generated |
| `data/augmented_offh` | About 1.5k augmented netlists, lighter variant | generated |

## Limitations

* Recall lags behind precision. The model is conservative and misses about 25 percent of
  Trojan gates while keeping false positives low. `design9` and `design16` are the worst
  cases, where large Trojans are only partially recovered.
* Two clean designs (`design28` and `design29`) still trigger false alarms despite the
  `--min-trojan-gates` guard.
* All evaluation is in-domain, as noted in the Results section.
* Large designs are slow. `design14` has about 5k Trojan gates and takes roughly 20 seconds
  to score on CPU.

In the comparative study, approaches that split circuit-level classification ("is there a
Trojan?") from gate-level classification ("which gates?") into two separate models reached
higher circuit-level precision than this single unified node classifier. That seems like
the most promising direction for future work.

## Citation

```
Y.-C. Li, T.-C. Huang, C.-L. Chen, E.-L. Hsiung, T.-Y. Hsieh, and L.-H. Yang,
"A Comparative Study of Graph Neural Network Approaches for Hardware Trojan Detection,"
2025 CAD Contest Problem A, National Tsing Hua University, 2025.
```

## License

[MIT](LICENSE)
