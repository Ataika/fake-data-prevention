"""
visualizer.py
=============
Generates all charts and figures for the project report and frontend.
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import matplotlib.ticker as mticker


# ── Colour palette ───────────────────────────────────────────────────────────
C_OK      = "#2ecc71"
C_TAMPER  = "#e74c3c"
C_FAKE    = "#e67e22"
C_REPLAY  = "#9b59b6"
C_CERT    = "#3498db"
C_NEUTRAL = "#95a5a6"
C_DARK    = "#2c3e50"
C_BG      = "#f8f9fa"


def _style_ax(ax, title: str):
    ax.set_facecolor(C_BG)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title(title, fontweight="bold", color=C_DARK, fontsize=12, pad=10)


# ─────────────────────────────────────────────────────────────────────────────
#  Chart 1 — Verification Results Overview (bar chart)
# ─────────────────────────────────────────────────────────────────────────────

def plot_verification_overview(results: list, out_path: str):
    from collections import Counter

    status_map = {
        "✅ VALID":                     ("Valid",        C_OK),
        "❌ MODIFICATION DETECTED":     ("Modification", C_TAMPER),
        "❌ FABRICATION DETECTED":      ("Fabrication",  C_FAKE),
        "❌ REPLAY ATTACK DETECTED":    ("Replay",       C_REPLAY),
        "❌ INVALID CERTIFICATE":       ("Invalid Cert", C_CERT),
    }

    counts  = Counter(r["status"] for r in results)
    labels  = []
    values  = []
    colours = []

    for raw, (label, colour) in status_map.items():
        if counts.get(raw, 0) > 0:
            labels.append(label)
            values.append(counts[raw])
            colours.append(colour)

    fig, ax = plt.subplots(figsize=(9, 5), facecolor="white")
    bars = ax.bar(labels, values, color=colours, width=0.55, edgecolor="white", linewidth=1.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.3,
                str(val), ha="center", va="bottom",
                fontweight="bold", fontsize=13, color=C_DARK)

    _style_ax(ax, "Verification Results by Category")
    ax.set_ylabel("Number of transactions", color=C_DARK)
    ax.set_xlabel("")
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.set_facecolor(C_BG)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[chart] {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  Chart 2 — Attack Detection Breakdown (pie / donut)
# ─────────────────────────────────────────────────────────────────────────────

def plot_attack_pie(results: list, out_path: str):
    from collections import Counter
    counts = Counter(r["status"] for r in results)

    valid_n = counts.get("✅ VALID", 0)
    attack_n = len(results) - valid_n

    sizes   = [valid_n, attack_n]
    labels  = [f"Valid ({valid_n})", f"Threats Detected ({attack_n})"]
    colours = [C_OK, C_TAMPER]
    explode = [0, 0.07]

    fig, ax = plt.subplots(figsize=(6, 6), facecolor="white")
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colours, explode=explode,
        autopct="%1.1f%%", startangle=140,
        wedgeprops=dict(edgecolor="white", linewidth=2),
        textprops=dict(color=C_DARK, fontsize=12)
    )
    for at in autotexts:
        at.set_fontweight("bold")
        at.set_fontsize(13)

    ax.set_title("Valid vs Compromised Transactions", fontweight="bold",
                 color=C_DARK, fontsize=13, pad=14)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[chart] {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  Chart 3 — Data Flow Architecture diagram
# ─────────────────────────────────────────────────────────────────────────────

def plot_data_flow(out_path: str):
    fig, ax = plt.subplots(figsize=(14, 7), facecolor="white")
    ax.axis("off")
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 7)

    ax.set_title("Data Flow: Fake Data Prevention Pipeline",
                 fontsize=15, fontweight="bold", color=C_DARK, pad=12)

    # ── Node definitions: (x, y, label, colour, width, height) ──────────────
    nodes = [
        (1.0,  5.5, "CSV\nDataset",         "#dfe6e9",  1.6, 0.8),
        (3.2,  5.5, "SHA-256\nDigest",       "#d5f5e3",  1.6, 0.8),
        (5.4,  5.5, "RSA-PSS\nSignature",    "#d5f5e3",  1.6, 0.8),
        (7.6,  5.5, "JWT\n(RS256)",          "#d6eaf8",  1.6, 0.8),
        (9.8,  5.5, "AES-256\nEncrypt",      "#fdebd0",  1.6, 0.8),
        (12.0, 5.5, "Secure\nDB",            "#d7bde2",  1.6, 0.8),

        (12.0, 3.2, "AES\nDecrypt",          "#fdebd0",  1.6, 0.8),
        (9.8,  3.2, "JWT\nVerify",           "#d6eaf8",  1.6, 0.8),
        (7.6,  3.2, "Digest\nRecompute",     "#d5f5e3",  1.6, 0.8),
        (5.4,  3.2, "Sig\nVerify",           "#d5f5e3",  1.6, 0.8),
        (3.2,  3.2, "Certificate\nCheck",    "#fadbd8",  1.6, 0.8),
        (1.0,  3.2, "✅ VALID\nor ❌ FAKE",  "#eaecee",  1.6, 0.8),
    ]

    for (x, y, lbl, col, w, h) in nodes:
        rect = mpatches.FancyBboxPatch(
            (x - w/2, y - h/2), w, h,
            boxstyle="round,pad=0.07",
            facecolor=col, edgecolor="#aab7b8", linewidth=1.5
        )
        ax.add_patch(rect)
        ax.text(x, y, lbl, ha="center", va="center",
                fontsize=9, fontweight="bold", color=C_DARK, linespacing=1.4)

    # ── Arrows (sender top row) ──────────────────────────────────────────────
    top_xs = [1.0, 3.2, 5.4, 7.6, 9.8, 12.0]
    for i in range(len(top_xs) - 1):
        ax.annotate("", xy=(top_xs[i+1] - 0.82, 5.5),
                    xytext=(top_xs[i] + 0.82, 5.5),
                    arrowprops=dict(arrowstyle="-|>", color=C_DARK, lw=1.6))

    # ── Arrow down (DB → decrypt) ────────────────────────────────────────────
    ax.annotate("", xy=(12.0, 3.2 + 0.42),
                xytext=(12.0, 5.5 - 0.42),
                arrowprops=dict(arrowstyle="-|>", color=C_DARK, lw=1.6))

    # ── Arrows (receiver bottom row, right→left) ─────────────────────────────
    bot_xs = [12.0, 9.8, 7.6, 5.4, 3.2, 1.0]
    for i in range(len(bot_xs) - 1):
        ax.annotate("", xy=(bot_xs[i+1] + 0.82, 3.2),
                    xytext=(bot_xs[i] - 0.82, 3.2),
                    arrowprops=dict(arrowstyle="-|>", color=C_DARK, lw=1.6))

    # ── Labels ───────────────────────────────────────────────────────────────
    ax.text(6.5, 6.6, "SENDER SIDE", fontsize=11, fontweight="bold",
            color="#117a65", ha="center",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#d5f5e3", edgecolor="#117a65"))
    ax.text(6.5, 2.2, "RECEIVER SIDE", fontsize=11, fontweight="bold",
            color="#7b241c", ha="center",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#fadbd8", edgecolor="#7b241c"))

    # ── Threat labels ─────────────────────────────────────────────────────────
    threat_data = [
        (5.4, 4.35, "Blocks\nFabrication", C_FAKE),
        (7.6, 4.35, "Blocks\nReplay",      C_REPLAY),
        (3.2, 4.35, "Blocks both",         C_CERT),
    ]
    for (x, y, lbl, col) in threat_data:
        ax.text(x, y, lbl, ha="center", va="center", fontsize=7.5,
                color=col, fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.15", facecolor="white",
                          edgecolor=col, linewidth=1))

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[chart] {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  Chart 4 — Step-by-step verification status grid
# ─────────────────────────────────────────────────────────────────────────────

def plot_verification_steps_heatmap(results: list, out_path: str):
    import numpy as np

    # Show first 20 transactions
    sample = results[:20]
    steps  = ["Cert\nValid", "JWT\nValid", "Digest\nValid", "Sig\nValid"]

    matrix = []
    labels_y = []
    for r in sample:
        row = [
            int(r["cert_valid"]),
            int(r["jwt_valid"]),
            int(r["digest_valid"]),
            int(r["sig_valid"]),
        ]
        matrix.append(row)
        labels_y.append(r["tx_id"].replace("TXN-2024-", "TXN-"))

    matrix = np.array(matrix, dtype=float)

    fig, ax = plt.subplots(figsize=(7, 8), facecolor="white")
    cmap = matplotlib.colors.ListedColormap([C_TAMPER, C_OK])
    ax.imshow(matrix, aspect="auto", cmap=cmap, vmin=0, vmax=1)

    ax.set_xticks(range(len(steps)))
    ax.set_xticklabels(steps, fontsize=10, fontweight="bold", color=C_DARK)
    ax.set_yticks(range(len(labels_y)))
    ax.set_yticklabels(labels_y, fontsize=8, color=C_DARK)
    ax.set_title("Verification Steps — First 20 Rows", fontweight="bold",
                 color=C_DARK, fontsize=12, pad=10)

    # Add text annotations
    for i in range(len(sample)):
        for j in range(len(steps)):
            val = "✓" if matrix[i, j] == 1 else "✗"
            ax.text(j, i, val, ha="center", va="center",
                    fontsize=11, color="white", fontweight="bold")

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[chart] {out_path}")


def generate_all_charts(results: list, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    paths = {
        "overview":  os.path.join(output_dir, "chart_overview.png"),
        "pie":       os.path.join(output_dir, "chart_pie.png"),
        "dataflow":  os.path.join(output_dir, "chart_dataflow.png"),
        "heatmap":   os.path.join(output_dir, "chart_heatmap.png"),
    }
    plot_verification_overview(results, paths["overview"])
    plot_attack_pie(results, paths["pie"])
    plot_data_flow(paths["dataflow"])
    plot_verification_steps_heatmap(results, paths["heatmap"])
    return paths
