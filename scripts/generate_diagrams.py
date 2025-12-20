#!/usr/bin/env python3
"""
Generate high-quality architecture and solution diagrams
"""
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import numpy as np

# Set style
plt.style.use('default')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.size'] = 10

# ============================================================================
# FIGURE 1: Pipeline Flow (Three-Stage Process)
# ============================================================================
fig = plt.figure(figsize=(10, 12))
gs = fig.add_gridspec(1, 1, hspace=0.35, wspace=0.3)

# ---- LEFT: Three-stage pipeline ----
ax1 = fig.add_subplot(gs[0, 0])
ax1.set_xlim(0, 10)
ax1.set_ylim(0, 14)
ax1.axis('off')
ax1.text(5, 13.5, 'Detection & Attribution Pipeline', fontsize=16, fontweight='bold', ha='center')

# Stage labels on left
stages = [
    (1, 11, 'STAGE 1\nAggregation', '#4A90E2'),
    (1, 8, 'STAGE 2\nDetection', '#F5A623'),
    (1, 5, 'STAGE 3\nAttribution', '#7ED321'),
]

for x, y, label, color in stages:
    box = FancyBboxPatch((x-0.4, y-0.6), 1.2, 1.2, boxstyle="round,pad=0.05",
                         edgecolor=color, facecolor=color, alpha=0.3, linewidth=2)
    ax1.add_patch(box)
    ax1.text(x + 0.2, y, label, fontsize=9, fontweight='bold', ha='center', va='center')

# Stage 1: Input data
inputs = ['System\nMetrics', 'App\nLogs', 'Ground\nTruth']
for i, label in enumerate(inputs):
    x = 3 + i * 2
    box = Rectangle((x-0.6, 11.5), 1.2, 0.8, edgecolor='#4A90E2', facecolor='#E8F4FD', linewidth=1.5)
    ax1.add_patch(box)
    ax1.text(x, 11.9, label, fontsize=8, ha='center', va='center')
    ax1.arrow(x, 11.4, 0, -0.5, head_width=0.15, head_length=0.1, fc='#333', ec='#333')

# Stage 1: Output
output1 = '60s Windows\nAggregated Data'
box = FancyBboxPatch((3, 10), 4, 0.8, boxstyle="round,pad=0.05",
                     edgecolor='#4A90E2', facecolor='#E8F4FD', linewidth=2)
ax1.add_patch(box)
ax1.text(5, 10.4, output1, fontsize=9, ha='center', va='center', fontweight='bold')
ax1.arrow(5, 10, 0, -0.5, head_width=0.15, head_length=0.1, fc='#333', ec='#333')

# Stage 2: Detection
method2 = 'Isolation Forest\nContamination: 0.35'
box = FancyBboxPatch((3, 8.5), 4, 1, boxstyle="round,pad=0.05",
                     edgecolor='#F5A623', facecolor='#FFF5E6', linewidth=2)
ax1.add_patch(box)
ax1.text(5, 9.2, method2, fontsize=9, ha='center', va='center', fontweight='bold')

# Stage 2: Output
output2 = 'Anomaly\nDetected'
box = Rectangle((3.8, 7.8), 2.4, 0.6, edgecolor='#F5A623', facecolor='#FFF5E6', linewidth=1.5)
ax1.add_patch(box)
ax1.text(5, 8.1, output2, fontsize=9, ha='center', va='center', fontweight='bold')
ax1.arrow(5, 7.8, 0, -0.5, head_width=0.15, head_length=0.1, fc='#333', ec='#333')

# Stage 3: Attribution
method3_box = FancyBboxPatch((3, 5.8), 4, 1.2, boxstyle="round,pad=0.05",
                             edgecolor='#7ED321', facecolor='#F0FFF0', linewidth=2)
ax1.add_patch(method3_box)
ax1.text(5, 6.5, 'Multi-Signal Scoring + Persistence', fontsize=9, ha='center', va='center', fontweight='bold')
ax1.text(5, 6.1, 'z(35%) rel(25%) cnt(20%) base(12%) der(8%)', fontsize=8, ha='center', va='center', style='italic')

# Stage 3: Output
output3 = 'Blamed Tenant'
box = Rectangle((3.8, 5), 2.4, 0.6, edgecolor='#7ED321', facecolor='#F0FFF0', linewidth=1.5)
ax1.add_patch(box)
ax1.text(5, 5.3, output3, fontsize=9, ha='center', va='center', fontweight='bold')
ax1.arrow(5, 5, 0, -0.4, head_width=0.15, head_length=0.1, fc='#333', ec='#333')

# Detection performance
perf_box = FancyBboxPatch((3, 3.5), 4, 1.3, boxstyle="round,pad=0.1",
                         edgecolor='#BD10E0', facecolor='#F5E6FF', linewidth=2)
ax1.add_patch(perf_box)
ax1.text(5, 4.5, 'Detection Performance', fontsize=10, ha='center', fontweight='bold')
ax1.text(5, 4.0, 'Precision: 100%  |  Recall: 49.1%', fontsize=9, ha='center', family='monospace')

# Attribution performance
attr_box = FancyBboxPatch((3, 1.8), 4, 1.3, boxstyle="round,pad=0.1",
                         edgecolor='#13A538', facecolor='#E6F7EE', linewidth=2)
ax1.add_patch(attr_box)
ax1.text(5, 2.8, 'Attribution Accuracy', fontsize=10, ha='center', fontweight='bold')
ax1.text(5, 2.3, '66.7% (4/6 windows correct)', fontsize=9, ha='center', family='monospace', fontweight='bold')

fig.suptitle('AIOps Pipeline: Three-Stage Process', fontsize=18, fontweight='bold', y=0.98)
plt.savefig('figures/pipeline_flow.png', dpi=300, bbox_inches='tight', facecolor='white')
print('[OK] Pipeline flow diagram saved: figures/pipeline_flow.png')
plt.close()

# ============================================================================
# FIGURE 2: Results and Comparisons
# ============================================================================
fig2 = plt.figure(figsize=(12, 10))
gs2 = fig2.add_gridspec(2, 1, hspace=0.35, wspace=0.3)
# ---- Accuracy Progression ----
ax2 = fig2.add_subplot(gs2[0, 0])
methods = ['Initial\n(0 fixes)', 'Bug Fixes\nApplied', 'Balanced\nWeights', 'Persistent\nTracking']
accuracies = [0, 16.7, 16.7, 66.7]
colors = ['#E74C3C', '#F39C12', '#F39C12', '#27AE60']

bars = ax2.bar(methods, accuracies, color=colors, edgecolor='#333', linewidth=2, width=0.6)
ax2.set_ylabel('Attribution Accuracy (%)', fontsize=13, fontweight='bold')
ax2.set_ylim(0, 75)
ax2.axhline(y=50, color='red', linestyle='--', linewidth=2, label='Target (50%)', alpha=0.7)
ax2.grid(axis='y', alpha=0.3, linestyle='--')

# Add value labels on bars
for bar, acc in zip(bars, accuracies):
    height = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2., height + 1,
            f'{acc:.1f}%', ha='center', va='bottom', fontsize=11, fontweight='bold')

ax2.legend(fontsize=10)
ax2.set_title('Attribution Accuracy: Improvement Path', fontsize=14, fontweight='bold', pad=10)
ax2.set_ylim(0, 80)

# ---- Baseline Comparison ----
ax3 = fig2.add_subplot(gs2[1, 0])
baselines = ['Heuristic\n+Persistent', 'Correlation', 'Logs-Only', 'Metrics-Only', 'Random']
baseline_acc = [66.7, 14.3, 12.1, 9.2, 9.1]
colors_base = ['#27AE60', '#E67E22', '#E74C3C', '#95A5A6', '#BDC3C7']

bars2 = ax3.barh(baselines, baseline_acc, color=colors_base, edgecolor='#333', linewidth=1.5)
ax3.set_xlabel('Attribution Accuracy (%)', fontsize=13, fontweight='bold')
ax3.set_xlim(0, 75)
ax3.axvline(x=50, color='red', linestyle='--', linewidth=2, alpha=0.7)

# Add value labels
for bar, acc in zip(bars2, baseline_acc):
    width = bar.get_width()
    ax3.text(width + 1.5, bar.get_y() + bar.get_height()/2.,
            f'{acc:.1f}%', ha='left', va='center', fontsize=11, fontweight='bold')

ax3.set_title('Method Comparison vs. Baselines', fontsize=14, fontweight='bold', pad=10)
ax3.grid(axis='x', alpha=0.3, linestyle='--')

fig2.suptitle('Attribution Results & Baseline Comparison', fontsize=18, fontweight='bold', y=0.98)
plt.savefig('figures/pipeline_results.png', dpi=300, bbox_inches='tight', facecolor='white')
print('[OK] Results diagram saved: figures/pipeline_results.png')
plt.close()

print('\n' + '='*70)
print('DIAGRAMS GENERATED SUCCESSFULLY')
print('='*70)
print('✓ figures/pipeline_flow.png - Three-stage pipeline architecture')
print('✓ figures/pipeline_results.png - Accuracy improvements and comparisons')
print('='*70)

