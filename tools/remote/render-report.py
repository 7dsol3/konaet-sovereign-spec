"""Render archived remote observations after verify-report.mjs has accepted them.

Optional reporting dependency: matplotlib. The Node runtime does not need it.
"""
import argparse
import datetime as dt
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--preview', type=Path)
    args = parser.parse_args()
    read = lambda name: json.loads((args.directory / name).read_text(encoding='utf-8'))
    summary = read('verified-summary.json')
    controller = read('controller.json')['body']
    if not summary.get('passed') or summary['stateRoot'] != controller['finalRoot']:
        raise ValueError('A verified matching report is required before rendering.')
    started = controller['startedAt']
    duration = controller['elapsedMs'] / 60000
    observations = []
    for line in (args.directory / 'external-observations.jsonl').read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        timestamp = dt.datetime.fromisoformat(row['observedAt'].replace('Z', '+00:00')).timestamp() * 1000
        minute = (timestamp - started) / 60000
        if 0 <= minute <= duration:
            observations.append((minute, row['states']))
    if len(observations) < 2:
        raise ValueError('Multiple external observations are required.')
    observations.append((duration, controller['finalStates']))

    colors = ['#a898ff', '#46d6cf', '#ffc675', '#f08dbe']
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'text.color': '#e8ebfa',
        'axes.labelcolor': '#c4cce2', 'xtick.color': '#a9b6d2', 'ytick.color': '#a9b6d2',
        'axes.edgecolor': '#33405b', 'axes.facecolor': '#141c2c', 'figure.facecolor': '#0b101b',
        'grid.color': '#29364d', 'font.size': 10, 'svg.hashsalt': 'konaet-remote-endurance'})
    fig, (availability, sequences, memory) = plt.subplots(3, 1, figsize=(13, 9),
        gridspec_kw={'height_ratios': [1.15, 1.5, 1.25]}, constrained_layout=True)
    fig.suptitle('KONAET  ·  HOMOLOGAÇÃO ENTRE 4 VMs', fontsize=19, fontweight='bold', x=0.04, ha='left')
    availability.set_title(f'{duration:.1f} min  ·  {summary["transfers"]} transferências  ·  '
        f'{summary["calls"]} chamadas .ko  ·  {summary["sequence"]} fechamentos', loc='left', pad=17, fontsize=12)

    for index in range(4):
        packet = read(f'result-{index}.json')['body']
        offline, cursor, stopped = [], 0.0, None
        for fault in packet['faults']:
            minute = max(0.0, min(duration, (fault['at'] - started) / 60000))
            if fault['action'] in ('stop', 'kill'):
                stopped = minute
            elif fault['action'] == 'start' and stopped is not None:
                offline.append((stopped, max(0.0, minute - stopped)))
                stopped = None
        if stopped is not None:
            offline.append((stopped, duration - stopped))
        for start, width in offline:
            if start > cursor:
                availability.broken_barh([(cursor, start - cursor)], (index - .27, .54), color=colors[index])
            availability.broken_barh([(start, width)], (index - .27, .54), color='#ef6675')
            cursor = start + width
        if cursor < duration:
            availability.broken_barh([(cursor, duration - cursor)], (index - .27, .54), color=colors[index])
        samples = [(minute, state) for minute, states in observations for state in states
            if state.get('index') == index and state.get('sequence') is not None]
        sequences.plot([row[0] for row in samples], [int(row[1]['sequence']) for row in samples],
            color=colors[index], linewidth=1.6, linestyle=['-', '--', ':', '-.'][index], label=f'Validador {index}')
        memory.plot([row[0] for row in samples], [row[1]['peakRssKb'] / 1024 for row in samples],
            color=colors[index], linewidth=1.6, label=f'Validador {index}')

    availability.set_yticks(range(4), [f'Validador {index}' for index in range(4)])
    availability.invert_yaxis()
    availability.set_ylabel('Processos ativos')
    availability.text(.99, 1.05, 'Vermelho: parada aplicada pelo roteiro', transform=availability.transAxes,
        ha='right', color='#ef9aa2', fontsize=9)
    sequences.set_ylabel('Sequência finalizada')
    sequences.set_ylim(bottom=0)
    sequences.legend(ncol=4, loc='upper left', frameon=False, fontsize=9)
    memory.set_ylabel('Pico de RSS observado (MiB)')
    memory.set_ylim(bottom=0)
    memory.set_xlabel('Minutos desde a convergência inicial')
    for axis in (availability, sequences, memory):
        axis.set_xlim(0, duration)
        axis.grid(axis='x', alpha=.55)
        axis.set_axisbelow(True)
        for side in ('top', 'right'):
            axis.spines[side].set_visible(False)
    fig.supxlabel('Amostras externas, estados finais e intervalos de falha dos relatos assinados. '
        'VMs sob a mesma conta/provedor; este gráfico não atesta administrações independentes.', fontsize=9, color='#a9b6d2')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, metadata={'Creator': 'Konaet remote operational validation', 'Date': None})
    if args.preview:
        args.preview.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(args.preview, dpi=120)
    plt.close(fig)
    print(json.dumps({'rendered': str(args.output), 'observationCount': len(observations), 'minutes': duration}))


if __name__ == '__main__':
    main()
