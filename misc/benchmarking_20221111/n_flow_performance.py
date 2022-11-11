#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt

labels = ['34', '66', '130', '258']
nobatch_many_jq = [2087720, 4070806, 7964851, 15761758]
nobatch_one_jq = [1075662, 2096756, 4110590, 8167249]
batch_many_jq = [(69832+74551+70318)/3,
                 (75263+78929+78031)/3,
                 (99978+96594+95671)/3,
                 (130711+127055+129459)/3]
batch_one_jq = [(36970+38420+34403)/3,
                (40202+39713+39580)/3,
                (44911+45686+47030)/3,
                (52168+56735+51616)/3]

x = np.arange(len(labels))
width = 0.2
fig, ax = plt.subplots()
rects1 = ax.bar(x - 1.5*width/1, nobatch_many_jq, width, label='nobatch-1shell-8jq')
rects2 = ax.bar(x - width/2, nobatch_one_jq, width, label='nobatch-1shell-1jq')
rects3 = ax.bar(x + width/2, batch_many_jq, width, label='batch-1shell-8jq')
rects4 = ax.bar(x + 1.5*width/1, batch_one_jq, width, label='batch-1shell-1jq')

ax.set_ylabel('latency [usec]')
ax.set_xticks(x, labels)
ax.set_title('#Flows Performance')
ax.legend()

ax.bar_label(rects1, padding=3)
ax.bar_label(rects2, padding=3)
ax.bar_label(rects3, padding=3)
ax.bar_label(rects4, padding=3)
fig.tight_layout()
plt.savefig("n_flow_performance.png")
