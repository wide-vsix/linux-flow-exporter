#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt

labels = ['nothing', '1 hook', '2 hooks', '8 hooks']
shell_means   = [5772, 8335522, 16449901, 65299620]
command_means = [5772, 8111420, 16282779, 64994027]

x = np.arange(len(labels))
width = 0.35
fig, ax = plt.subplots()
rects1 = ax.bar(x - width/2, shell_means, width, label='shell')
rects2 = ax.bar(x + width/2, command_means, width, label='command')

ax.set_ylabel('latency [usec]')
ax.set_xticks(x, labels)
ax.set_title('#Hooks Performance')
ax.legend()

ax.bar_label(rects1, padding=3)
ax.bar_label(rects2, padding=3)
fig.tight_layout()
plt.savefig("n_hook_performance.png")
