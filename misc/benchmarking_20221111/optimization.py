#!/usr/bin/env python3
import numpy as np
import matplotlib.pyplot as plt

labels = ['(shell-1jq)x8', '(shell-8jq)x1', '(shell-1jq)x1']
shell_means   = [65299620, 15761758, 8167249]

x = np.arange(len(labels))
width = 0.35
fig, ax = plt.subplots()
rects1 = ax.bar(x, shell_means, width, label='shell')

ax.set_ylabel('latency [usec]')
ax.set_xticks(x, labels)
ax.set_title('Optimize Shell Hooks')
ax.legend()

ax.bar_label(rects1, padding=3)
#ax.bar_label(rects2, padding=3)
fig.tight_layout()
plt.savefig("optimization.png")
