# import numpy as np
# import matplotlib.pyplot as plt
#
# x = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
# y = [27.50, 49.55, 69.78, 91.22, 113.21, 134.88, 155.85, 177.16, 198.46, 219.72]
# # y1, y2 = np.sin(x), np.cos(x)
#
# ax = plt.subplots()
# # plt.plot(x, y, marker='.', mec='r', mfc='w')
# # plt.plot(x, y, marker='.', ms=10)
# rect1 = ax.bar(range(len(y)), y, tick_label=x, label='KeyGen_S', color='springgreen')
#
# plt.show()

import matplotlib.pyplot as plt
import numpy as np


def auto_label(rects):
  for rect in rects:
    height = rect.get_height()
    ax.annotate('{}'.format(height),  # put the detail data
                xy=(rect.get_x() + rect.get_width() / 2, height),  # get the center location.
                xytext=(0, 3),  # 3 points vertical offset
                textcoords="offset points",
                ha='center', va='bottom')


def auto_text(rects):
  for rect in rects:
    ax.text(rect.get_x(), rect.get_height(), rect.get_height(), ha='left', va='bottom')


# x = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
# y = [27.50, 49.55, 69.78, 91.22, 113.21, 134.88, 155.85, 177.16, 198.46, 219.72]

labels = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
keygen_s = [27.50, 49.55, 69.78, 91.22, 113.21, 134.88, 155.85, 177.16, 198.46, 219.72]
keygen_id = [6.86, 6.81, 6.81, 6.81, 6.79, 6.81, 6.84, 6.79, 6.81, 6.81]
enc = [9.54, 9.54, 9.54, 9.57, 9.58, 9.56, 9.54, 9.57, 9.56, 9.60]
rk_gen = [39.23, 68.18, 100.54, 128.08, 158.70, 189.06, 220.11, 248.62, 279.35, 310.88]
re_enc = [1.83, 1.91, 2.03, 2.14, 2.28, 2.42, 2.58, 2.74, 2.95, 3.14]
trapdoor_id = [6.03, 5.95, 5.93, 5.92, 5.94, 5.99, 5.96, 5.95, 5.96, 5.98]
test_id = [3.49, 3.47, 3.48, 3.50, 3.48, 3.50, 3.48, 3.49, 3.50, 3.51]
trapdoor_s = [9.30, 13.43, 17.75, 21.79, 26.24, 30.43, 34.60, 38.88, 42.80, 47.41]
test_s = [8.17, 14.23, 20.14, 25.96, 32.08, 38.24, 44.43, 50.26, 56.52, 63.23]
dec_id = [1.74, 1.75, 1.75, 1.74, 1.76, 1.76, 1.74, 1.74, 1.74, 1.75]
dec_s = [11.83, 20.79, 29.61, 38.42, 48.84, 56.51, 65.71, 74.40, 83.63, 92.75]
# women_means = [25, 32, 34, 20, 25]

index = np.arange(len(labels))
width = 0.3

fig, ax = plt.subplots()
# rect1 = ax.bar(index - width / 2, men_means, color ='springgreen', width=width, label ='Men')
# rect1 = ax.bar(index - width / 1.3, keygen_id, color ='springgreen', width=width, label ='KeyGen(ID)')
# rect2 = ax.bar(index + width / 1.3, keygen_s, color='coral', width=width, label="KeyGen(S)")

# enc
# rect1 = plt.plot(labels, enc, label="Encrypt", marker='o')
# rect2 = plt.plot(labels, re_enc, label="ReEnc", marker='o')
# rect3 = plt.plot(labels, rk_gen, label='RKGen', marker='o')

# keygen
# rect1 = plt.plot(labels, keygen_id, label="KeyGen(ID)", marker='o')
# rect2 = plt.plot(labels, keygen_s, label="KeyGen(S)", marker='o')

# keyword search
# rect1 = plt.plot(labels, trapdoor_id, label="Trapdoor(ID)", marker='o')
# rect2 = plt.plot(labels, trapdoor_s, label="Trapdoor(S)", marker='o')
# rect3 = plt.plot(labels, test_id, label="Test(ID)", marker='o')
# rect4 = plt.plot(labels, test_s, label="Test(S)", marker='o')
#
# plt.xlabel('Number of attributes')
# plt.ylabel('Time(ms)')
# plt.legend()

# trapdoor
# rect1 = ax.bar(index - width / 2, trapdoor_id, color ='springgreen', width=width, label ='Trapdoor(Or)')
# rect2 = ax.bar(index + width / 2, trapdoor_s, color='coral', width=width, label="Trapdoor(Re)")

# decrypt
# rect1 = ax.bar(index - width / 2, dec_id, color ='springgreen', width=width, label ='Decrypt(Or)')
# rect2 = ax.bar(index + width / 2, dec_s, color='coral', width=width, label="Decrypt(Re)")

# keygen
# rect1 = ax.bar(index - width / 2, keygen_id, color ='springgreen', width=width, label ='KeyGen(ID)')
# rect2 = ax.bar(index + width / 2, keygen_s, color='coral', width=width, label="KeyGen(S)")

# test
# rect1 = ax.bar(index - width / 2, test_id, color ='springgreen', width=width, label ='Test(Or)')
# rect2 = ax.bar(index + width / 2, test_s, color='coral', width=width, label="Test(Re)")

# rect1 = ax.bar(index - width, enc, color='coral', width=width, label="Encrypt")
# rect2 = ax.bar(index, re_enc, color='springgreen', width=width, label='ReEnc')
# rect3 = ax.bar(index + width, rk_gen, color='cyan', width=width, label='RKGen')

# enc
# rect1 = ax.bar(range(len(enc)), enc, color='coral', width=width, label="Encrypt")
# rect1 = ax.bar(index - width / 2, re_enc, color='springgreen', width=width, label='ReEnc')
# rect2 = ax.bar(index + width / 2, rk_gen, color='coral', width=width, label='RKGen')
plt.plot(labels, keygen_id, marker='*', ms=5, label="keygen_id")
plt.plot(labels, keygen_s, marker='*', ms=5, label="keygen_s")
plt.plot(labels, enc, marker='*', ms=5, label="enc")
plt.plot(labels, re_enc, marker='*', ms=5, label="re_enc")
plt.plot(labels, dec_id, marker='*', ms=5, label="dec_id")
plt.plot(labels, dec_s, marker='*', ms=5, label="dec_s")
# ax.set_title('Time cost of the key generation algorithms')
ax.set_xticks(ticks=index)
ax.set_xticklabels(labels)
ax.set_xlabel("Number of attributes")
ax.set_ylabel('Time(ms)')

ax.set_ylim(0, 350)
# auto_label(rect1)
# auto_label(rect2)
# auto_label(rect3)
# auto_text(rect1)
# auto_text(rect2)

ax.legend(loc='upper left', frameon=False)
fig.tight_layout()
plt.savefig('re_enc_bar.png', dpi=300)
plt.show()
