# ART ANOVA Results Report: Prior Knowledge x Memory Organization


## 1. Main ART ANOVA Results

> The effect size `partial_eta2` is partial eta squared computed on the ART-aligned ranked response, and is used to quantify the explanatory strength of each term in rank space.

| Metric | Effect | df | df.res | F | p | partial_eta2 |
|---|---|---|---|---|---|---|
| Binary F1 | Prior | 2.0000 | 30.0000 | 17.2996 | <0.001 | 0.5356 |
| Binary F1 | Memory | 4.0000 | 30.0000 | 5.1476 | 0.0028 | 0.4070 |
| Binary F1 | Prior:Memory | 8.0000 | 30.0000 | 7.1128 | <0.001 | 0.6548 |
| SSH F1 | Prior | 2.0000 | 30.0000 | 13.8953 | <0.001 | 0.4809 |
| SSH F1 | Memory | 4.0000 | 30.0000 | 4.8778 | 0.0038 | 0.3941 |
| SSH F1 | Prior:Memory | 8.0000 | 30.0000 | 6.7782 | <0.001 | 0.6438 |
| Weighted F1 | Prior | 2.0000 | 30.0000 | 33.0441 | <0.001 | 0.6878 |
| Weighted F1 | Memory | 4.0000 | 30.0000 | 4.8816 | 0.0037 | 0.3943 |
| Weighted F1 | Prior:Memory | 8.0000 | 30.0000 | 3.0449 | 0.0125 | 0.4481 |
| Accuracy | Prior | 2.0000 | 30.0000 | 39.0379 | <0.001 | 0.7224 |
| Accuracy | Memory | 4.0000 | 30.0000 | 5.5751 | 0.0018 | 0.4264 |
| Accuracy | Prior:Memory | 8.0000 | 30.0000 | 3.3873 | 0.0069 | 0.4746 |
| Precision@High/Critical | Prior | 2.0000 | 30.0000 | 15.5680 | <0.001 | 0.5093 |
| Precision@High/Critical | Memory | 4.0000 | 30.0000 | 4.8207 | 0.0040 | 0.3913 |
| Precision@High/Critical | Prior:Memory | 8.0000 | 30.0000 | 5.0658 | <0.001 | 0.5746 |
| Recall@High/Critical | Prior | 2.0000 | 30.0000 | 24.0602 | <0.001 | 0.6160 |
| Recall@High/Critical | Memory | 4.0000 | 30.0000 | 7.9629 | <0.001 | 0.5150 |
| Recall@High/Critical | Prior:Memory | 8.0000 | 30.0000 | 6.1844 | <0.001 | 0.6225 |
| Consistency std | Prior | 2.0000 | 30.0000 | 65.7027 | <0.001 | 0.8141 |
| Consistency std | Memory | 4.0000 | 30.0000 | 9.4326 | <0.001 | 0.5571 |
| Consistency std | Prior:Memory | 8.0000 | 30.0000 | 8.3485 | <0.001 | 0.6900 |
| Esc rho | Prior | 2.0000 | 30.0000 | 8.4063 | 0.0013 | 0.3591 |
| Esc rho | Memory | 4.0000 | 30.0000 | 7.1448 | <0.001 | 0.4879 |
| Esc rho | Prior:Memory | 8.0000 | 30.0000 | 1.9056 | 0.0962 | 0.3369 |
| Binary Precision | Prior | 2.0000 | 30.0000 | 22.1462 | <0.001 | 0.5962 |
| Binary Precision | Memory | 4.0000 | 30.0000 | 7.6142 | <0.001 | 0.5038 |
| Binary Precision | Prior:Memory | 8.0000 | 30.0000 | 9.3618 | <0.001 | 0.7140 |
| Binary Recall | Prior | 2.0000 | 30.0000 | 25.1213 | <0.001 | 0.6261 |
| Binary Recall | Memory | 4.0000 | 30.0000 | 7.5687 | <0.001 | 0.5023 |
| Binary Recall | Prior:Memory | 8.0000 | 30.0000 | 7.5374 | <0.001 | 0.6678 |
| Prompt tokens | Prior | 2.0000 | 30.0000 | 8.8275 | <0.001 | 0.3705 |
| Prompt tokens | Memory | 4.0000 | 30.0000 | 80.2060 | <0.001 | 0.9145 |
| Prompt tokens | Prior:Memory | 8.0000 | 30.0000 | 0.8117 | 0.5979 | 0.1779 |

## 2. Binary F1 Cell Means, SD, and CV

> CV = SD / mean. When the mean is close to 0, CV can become extreme or undefined, so CV should be interpreted together with the original three-run values.

| Prior | Memory | mean | sd | CV | n=3 values | note |
|---|---|---|---|---|---|---|
| Mismatch | NoMem | 0.1753 | 0.0021 | 0.0117 | 0.1743, 0.1740, 0.1777 |  |
| Mismatch | GlobalMem | 0.1969 | 0.0043 | 0.0220 | 0.2009, 0.1975, 0.1923 |  |
| Mismatch | GlobalMemRolling | 0.1533 | 0.0021 | 0.0137 | 0.1509, 0.1545, 0.1546 |  |
| Mismatch | PairMem | 0.2428 | 0.0480 | 0.1976 | 0.2882, 0.2477, 0.1926 | best in prior |
| Mismatch | PairMemRolling | 0.2338 | 0.0403 | 0.1723 | 0.2788, 0.2215, 0.2011 |  |
| Fair | NoMem | 0.0251 | 0.0142 | 0.5638 | 0.0399, 0.0117, 0.0237 |  |
| Fair | GlobalMem | 0.3048 | 0.2955 | 0.9696 | 0.3243, 0.0000, 0.5901 |  |
| Fair | GlobalMemRolling | 0.2145 | 0.2318 | 1.0805 | 0.4604, 0.1832, 0.0000 |  |
| Fair | PairMem | 0.3290 | 0.0453 | 0.1377 | 0.3623, 0.3473, 0.2774 | best in prior |
| Fair | PairMemRolling | 0.2732 | 0.0226 | 0.0826 | 0.2891, 0.2832, 0.2474 |  |
| Oracle | NoMem | 0.7881 | 0.0613 | 0.0778 | 0.8016, 0.8415, 0.7212 | best in prior |
| Oracle | GlobalMem | 0.3560 | 0.1253 | 0.3520 | 0.4695, 0.2215, 0.3771 |  |
| Oracle | GlobalMemRolling | 0.1166 | 0.1017 | 0.8725 | 0.0000, 0.1872, 0.1625 |  |
| Oracle | PairMem | 0.3033 | 0.0550 | 0.1813 | 0.3657, 0.2821, 0.2620 |  |
| Oracle | PairMemRolling | 0.2767 | 0.0187 | 0.0675 | 0.2552, 0.2861, 0.2888 |  |

## 3. High-CV Diagnostics for the GlobalMem Series

| Metric | Prior | Memory | mean | sd | CV | min | max | n=3 values |
|---|---|---|---|---|---|---|---|---|
| Binary F1 | Fair | GlobalMem | 0.3048 | 0.2955 | 0.9696 | 0.0000 | 0.5901 | 0.3243, 0.0000, 0.5901 |
| Binary F1 | Fair | GlobalMemRolling | 0.2145 | 0.2318 | 1.0805 | 0.0000 | 0.4604 | 0.4604, 0.1832, 0.0000 |
| Binary F1 | Mismatch | GlobalMem | 0.1969 | 0.0043 | 0.0220 | 0.1923 | 0.2009 | 0.2009, 0.1975, 0.1923 |
| Binary F1 | Mismatch | GlobalMemRolling | 0.1533 | 0.0021 | 0.0137 | 0.1509 | 0.1546 | 0.1509, 0.1545, 0.1546 |
| Binary F1 | Oracle | GlobalMem | 0.3560 | 0.1253 | 0.3520 | 0.2215 | 0.4695 | 0.4695, 0.2215, 0.3771 |
| Binary F1 | Oracle | GlobalMemRolling | 0.1166 | 0.1017 | 0.8725 | 0.0000 | 0.1872 | 0.0000, 0.1872, 0.1625 |
| SSH F1 | Fair | GlobalMem | 0.4625 | 0.4030 | 0.8714 | 0.0000 | 0.7385 | 0.6490, 0.0000, 0.7385 |
| SSH F1 | Fair | GlobalMemRolling | 0.4609 | 0.4160 | 0.9026 | 0.0000 | 0.8086 | 0.8086, 0.5741, 0.0000 |
| SSH F1 | Mismatch | GlobalMem | 0.5511 | 0.0170 | 0.0308 | 0.5315 | 0.5621 | 0.5315, 0.5596, 0.5621 |
| SSH F1 | Mismatch | GlobalMemRolling | 0.5268 | 0.0061 | 0.0116 | 0.5220 | 0.5337 | 0.5247, 0.5220, 0.5337 |
| SSH F1 | Oracle | GlobalMem | 0.7526 | 0.1057 | 0.1405 | 0.6659 | 0.8704 | 0.8704, 0.6659, 0.7216 |
| SSH F1 | Oracle | GlobalMemRolling | 0.3693 | 0.3203 | 0.8674 | 0.0000 | 0.5717 | 0.0000, 0.5717, 0.5363 |

## 4. Variance Heterogeneity Diagnostics

> This section uses the Brown-Forsythe form of Levene's test: a one-way ANOVA on deviations from the median within each Prior x Memory cell. Because n=3 is very small, this test has low power; a non-significant p-value does not prove equal variances, and only indicates that there is insufficient evidence to reject homogeneity of variance.

| Metric | Brown-Forsythe F | p |
|---|---|---|
| Binary F1 | 2.1061 | 0.0426 |
| SSH F1 | 1.2292 | 0.3062 |
| Weighted F1 | 0.7638 | 0.6969 |
| Accuracy | 0.8267 | 0.6368 |
| Precision@High/Critical | 1.3088 | 0.2593 |
| Recall@High/Critical | 1.3247 | 0.2507 |
| Consistency std | 1.7559 | 0.0958 |
| Esc rho | 1.0424 | 0.4421 |
| Binary Precision | 2.0741 | 0.0459 |
| Binary Recall | 1.1488 | 0.3603 |
| Prompt tokens | 0.7370 | 0.7223 |
