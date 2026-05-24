# RQ1 Case Study Materials

## Reconstruction Boundaries

- PairMem contexts can be reconstructed from persisted `joined_data.jsonl` records with artifact-level near-exact reconstruction. The original memory item format is `[timestamp] event_type summary`; this material is not a persisted verbatim runtime prompt snapshot.
- PairMemRolling contexts can only be approximately reconstructed because the actual LLM-generated merged summaries were not persisted as standalone artifacts.
- The case materials are used to explain the overall result patterns and are not used as evidence of statistical significance.

## Case A: Fair / NoMem vs. Fair / PairMem Comparison

- Status: `已选中`
- Experimental run: `fair_n2`
- Communication pair: `172.16.0.1 <-> 192.168.10.50`

### NoMem False Negative

- Timestamp: `2026-04-17T07:58:18.351354091Z`
- Event type: `ssh`
- Ground-truth label: `SSH-Patator`
- Threat level: `无危`
- Communication pair: `172.16.0.1 <-> 192.168.10.50`
- Summary: 源IP 172.16.0.1:46366 通过TCP协议向目标IP 192.168.10.50:22 发起SSH连接请求，目标主机为Windows Vista系统。
- Security note: 该事件为一次SSH连接尝试，但因源IP地址属于外部网络（172.16.0.1），可能为外部攻击者尝试连接内部Windows系统，需关注是否为暴力破解行为。

### PairMem True Positive

- Timestamp: `2026-04-18T04:13:11.277630852Z`
- Event type: `ssh`
- Ground-truth label: `SSH-Patator`
- Threat level: `中`
- Communication pair: `172.16.0.1 <-> 192.168.10.50`
- Summary: 源IP 172.16.0.1:46392 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。该通信对在历史记忆中已出现过，且目标主机为Windows Vista系统，存在SSH服务暴露风险。
- Security note: 该事件表明外部IP尝试连接内网Windows Vista主机的SSH服务，可能为扫描或攻击行为。Windows Vista系统存在安全漏洞，若SSH服务未受保护，可能导致系统被入侵。

### PairMemRolling True Positive

- Timestamp: `2026-04-18T12:41:52.514310638Z`
- Event type: `ssh`
- Ground-truth label: `SSH-Patator`
- Threat level: `高`
- Communication pair: `172.16.0.1 <-> 192.168.10.50`
- Summary: 源IP 172.16.0.1:46528 通过TCP协议向目标IP 192.168.10.50:22 发起SSH连接请求，目标主机为Windows Vista，该通信对在短时间内多次重复出现，存在暴力破解风险。
- Security note: 该行为表现为典型的SSH暴力破解尝试，攻击者可能正在尝试通过大量连接请求猜解目标系统的SSH登录凭证。Windows Vista系统本身存在安全风险，且SSH服务暴露在外增加了被攻击的可能性。

### PairMem Context Before the Selected Event

- Reconstruction method: `artifact-level near-exact`
- Memory item count: `8`
- Limitation: `PairMem raw entries are reconstructed from persisted timestamp/event_type/ai.summary records, but the runtime prompt snapshot was not persisted.`

```text
[2026-04-18T04:13:11.277577718Z] ssh 源IP 172.16.0.1:46404 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。
[2026-04-18T04:13:11.277594412Z] ssh 源IP 172.16.0.1:46400 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。
[2026-04-18T04:13:11.277568018Z] ssh 源IP 172.16.0.1:46406 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。
[2026-04-18T04:13:11.277603150Z] ssh 源IP 172.16.0.1:46396 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。
[2026-04-18T04:13:11.277585588Z] ssh 源IP 172.16.0.1:46402 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。
[2026-04-18T04:13:11.277611097Z] ssh 源IP 172.16.0.1:46398 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。
[2026-04-18T04:13:11.277620264Z] ssh 源IP 172.16.0.1:46394 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。
[2026-04-18T04:13:11.277641124Z] ssh 源IP 172.16.0.1:46390 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。该通信对在短时间内重复出现，可能为扫描行为。
```

### PairMemRolling Context Before the Selected Event

- Selection note: `同一通信对至少发生一次模拟合并后的第一个真阳性事件`
- Reconstruction method: `近似`
- Memory item count: `21`
- Approximate merge count for this communication pair: `1`
- Limitation: `PairMemRolling 使用 LLM 生成的合并摘要；真实合并摘要没有作为独立字段持久化到 joined_data.jsonl；合并次数依据配置中的阈值与批大小模拟得到；该输出只近似保留原始记忆项顺序和合并边界。`

```text
[合并摘要近似] 已将 10 条原始记忆项从 2026-04-18T12:41:52.299837719Z 到 2026-04-18T12:41:52.300273035Z 近似合并；事件类型分布=ssh:10；真实的 LLM 生成合并摘要未被持久化。
[2026-04-18T12:41:52.300282382Z] ssh 源IP 172.16.0.1:46280 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。目标主机为Windows Vista。
[2026-04-18T12:41:52.300290421Z] ssh 源IP 172.16.0.1:46294 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。目标主机为Windows Vista。
[2026-04-18T12:41:52.330075799Z] ssh 源IP 172.16.0.1:46386 → 目标IP 192.168.10.50:22，使用TCP协议尝试建立SSH连接，目标主机为Windows Vista。
[2026-04-18T12:41:52.330084849Z] ssh 源IP 172.16.0.1:46382 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。该通信对在短时间内多次重复出现，目标主机为Windows Vista。
[2026-04-18T12:41:52.352607044Z] ssh 源IP 172.16.0.1:46384 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista。
[2026-04-18T12:41:52.352664012Z] ssh 源IP 172.16.0.1:46376 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求。目标主机为Windows Vista，存在SSH服务暴露风险。
[2026-04-18T12:41:52.352625990Z] ssh 源IP 172.16.0.1:46380 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista系统，存在SSH服务暴露风险。
[2026-04-18T12:41:52.352739607Z] ssh 源IP 172.16.0.1:46374 通过TCP协议向目标IP 192.168.10.50:22 发起SSH连接请求，目标主机为Windows Vista系统，存在SSH服务暴露风险。
[2026-04-18T12:41:52.352704676Z] ssh 源IP 172.16.0.1:46378 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求。该通信对在短时间内多次尝试连接目标主机的SSH服务，目标主机为Windows Vista系统，存在SSH服务暴露风险。
[2026-04-18T12:41:52.397971045Z] ssh 源IP 172.16.0.1:46482 → 目标IP 192.168.10.50:22，使用TCP协议，尝试建立SSH连接。目标主机为Windows Vista，该通信对在短时间内多次尝试连接SSH服务，存在暴力破解风险。
[2026-04-18T12:41:52.425461870Z] ssh 源IP 172.16.0.1:46478 通过TCP协议向目标IP 192.168.10.50:22 发起SSH连接请求，目标主机为Windows Vista，该通信对在短时间内多次尝试连接目标主机的SSH服务，存在暴力破解风险。
[2026-04-18T12:41:52.425481604Z] ssh 源IP 172.16.0.1:46486 通过TCP协议向目标IP 192.168.10.50:22 发起SSH连接请求，目标主机为Windows Vista系统，存在SSH服务暴露风险。
[2026-04-18T12:41:52.425500880Z] ssh 源IP 172.16.0.1:46484 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista，该通信对在短时间内多次尝试连接SSH服务，存在暴力破解风险。
[2026-04-18T12:41:52.425510447Z] ssh 源IP 172.16.0.1:46476 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista，该通信对在短时间内多次尝试连接SSH服务，存在暴力破解风险。
[2026-04-18T12:41:52.425492567Z] ssh 源IP 172.16.0.1:46480 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista系统，该通信对在短时间内多次尝试连接SSH服务，存在暴力破解风险。
[2026-04-18T12:41:52.426795262Z] ssh 源IP 172.16.0.1:46474 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista，该通信对在短时间内多次尝试连接SSH服务，存在暴力破解风险。
[2026-04-18T12:41:52.438489841Z] ssh 源IP 172.16.0.1:46472 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista系统，该通信对在短时间内多次尝试连接SSH服务，存在暴力破解风险。
[2026-04-18T12:41:52.456807088Z] ssh 源IP 172.16.0.1:46470 → 目标IP 192.168.10.50:22，使用TCP协议发起SSH连接请求，目标主机为Windows Vista系统，该通信对在短时间内多次重复出现，存在暴力破解风险。
[2026-04-18T12:41:52.456817363Z] ssh 源IP 172.16.0.1:46468 通过TCP协议向目标IP 192.168.10.50:22 发起SSH连接请求，目标主机为Windows Vista，该通信对在短时间内多次尝试连接SSH服务，存在暴力破解风险。
```

## Case B: GlobalMem Collapse vs. Non-Collapse Comparison

- Status: `已选中`

### Collapsed or Low-Score Experimental Run

- Experimental run: `fair_n2`
- Memory condition: `GlobalMem`
- Binary F1: `0.0`
- SSH F1: `0.0`
- Confusion matrix computed from `joined_data`: `{'tp': 0, 'fp': 268, 'tn': 5828, 'fn': 592}`
- Confusion matrix recorded in metrics.json: `{'tp': 0, 'fp': 268, 'tn': 5828, 'fn': 592}`
- Predicted threat-level distribution: `{'低': 3, '无危': 6417, '高': 268}`

#### First SSH False Negative

- Timestamp: `2026-04-17T10:28:18.925780489Z`
- Event type: `ssh`
- Communication pair: `172.16.0.1 <-> 192.168.10.50`
- Ground-truth label: `SSH-Patator`
- Threat level: `无危`
- Summary: 源主机172.16.0.1:46366通过TCP协议向目标主机Windows Vista (192.168.10.50):22发起SSH连接，但无具体行为记录，未检测到明确恶意行为。

#### First False Positive

- Timestamp: `2026-04-17T10:27:40.272578848Z`
- Event type: `alert`
- Communication pair: `192.168.10.3 <-> 192.168.10.9`
- Ground-truth label: `BENIGN`
- Threat level: `高`
- Summary: 源主机192.168.10.9:51111通过UDP协议向目标主机192.168.10.3:53发起DNS查询，疑似查询*.pw域名，可能为恶意域名解析行为。

### Non-Collapsed Control Experimental Run

- Experimental run: `fair_n3`
- Memory condition: `GlobalMem`
- Binary F1: `0.5901116427432217`
- SSH F1: `0.7385`
- Confusion matrix computed from `joined_data`: `{'tp': 370, 'fp': 313, 'tn': 5559, 'fn': 201}`
- Confusion matrix recorded in metrics.json: `{'tp': 370, 'fp': 313, 'tn': 5559, 'fn': 201}`
- Predicted threat-level distribution: `{'中': 91, '低': 157, '无危': 5603, '高': 592}`

#### First SSH False Negative

- Timestamp: `2026-04-18T20:19:00.429612855Z`
- Event type: `ssh`
- Communication pair: `172.16.0.1 <-> 192.168.10.50`
- Ground-truth label: `SSH-Patator`
- Threat level: `无危`
- Summary: 源主机Ubuntu 32位(192.168.10.8):53124通过TCP协议向目标主机Windows Vista(192.168.10.50):22发起SSH连接，使用SSH协议进行通信，未识别具体应用层行为特征。

#### First False Positive

- Timestamp: `2026-04-18T20:17:27.563664328Z`
- Event type: `smb`
- Communication pair: `192.168.10.25 <-> 192.168.10.50`
- Ground-truth label: `BENIGN`
- Threat level: `中`
- Summary: Mac OS (192.168.10.25):49520 通过 TCP 协议向 Windows Vista (192.168.10.50):139 发起 SMB 连接，使用 139 端口进行通信，行为模式重复且密集，可能为文件共享或目录访问行为。

#### First True Positive

- Timestamp: `2026-04-18T20:19:00.726361020Z`
- Event type: `ssh`
- Communication pair: `172.16.0.1 <-> 192.168.10.50`
- Ground-truth label: `SSH-Patator`
- Threat level: `中`
- Summary: 源IP 172.16.0.1:46728通过TCP协议向目标主机Windows Vista (192.168.10.50):22发起SSH连接，使用SSH协议进行通信，未识别具体应用层行为特征。
