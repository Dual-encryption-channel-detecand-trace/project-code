import os
from pathlib import Path
import json
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from scapy.all import rdpcap, IP, TCP, UDP
from itertools import groupby

# ----------- 特征提取脚本 -----------
def entropy(data):
    if data.size == 0:
        return 0.0
    probs = np.bincount(data) / data.size
    probs = probs[probs > 0]
    return -np.sum(probs * np.log2(probs))

def extract_obfs_features(pcap_file):
    pkts = rdpcap(str(pcap_file))
    flows = {}
    for pkt in pkts:
        if IP not in pkt:
            continue
        if not (TCP in pkt or UDP in pkt):
            continue

        ip_layer = pkt[IP]
        l4_layer = pkt[TCP] if TCP in pkt else pkt[UDP]

        src = (ip_layer.src, l4_layer.sport)
        dst = (ip_layer.dst, l4_layer.dport)
        flow_key = tuple(sorted([src, dst]))

        if flow_key not in flows:
            flows[flow_key] = {
                'directions': [],
                'timestamps': [],
                'payload_bytes': bytearray(),
                'pkt_lengths': []
            }

        direction = 1 if src == flow_key[0] else 0
        flows[flow_key]['directions'].append(direction)
        flows[flow_key]['timestamps'].append(pkt.time)

        raw_load = bytes(l4_layer.payload)
        flows[flow_key]['payload_bytes'].extend(raw_load)

        pkt_len = len(raw_load)
        flows[flow_key]['pkt_lengths'].append(pkt_len)

    features = []
    for data in flows.values():
        directions = data['directions']
        timestamps = list(map(float, data['timestamps']))
        payload_bytes = np.frombuffer(data['payload_bytes'], dtype=np.uint8)
        pkt_lengths = data['pkt_lengths']

        load_entropy = entropy(payload_bytes)
        max_single_dir_len = max((len(list(g)) for _, g in groupby(directions)), default=0)
        inter_arrival_mean = np.mean(np.diff(timestamps)) if len(timestamps) > 1 else 0.0
        pkt_len_min = np.min(pkt_lengths) if pkt_lengths else 0
        pkt_len_max = np.max(pkt_lengths) if pkt_lengths else 0
        pkt_len_mean = np.mean(pkt_lengths) if pkt_lengths else 0
        pkt_len_std = np.std(pkt_lengths) if pkt_lengths else 0
        pkt_count = len(directions)
        total_payload_bytes = len(payload_bytes)

        feat_vec = [
            load_entropy,
            max_single_dir_len,
            inter_arrival_mean,
            pkt_count,
            total_payload_bytes,
            pkt_len_min,
            pkt_len_max,
            pkt_len_mean,
            pkt_len_std,
        ]

        features.append(feat_vec)

    # 这里取前10个flows的特征（不够补零）
    max_flows = 10
    if len(features) < max_flows:
        features.extend([[0]*9]*(max_flows - len(features)))
    else:
        features = features[:max_flows]

    return np.array(features, dtype=np.float32)  # shape (10, 9)

# ----------- Dataset -----------
class FlowDataset(Dataset):
    def __init__(self, files, labels):
        self.files = files
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        feats = extract_obfs_features(self.files[idx])  # (10,9)
        return torch.tensor(feats, dtype=torch.float32), torch.tensor(self.labels[idx], dtype=torch.long)

# ----------- CNN 模型 -----------
class ObfsCNNClassifier(nn.Module):
    def __init__(self, input_dim=9, seq_len=10, num_classes=2):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv1d(input_dim, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.MaxPool1d(2),  # 10->5

            nn.Conv1d(64, 128, 3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.MaxPool1d(2),  # 5->2

            nn.Conv1d(128, 256, 3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(256 * 2, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, num_classes),
        )

    def forward(self, x):
        # x shape (batch, seq_len, input_dim)
        x = x.permute(0, 2, 1)  # (batch, input_dim, seq_len)
        x = self.features(x)
        x = self.classifier(x)
        return x

# ----------- 训练和评估 -----------

def load_data_and_labels(data_root):
    """
    遍历obfs和normal目录，收集pcap文件和标签
    """
    obfs_dir = Path(data_root) / "obfs"
    normal_dir = Path(data_root) / "normal"

    obfs_files = list(obfs_dir.glob("*.pcap"))
    normal_files = list(normal_dir.glob("*.pcap"))

    files = obfs_files + normal_files
    labels = [1]*len(obfs_files) + [0]*len(normal_files)
    return files, labels

def train(model, train_loader, device, epochs=20, lr=1e-3):
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)
    model.train()
    for epoch in range(epochs):
        total_loss = 0
        for x, y in train_loader:
            x, y = x.to(device), y.to(device)
            optimizer.zero_grad()
            out = model(x)
            loss = criterion(out, y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"Epoch {epoch+1}/{epochs} loss: {total_loss/len(train_loader):.4f}")

def evaluate(model, val_loader, device):
    model.eval()
    total, correct = 0, 0
    with torch.no_grad():
        for x, y in val_loader:
            x, y = x.to(device), y.to(device)
            out = model(x)
            pred = out.argmax(dim=1)
            total += y.size(0)
            correct += (pred == y).sum().item()
    acc = correct/total
    print(f"Validation Accuracy: {acc:.2%}")
    return acc

# ----------- 检测新文件 -----------

def predict_single_pcap(model, pcap_file, device):
    model.eval()
    feats = extract_obfs_features(pcap_file)
    x = torch.tensor(feats, dtype=torch.float32).unsqueeze(0).to(device)  # (1,10,9)
    with torch.no_grad():
        out = model(x)
        probs = torch.softmax(out, dim=1)
        pred_label = probs.argmax(dim=1).item()
        pred_prob = probs[0, pred_label].item()
    return pred_label, pred_prob

def detect_on_directory(model, target_dir, device):
    pcap_files = list(Path(target_dir).glob("*.pcap"))
    print(f"检测目录: {target_dir} ，共{len(pcap_files)}个pcap文件")
    result={}
    for f in pcap_files:
        label, prob = predict_single_pcap(model, f, device)
        label_name = "obfs" if label == 1 else "normal"
        result[f.name]=(label_name,prob)
    return result

def main():
    # device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    # data_root = "D:/pcap" 

    # files, labels = load_data_and_labels(data_root)

    # # 划分训练和验证（8:2）
    # from sklearn.model_selection import train_test_split
    # train_files, val_files, train_labels, val_labels = train_test_split(files, labels, test_size=0.2, random_state=42)

    # train_dataset = FlowDataset(train_files, train_labels)
    # val_dataset = FlowDataset(val_files, val_labels)

    # train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True, num_workers=4)
    # val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False, num_workers=4)

    # model = ObfsCNNClassifier().to(device)

    # train(model, train_loader, device, epochs=20)
    # evaluate(model, val_loader, device)

    # # 模型保存
    # torch.save(model.state_dict(), "obfs_cnn_model.pth")
    # print("Model saved as obfs_cnn_model.pth")

    # model = ObfsCNNClassifier().to("cpu")
    # model.load_state_dict(torch.load("D:\DTDEC\project-code\code\module\obfs_cnn_model.pth", map_location="cpu"))
    # rresult=detect_on_directory(model,r'D:\DTDEC\obfs_1c1g_2020-06-25_00_01_03.016746.pcap','cpu')
    # print(rresult)

    # detect_on_directory(model, "D:/pcap/target", "cuda")


    pass

if __name__ == "__main__":
    model = ObfsCNNClassifier().to("cpu")
    model.load_state_dict(torch.load("D:\DTDEC\project-code\code\module\obfs_cnn_model.pth", map_location="cpu"))
    rresult=detect_on_directory(model,r'D:\pcap\temporary\testobfss','cpu')
    print(rresult)
    # rresult=list(rresult)
    # rresult=list(map(lambda x:x[0],rresult))
    # print('obfs'in rresult)
