import torch
import torch.nn as nn
import torch.optim as optim
from .extractTlsFeatures import extract_tls_features as tlsft
from torch.utils.data import Dataset, DataLoader
from pathlib import Path
import json
import os
import numpy as np

curdir = Path(__file__).resolve().parent
pcapdir = "D:/pcap"
pcapdir = Path(pcapdir)
train_dirs = [
    "tormeek",
    "normal",
]
detect_files =list(map(lambda x: pcapdir / Path("target") / x, os.listdir(pcapdir / Path("target"))))
pth_file = "tls_classifier_model.pth"

train_dirs = list(map(lambda x: pcapdir / Path(x), train_dirs))
train_files = list(map(lambda x: list(map(lambda y: x / Path(y), os.listdir(x))), train_dirs))
train_labels = [1] * len(train_files[0]) + [0] * len(train_files[1])
train_files = train_files[0] + train_files[1]

pth_file = curdir / Path(pth_file)

def np2list(npobj):
    if type(npobj)==np.float32:
        return float(npobj)
    npobj=list(map(lambda x:np2list(x),npobj))
    return npobj

class TLSClassifier(nn.Module):
    """
    基于 CNN 和 LSTM 的混合模型，用于流量分类
    """
    def __init__(self, input_dim=34, seq_len=10, cnn_channels=64, lstm_hidden=128, num_classes=2):
        super(TLSClassifier, self).__init__()
        self.seq_len = seq_len

        # CNN 部分
        self.cnn = nn.Sequential(
            nn.Conv1d(in_channels=1, out_channels=cnn_channels, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2),
            nn.Conv1d(in_channels=cnn_channels, out_channels=cnn_channels, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2)
        )

        # LSTM 部分
        self.lstm = nn.LSTM(
            input_size=cnn_channels,
            hidden_size=lstm_hidden,
            num_layers=2,
            bidirectional=True,
            batch_first=True
        )

        # 全连接层
        self.fc = nn.Sequential(
            nn.Linear(lstm_hidden * 2, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        # 输入形状: (batch_size, seq_len, input_dim)
        batch_size = x.size(0)
        x = x.view(batch_size, 1, -1)  # 调整为 (batch_size, 1, seq_len * input_dim)

        # CNN 部分
        cnn_out = self.cnn(x)  # 输出形状: (batch_size, cnn_channels, reduced_seq_len)

        # 调整为 LSTM 输入形状
        lstm_input = cnn_out.permute(0, 2, 1)  # 调整为 (batch_size, reduced_seq_len, cnn_channels)

        # LSTM 部分
        lstm_out, _ = self.lstm(lstm_input)  # 输出形状: (batch_size, reduced_seq_len, lstm_hidden * 2)

        # 取最后一个时间步的输出
        final_output = lstm_out[:, -1, :]  # 输出形状: (batch_size, lstm_hidden * 2)

        # 全连接层
        return self.fc(final_output)


class TlsCnnModel:
    """
    流量分类模型的封装类，包含训练、验证、预测功能
    """
    def __init__(self, model_path=pth_file, input_dim=34, seq_len=10):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")
        self.model = TLSClassifier(input_dim=input_dim, seq_len=seq_len).to(self.device)
        self.model_path = model_path

    def extract_features(self, pcap_files, labels=None):
        """
        提取特征并返回特征和标签
        :param pcap_files: PCAP 文件列表
        :param labels: 标签列表（可选）
        :return: 特征和标签（如果提供标签）
        """
        pcap_len=[]
        print(f"Start extracting TLS features...")
        features = []
        valid_labels = [] if labels is not None else None  # 用于存储与特征匹配的标签

        for idx, file in enumerate(pcap_files):
            label = labels[idx] if labels is not None else None

            if label != None :
                feat_file=Path(file).parent.parent/"features"/("tormeek" if label==1 else "normal")/(str(Path(file).stem)+".json")
                if feat_file.is_file():
                    with open(feat_file,'r') as f:
                        feats = json.load(f)
                else:
                    with open(feat_file,'w') as f:
                        feats = tlsft(file)
                        json.dump(np2list(feats),f)
                feats=np.array(feats,dtype=np.float32)
            else:
                feats = tlsft(file)
            if feats is not None and len(feats) > 0:
                for feat in feats:
                    features.append(feat)  # 只存储特征
                    if labels is not None:
                        valid_labels.append(label)  # 添加对应的标签
            else:
                print(f"No valid features extracted from {file}. Filling with zeros.")
                max_length = 34
                features.append([0] * max_length)  # 添加全零特征向量
                if labels is not None:
                    valid_labels.append(label)
            pcap_len.append(len(feats))

        # 检查特征和标签数量是否一致
        if labels is not None and len(features) != len(valid_labels):
            raise ValueError(f"Mismatch between features and labels: {len(features)} features, {len(valid_labels)} labels.")

        print(f"Features extraction completed. Total samples: {len(features)}")
        if labels is not None:
            return np.array(features, dtype=np.float32), np.array(valid_labels, dtype=np.int64), pcap_len
        return np.array(features, dtype=np.float32), pcap_len

    def train(self, features, labels, epochs=20, batch_size=32, learning_rate=1e-3):
        """
        训练模型
        :param features: 特征数组
        :param labels: 标签数组
        """
        # 数据加载
        dataset = FlowDataset(features, labels)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True, num_workers=4)

        # 损失函数和优化器
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=5, gamma=0.5)

        for epoch in range(epochs):
            self.model.train()
            total_loss = 0.0

            for batch_features, batch_labels in dataloader:
                batch_features, batch_labels = batch_features.to(self.device), batch_labels.to(self.device)

                # 前向传播
                outputs = self.model(batch_features)
                loss = criterion(outputs, batch_labels)

                # 反向传播与优化
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

                total_loss += loss.item()

            scheduler.step()
            print(f"Epoch {epoch + 1}/{epochs}, Loss: {total_loss / len(dataloader):.4f}")

        # 保存模型
        torch.save(self.model.state_dict(), self.model_path)
        print(f"Model saved to {self.model_path}")

    def evaluate(self, features, labels, batch_size=32):
        """
        评估模型
        :param features: 特征数组
        :param labels: 标签数组
        """
        dataset = FlowDataset(features, labels)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

        self.model.eval()
        correct = 0
        total = 0

        with torch.no_grad():
            for batch_features, batch_labels in dataloader:
                batch_features, batch_labels = batch_features.to(self.device), batch_labels.to(self.device)
                outputs = self.model(batch_features)
                _, predicted = torch.max(outputs, 1)
                total += batch_labels.size(0)
                correct += (predicted == batch_labels).sum().item()

        accuracy = correct / total
        print(f"Evaluation Accuracy: {accuracy:.2%}")
        return accuracy

    def detect(self, pcap_files, batch_size=32):
        """
        使用训练好的模型对新的 PCAP 文件进行检测
        :param pcap_files: PCAP 文件列表
        :param batch_size: 批量大小
        :return: 每个文件的预测结果
        """
        print("Start detecting...")
        # 提取特征
        features ,pcap_len = self.extract_features(pcap_files)

        # 数据加载
        dataset = FlowDataset(features, labels=np.zeros(len(features)))  # 标签在检测时不需要
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

        # 加载模型
        self.model.load_state_dict(torch.load(self.model_path,map_location=self.device))
        self.model.eval()

        predictions = []
        with torch.no_grad():
            for batch_features, _ in dataloader:
                batch_features = batch_features.to(self.device)
                outputs = self.model(batch_features)
                _, predicted = torch.max(outputs, 1)
                predictions.extend(predicted.cpu().numpy())

        print(f"Detection completed. Total files detected: {len(pcap_files)}")
        return predictions, pcap_len


class FlowDataset(Dataset):
    """
    数据集类，用于加载特征和标签
    """
    def __init__(self, features, labels):
        """
        初始化数据集
        :param features: 特征数组
        :param labels: 标签数组
        """
        self.features = features
        self.labels = labels.astype(np.int64)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return (
            torch.tensor(self.features[idx], dtype=torch.float32),
            torch.tensor(self.labels[idx], dtype=torch.long)
        )

if __name__ == "__main__":
    myAI = TlsCnnModel()
    # 提取特征和标签
    features, labels, pcap_len = myAI.extract_features(train_files, train_labels)

    # 检查特征和标签
    print(f"Features shape: {features.shape}")
    print(f"Labels distribution: {np.bincount(labels)}")

    # 训练模型
    myAI.train(features, labels, epochs=20)

    # 评估模型
    accuracy = myAI.evaluate(features, labels)
    print(f"Training Accuracy: {accuracy:.2%}")

    # 检测新文件
    predictions = myAI.detect(detect_files)
    for file, pred in zip(detect_files, predictions):
        print(f"File: {file}, Prediction: {pred}")