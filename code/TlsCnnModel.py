import torch
import torch.nn as nn
import torch.optim as optim
from extractTlsFeatures import extract_tls_features as tlsft
from torch.utils.data import Dataset, DataLoader
from pathlib import Path
import os

curdir = Path(__file__).resolve().parent
pcapdir="D:\\pcap"
pcapdir = Path(pcapdir)
train_dirs = [
    "tormeek",
    "normal",
]
detect_file = "meek_1c1g_2020-05-27_04_37_07.836652.pcap"
pth_file = "tls_classifier_model.pth"

train_dirs = list(map(lambda x:pcapdir/Path(x),train_dirs))
train_files = list(map( lambda x: list(map(lambda y: x/Path(y), os.listdir(x))) ,train_dirs))
train_labels = [1]*len(train_files[0]) + [0]*len(train_files[1])
train_files = train_files[0]+train_files[1]

# detect_file = pcapdir/Path(detect_file)
pth_file = curdir/Path(pth_file)

class FlowDataset(Dataset):
    def __init__(self, pcap_files, labels):
        """
        pcap_files: 包含正负样本路径的列表
        labels: 对应的标签列表 (0/1)
        """
        self.features = []
        self.labels = []
        for file, label in zip(pcap_files, labels):
            feats = tlsft(file,label)
            self.features.extend(feats)
            self.labels.extend([label] * len(feats))

    def __len__(self):
        return len(self.features)

    def __getitem__(self, idx):
        return (
            torch.tensor(self.features[idx], dtype=torch.float32),
            torch.tensor(self.labels[idx], dtype=torch.long)
        )

class TLSClassifier(nn.Module):
    def __init__(self):
        super(TLSClassifier, self).__init__()
        self.fc_layers = nn.Sequential(
            nn.Linear(25, 64),  # 输入特征为 25
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(64, 2)  # 输出为 2 类
        )

    def forward(self, x):
        return self.fc_layers(x)

class TlsCnnModel:
    initial_file=pth_file
    def __init__(self,load_file=None,load=False):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")
        # 初始化模型
        self.model = TLSClassifier().to(self.device)
        if load or load_file!=None:
            if load_file!=None:
                self.model.load_state_dict(torch.load(load_file))
                print(load_file)
            else :
                self.model.load_state_dict(torch.load(TlsCnnModel.initial_file))

    def train_model(self,train_files, train_labels, epochs=10, batch_size=16,load_file=None,save_file=None):
        """
        模型训练函数
        输入pcap文件list
        """
        # 导入pcap数据
        print(train_files)
        dataset = FlowDataset(train_files, train_labels)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        print("Dataset loaded successfully.")
        
        # 初始化模型
        if load_file!=None:
            self.model.load_state_dict(torch.load(load_file))
        self.model.train()

        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        
        for epoch in range(epochs):
            for batch, labels in dataloader:
                batch, labels = batch.to(self.device), labels.to(self.device)
                
                optimizer.zero_grad()
                outputs = self.model(batch)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()
            
            print(f'Epoch {epoch+1}/{epochs}, Loss: {loss.item()}')
        
        # 保存训练结果
        if save_file!=None:
            torch.save(self.model.state_dict(), save_file)
        elif load_file==None:
            torch.save(self.model.state_dict(), TlsCnnModel.initial_file)
        else:
            torch.save(self.model.state_dict(), save_file)


    def detect_traffic(self,pcap_file,load_file=None):
        """
        预测函数
        输入pcap文件list
        """
        # 导入训练结果
        if load_file != None:
            self.model.load_state_dict(torch.load(load_file))
        self.model.eval()
        
        # 提取预测包特征
        features = tlsft(pcap_file,0)
        inputs = torch.tensor(features, dtype=torch.float32).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(inputs)
            predictions = torch.argmax(outputs, dim=1)
        
        return predictions.cpu().numpy()
    
    def loadmodel(self,load_file=None):
        if load_file!=None:
            torch.save(self.model.state_dict(), load_file)
        else :
            torch.save(self.model.state_dict(), TlsCnnModel.initial_file)
    def savemodel(self,save_file=None):
        if save_file!=None:
            torch.save(self.model.state_dict(), save_file)
        else :
            torch.save(self.model.state_dict(), TlsCnnModel.initial_file)
        

if __name__=="__main__":
    
    detect_file = "meek_1c1g_2020-05-27_04_37_07.836652.pcap"
    myAI=TlsCnnModel()
    
    train_labels=[1,0]
    myAI.train_model(train_files,train_labels,epochs=20)
    # test_result = myAI.detect_traffic(detect_files)                    #[filepath]
    # print("Detection Results:", test_result)