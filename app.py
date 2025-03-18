import json
from extractTlsFeatures import extract_tls_features as tlsft
# from mysniffer import pktsniff
from TlsCnnModel import TlsCnnModel
import os

# def Predict(predictAI,filedir):
#     # 批量预测
#     # filedir=""                  #不想输入可以直接在这里写文件名
#     files=pcapFilter(filedir)
#     predictAI.detect_traffic(files)

def showfeatures(pcap_file):
    """
    展示特征
    """
    features=tlsft(pcap_file)
    print(features)


def terminal_ver(predictAI):
    """
    控制台版本
    仅功能展示用
    仅提供逐条预测
    """
    
    while 1:
        print("输入待检测文件名:")
        pcap_file=input()
        if os.path.isdir(pcap_file):
            print("这是一个文件夹！")
            continue
        elif os.path.splitext(pcap_file)[1]!=".pcap": 
            print("请输入一个pcap文件！")
            continue
        predict_result=predictAI.detect_traffic(pcap_file)
        print("Detection Results:", predict_result)

load_file=".\\tls_classifier_model.pth"                           #[filepath]
# load_file="D:\\DTDEC\\catch\\tls_classifier_model.pth"
if __name__=="__main__":
    predictAI=TlsCnnModel(load_file=load_file)
    print("导入训练结果成功")
    terminal_ver(predictAI)