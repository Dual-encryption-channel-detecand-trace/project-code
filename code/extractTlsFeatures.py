import numpy as np
import pyshark
import json
import os

def extract_tls_features(input_file,label):
    """
    提取 TLS ClientHello 特征，包括版本、密码套件列表、扩展类型列表和服务器名称等。
    """
    print("Start extracting TLS features...")
    features = []
    try:
        cap = pyshark.FileCapture(
            input_file=input_file,
            display_filter="tls.handshake.type == 1",
            use_ek=True,
        )

        capx=[]
        # f=open(".\\fliteredservername.json","r")
        f=open("%s\\..\\fliteredservername.json"%__file__,"r")
        strjson=f.read()
        f.close()
        checkdomain=json.loads(strjson)
        if label==1:
            for p in cap:
                if p.tls.handshake.extensions.server.name.value in checkdomain:
                    capx.append(p)
        else:
            capx=cap
            
        for packet in capx:
            try:
                tls = packet.tls
                # 提取特征
                version = tls.handshake.version if hasattr(tls.handshake, "version") else 0
                cipher_suites = tls.handshake.ciphersuite if hasattr(tls.handshake, "ciphersuite") else []
                cipher_suites_num = len(cipher_suites)
                extensions = tls.handshake.extension.type if hasattr(tls.handshake, "extension") else []
                extensions_num = len(extensions)
                # 将密码套件和扩展类型转换为数值特征
                cipher_suites_encoded = [cs for cs in cipher_suites]
                extensions_encoded = [ext for ext in extensions]

                # 构造特征向量
                feature_vector = [
                    version,  # ClientHello 版本
                    cipher_suites_num,  # 密码套件数量
                    extensions_num,  #extension数量
                ]
                # 将密码套件和扩展类型加入特征向量
                feature_vector.extend(cipher_suites_encoded[:18])  # 只取前18个密码套件
                feature_vector.extend(extensions_encoded[:11])  # 只取前11个扩展类型

                # 填充或截断特征向量到固定长度
                max_length = 42  # 假设固定长度为42
                if len(feature_vector) < max_length:
                    feature_vector.extend([0] * (max_length - len(feature_vector)))
                else:
                    feature_vector = feature_vector[:max_length]

                features.append(feature_vector)
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
        cap.close()
    except Exception as e:
        print(f"Error reading pcap file: {e}")
    
    print("Finish extracting TLS features.")
    
    return np.array(features, dtype=np.float32)

if __name__=="__main__":
    pass