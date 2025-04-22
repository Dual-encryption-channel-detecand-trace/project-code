import numpy as np
import pyshark
import json
import os

def extract_tls_features(input_file, label):
    """
    提取 TLS ClientHello 特征，包括版本、密码套件列表、扩展类型列表和服务器名称等。
    """
    features = []
    try:
        cap = pyshark.FileCapture(
            input_file=input_file,
            display_filter="tls.handshake.type == 1",
            use_ek=True,
        )
        
        f = open("fliteredservername.json", "r")
        strjson = f.read()
        f.close()
        for packet in cap:
            try:
                tls = packet.tls
                # 提取特征
                version = tls.handshake.version if hasattr(tls.handshake, "version") else 0
                cipher_suites = tls.handshake.ciphersuite if hasattr(tls.handshake, "ciphersuite") else []
                cipher_suites_num = len(cipher_suites)
                extensions = tls.handshake.extension.type if hasattr(tls.handshake, "extension") else []
                extensions_num = len(extensions)
                checkdomain = json.loads(strjson)
                servername = 0  # 默认值
                if label == 1:
                    for p in cap:
                        try:
                            if p.tls.handshake.extensions.server.name.value in checkdomain:
                                servername = 1
                                break  # 找到一个匹配的即可
                        except AttributeError:
                            continue
                # 将密码套件和扩展类型转换为数值特征
                cipher_suites_encoded = [cs for cs in cipher_suites]
                extensions_encoded = [ext for ext in extensions]

                # 构造特征向量
                feature_vector = [
                    version,  # ClientHello 版本
                    cipher_suites_num,  # 密码套件数量
                    extensions_num,  # extension数量
                    servername, #使用伪造的服务器
                ]

                # 将密码套件和扩展类型加入特征向量
                feature_vector.extend(cipher_suites_encoded[:19])  # 只取前19个密码套件
                feature_vector.extend(extensions_encoded[:11])  # 只取前11个扩展类型

                # 填充或截断特征向量到固定长度
                max_length = 34  # 假设固定长度为34
                if len(feature_vector) < max_length:
                    feature_vector.extend([0] * (max_length - len(feature_vector)))
                else:
                    feature_vector = feature_vector[:max_length]

                features.append(feature_vector)
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
        cap.close()
        print(f"Features extracted successfully from {input_file}")
    except Exception as e:
        print(f"Error reading pcap file: {e}")

    # 如果没有提取到任何特征，则返回一个全零填充的特征向量
    if len(features) == 0:
        print(f"No features extracted from {input_file}. Filling with zeros.")
        max_length = 34  # 假设固定长度为34
        features.append([0] * max_length)  # 添加全零特征向量

    return np.array(features, dtype=np.float32)

if __name__=="__main__":
    pass