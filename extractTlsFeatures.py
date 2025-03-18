import numpy as np
import pyshark
import os

def extract_tls_features(input_file):
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
            # tshark_path="D:\\Program Files\\Wireshark\\tshark.exe",        #我这里需要设置这个    #[filepath]
        )
        for packet in cap:
            try:
                tls = packet.tls
                # 提取特征
                # version = int(tls.handshake.version, 16) if hasattr(tls.handshake, "version") else 0
                version = tls.handshake.version if hasattr(tls.handshake, "version") else 0    #我这里本来就是 int类型
                cipher_suites = tls.handshake.ciphersuite if hasattr(tls.handshake, "ciphersuite") else []
                cipher_suites_num = len(cipher_suites)
                extensions = tls.handshake.extension.type if hasattr(tls.handshake, "extension") else []
                extensions_num = len(extensions)
                server_name = tls.handshake.extensions.server_name if hasattr(tls.handshake.extensions, "server_name") else ""
                # 将密码套件和扩展类型转换为数值特征
                # cipher_suites_encoded = [int(cs, 16) for cs in cipher_suites]
                cipher_suites_encoded = [cs for cs in cipher_suites]                           #同上，本来就是 int类型
                # extensions_encoded = [int(ext, 16) for ext in extensions]
                extensions_encoded = [ext for ext in extensions]                               #同上，本来就是 int类型

                # 构造特征向量
                feature_vector = [
                    version,  # ClientHello 版本
                    cipher_suites_num,  # 密码套件数量
                    extensions_num,  # 扩展数量
                    # len(server_name),  # 服务器名称长度
                    server_name.len,                    #我这里 不是len()是 .len
                ]
                # 将密码套件和扩展类型加入特征向量
                feature_vector.extend(cipher_suites_encoded[:10])  # 只取前10个密码套件
                feature_vector.extend(extensions_encoded[:10])  # 只取前10个扩展类型

                # 填充或截断特征向量到固定长度
                max_length = 25  # 假设固定长度为25
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