import socket
import threading
import json
import sys
import time
from crypto_utils import generate_keys, serialize_public_key, load_public_key, encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 9999

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = ""
        self.private_key = None
        self.public_key = None
        self.peers = {} # {username: public_key_obj}
        self.running = True

    def start(self):
        print("=== 安全加密聊天系统 (Secure Chat) ===")
        self.username = input("请输入你的用户名: ").strip()
        if not self.username:
            print("用户名不能为空")
            return

        print("正在生成 RSA 密钥对，请稍候...")
        self.private_key, self.public_key = generate_keys()
        print("密钥生成完毕。")

        try:
            self.sock.connect((HOST, PORT))
        except ConnectionRefusedError:
            print("无法连接到服务器，请确保服务器已启动。")
            return

        # 启动接收线程
        recv_thread = threading.Thread(target=self.receive_loop)
        recv_thread.daemon = True
        recv_thread.start()

        # 发送上线广播
        self.broadcast_presence(request_keys=True)

        print(f"已连接。你可以输入 '@用户名 消息' 进行私密聊天。")
        print("输入 '/list' 查看在线用户。输入 '/quit' 退出。")

        self.input_loop()

    def broadcast_presence(self, request_keys=False):
        """广播自己的存在和公钥"""
        pub_pem = serialize_public_key(self.public_key).decode('utf-8')
        msg = {
            "type": "announce",
            "username": self.username,
            "pubkey": pub_pem,
            "request_keys": request_keys
        }
        self.send_json(msg)

    def send_json(self, data):
        try:
            msg = json.dumps(data) + '\n'
            self.sock.sendall(msg.encode('utf-8'))
        except Exception as e:
            print(f"[Send Error] {e}")

    def receive_loop(self):
        buffer = ""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("\n[系统] 与服务器断开连接。")
                    self.running = False
                    break
                
                buffer += data.decode('utf-8')
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        self.handle_message(json.loads(line))
            except Exception as e:
                if self.running:
                    print(f"\n[Receive Error] {e}")
                break

    def handle_message(self, msg):
        msg_type = msg.get("type")
        sender = msg.get("username")

        if sender == self.username:
            return # 忽略自己的消息

        if msg_type == "announce":
            # 保存对方公钥
            try:
                pub_key = load_public_key(msg["pubkey"].encode('utf-8'))
                self.peers[sender] = pub_key
                print(f"\n[系统] 用户 '{sender}' 上线了。")
                
                # 如果对方请求交换密钥，我也广播一下（但不请求对方回复，避免循环）
                if msg.get("request_keys"):
                    self.broadcast_presence(request_keys=False)
            except Exception as e:
                print(f"[Error] 无法加载用户 {sender} 的公钥: {e}")

        elif msg_type == "chat":
            target = msg.get("target")
            if target == self.username:
                # 给我的加密消息
                content = msg.get("content")
                decrypted = decrypt_message(content, self.private_key)
                print(f"\n[{sender} (私密)]: {decrypted}")
                print("> ", end="", flush=True)

    def input_loop(self):
        while self.running:
            try:
                text = input("> ")
                if not text:
                    continue

                if text == "/quit":
                    self.running = False
                    self.sock.close()
                    break
                
                if text == "/list":
                    print("在线用户:", list(self.peers.keys()))
                    continue

                if text.startswith("@"):
                    # 私聊格式: @User Message
                    parts = text.split(' ', 1)
                    if len(parts) < 2:
                        print("格式错误。使用: @用户名 消息内容")
                        continue
                    
                    target_user = parts[0][1:]
                    message_content = parts[1]

                    if target_user not in self.peers:
                        print(f"未找到用户 '{target_user}'。请等待对方上线或检查拼写。")
                        continue

                    # 加密发送
                    encrypted_package = encrypt_message(message_content, self.peers[target_user])
                    msg = {
                        "type": "chat",
                        "username": self.username,
                        "target": target_user,
                        "content": encrypted_package
                    }
                    self.send_json(msg)
                    print(f"[发送给 {target_user}]: {message_content}")

                else:
                    print("请指定发送对象。使用: @用户名 消息内容")

            except KeyboardInterrupt:
                self.running = False
                self.sock.close()
                break

if __name__ == "__main__":
    client = ChatClient()
    client.start()
