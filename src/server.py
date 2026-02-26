import socket
import threading
import json

HOST = '0.0.0.0'
PORT = 9999

clients = []
clients_lock = threading.Lock()

def broadcast(message, sender_socket=None):
    """向所有连接的客户端广播消息"""
    with clients_lock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.sendall(message + b'\n')
                except:
                    # 如果发送失败，假设连接断开，稍后清理
                    pass

def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    
    try:
        with clients_lock:
            clients.append(client_socket)

        buffer = ""
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            
            buffer += data.decode('utf-8')
            
            while '\n' in buffer:
                message, buffer = buffer.split('\n', 1)
                if message.strip():
                    print(f"[{addr}] {message}")
                    # 直接广播收到的原始 JSON 消息
                    broadcast(message.encode('utf-8'), client_socket)
                    
    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        client_socket.close()
        print(f"[DISCONNECTED] {addr} disconnected.")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        client_sock, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_sock, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()
