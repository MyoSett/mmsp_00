import socket
import threading

# Settings
HOST = '127.0.0.1'  # localhost for testing
PORT = int(input("Enter your listening port: "))

# ========== Server Thread ==========
def listen_for_messages():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"🟢 Listening on port {PORT}...\n")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_peer, args=(conn, addr), daemon=True).start()

def handle_peer(conn, addr):
    while True:
        try:
            message = conn.recv(1024).decode()
            if not message:
                break
            print(f"\n👤 {addr[1]} says: {message}")
        except:
            break
    conn.close()

# ========== Client Sending ==========
def send_message():
    try:
        target_port = int(input("Enter peer's port: "))
        message = input("Your message: ")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, target_port))
        client.send(message.encode())
        client.close()
        print("✅ Message sent.")
    except ValueError:
        print("⚠ Invalid port. Please enter a number.")
    except Exception as e:
        print(f"❌ Error: {e}")

# ========== Menu ==========
def main_menu():
    while True:
        print("\n=== Main Menu ===")
        print("1. Send Message")
        print("2. Quit")
        choice = input("Select an option (1/2): ")

        if choice == '1':
            send_message()
        elif choice == '2':
            print("👋 Exiting chat. Goodbye!")
            break
        else:
            print("⚠ Invalid option. Please choose 1 or 2.")

# ========== Main ==========
if __name__ == "__main__":
    threading.Thread(target=listen_for_messages, daemon=True).start()
    main_menu()
