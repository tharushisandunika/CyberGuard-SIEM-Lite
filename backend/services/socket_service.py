# Global reference to SocketIO instance to avoid circular imports
_socketio = None

def init_socketio(socketio_instance):
    global _socketio
    _socketio = socketio_instance
    print("[+] SocketIO Service helper initialized.")

def emit_log(log_data):
    global _socketio
    if _socketio:
        try:
            # Emit new log event to all connected clients
            _socketio.emit('new_log', log_data)
        except Exception as e:
            print(f"[-] Failed to emit log websocket event: {e}")

def emit_alert(alert_data):
    global _socketio
    if _socketio:
        try:
            # Emit new alert event to all connected clients
            _socketio.emit('new_alert', alert_data)
        except Exception as e:
            print(f"[-] Failed to emit alert websocket event: {e}")
