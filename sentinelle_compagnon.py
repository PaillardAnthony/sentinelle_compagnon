import sys
import json
import struct
import os
import zipfile

def get_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        sys.exit(0)
    message_length = struct.unpack('@I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def send_message(message_content):
    encoded_content = json.dumps(message_content).encode('utf-8')
    message = struct.pack('@I', len(encoded_content)) + encoded_content
    sys.stdout.buffer.write(message)
    sys.stdout.buffer.flush()

def analyze_file(file_path, config):
    FILE_SIGNATURES = config.get("FILE_SIGNATURES", {})
    DANGEROUS_EXTENSIONS = config.get("SCRIPT_EXTENSIONS", [])

    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(4)
            hex_signature = header_bytes.hex()
            container_type = "unknown"
            for ft, sig in FILE_SIGNATURES.items():
                if hex_signature.startswith(sig):
                    container_type = ft
                    break
        
        if container_type == "zip":
            try:
                with zipfile.ZipFile(file_path, 'r') as archive:
                    for item_info in archive.infolist():
                        if item_info.is_dir(): continue
                        item_name = os.path.basename(item_info.filename)
                        item_ext = item_name.split('.')[-1].lower() if '.' in item_name else ''
                        if item_ext in DANGEROUS_EXTENSIONS:
                            return {"status": "danger", "reason": "executable_in_zip", "details": item_name}
                        with archive.open(item_info.filename) as file_in_zip:
                            item_header_bytes = file_in_zip.read(4)
                            item_hex_sig = item_header_bytes.hex()
                            actual_item_type = "unknown"
                            for ft, sig in FILE_SIGNATURES.items():
                                if item_hex_sig.startswith(sig):
                                    actual_item_type = ft
                                    break
                            if item_ext in FILE_SIGNATURES and actual_item_type != "unknown" and actual_item_type != item_ext:
                                return {"status": "danger", "reason": "mismatch_in_zip", "details": f"{item_name} (.{item_ext} -> .{actual_item_type})"}
            except zipfile.BadZipFile:
                 return {"status": "warning", "reason": "corrupt_zip", "details": os.path.basename(file_path)}

        return {"status": "success", "detected_type": container_type}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def delete_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return {"status": "success"}
        else:
            return {"status": "error", "message": "File not found for deletion."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def main():
    try:
        received_message = get_message()
        command = received_message.get("command")
        file_path = received_message.get("filePath")
        config = received_message.get("config") # On récupère la config du message

        if command == "ping":
            send_message({"status": "pong", "version": "3.0"})
        elif command == "analyze" and file_path and config:
            send_message(analyze_file(file_path, config))
        elif command == "delete" and file_path:
            send_message(delete_file(file_path))
        else:
            send_message({"status": "error", "message": "Commande, chemin ou config invalide."})

    except Exception as e:
        sys.exit(1)

main()