from datetime import datetime

def log_message(output_text, message, tag="info", timestamp=True):
    if timestamp:
        time_str = datetime.now().strftime("%H:%M:%S")
        output_text.insert("end", f"[{time_str}] ", "info")
    output_text.insert("end", message + "\n", tag)
    output_text.see("end")
