import frida
try:
    device = frida.get_usb_device()
    processes = device.enumerate_processes()
    for p in processes:
        if "diva" in p.name.lower():
            print(f"FOUND: {p.pid} - {p.name}")
except Exception as e:
    print(f"ERROR: {e}")
