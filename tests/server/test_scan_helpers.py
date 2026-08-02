from aivas.server.scan_helpers import device_type_from_ports


def test_windows_by_rdp():
    assert device_type_from_ports([3389]) == "Windows"


def test_windows_by_smb_rdp():
    assert device_type_from_ports([139, 445, 3389]) == "Windows"


def test_linux_by_ssh_only():
    assert device_type_from_ports([22]) == "Linux"


def test_router_by_telnet_no_ssh():
    assert device_type_from_ports([23, 80]) == "Router"


def test_camera_by_rtsp():
    assert device_type_from_ports([554, 80]) == "Camera"


def test_printer_by_jetdirect():
    assert device_type_from_ports([9100]) == "Printer"


def test_android_adb():
    assert device_type_from_ports([5555]) == "Android"


def test_unknown():
    assert device_type_from_ports([443, 8080]) == "Unknown"
