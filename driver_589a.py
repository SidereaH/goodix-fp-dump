import random
import re
import socket
import struct
import subprocess

import crcmod

import goodix
import protocol
import tool

TARGET_FIRMWARE = "GF_ST589SEC_APP_12117"  # Modified for 589a
IAP_FIRMWARE = "MILAN_ST589SEC_IAP_12101"  # Modified for 589a
VALID_FIRMWARE = "GF_ST589SEC_APP_121[0-9]{2}"  # Modified for 589a

PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH = bytes.fromhex(
    "ba1a86037c1d3c71c3af344955bd69a9a9861d9e911fa24985b677e8dbd72d43")

DEVICE_CONFIG = bytes.fromhex(
    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca000400840015b3860000"
    "c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000"
    "b6980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c008000560004205800030232000c02660003007c000058820080152a0182"
    "032200012024001400800001005c000001560004205800030232000c02660003"
    "007c0000588200801f2a0108005c008000540010016200040364001900660003"
    "007c0001582a0108005c0000015200080054000001660003007c00015800892e")

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 88

def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)
    device.nop()
    device.enable_chip(True)
    device.nop()
    return device

def check_psk(device: goodix.Device):
    success, flags, psk = device.preset_psk_read(0xbb020003)
    if not success:
        raise ValueError("Failed to read PSK")

    if flags != 0xbb020003:
        raise ValueError("Invalid flags")

    print(f"PSK: {psk.hex()}")
    return psk == PMK_HASH

def write_psk(device: goodix.Device):
    if not device.preset_psk_write(0xbb010003, PSK_WHITE_BOX):
        return False

    if not check_psk(device):
        return False

    return True

def erase_firmware(device: goodix.Device):
    device.mcu_erase_app(0, False)
    device.disconnect()

def update_firmware(device: goodix.Device):
    firmware_file = open(f"firmware/589a/{TARGET_FIRMWARE}.bin", "rb")  # Modified path for 589a
    firmware = firmware_file.read()
    firmware_file.close()

    try:
        length = len(firmware)
        for i in range(0, length, 1008):
            if not device.write_firmware(i, firmware[i:i + 1008]):
                raise ValueError("Failed to write firmware")

        if not device.check_firmware(
                0, length,
                crcmod.predefined.mkCrcFun("crc-32-mpeg")(firmware)):
            raise ValueError("Failed to check firmware")

    except Exception as error:
        print(
            tool.warning(
                f"The program went into serious problems while trying to "
                f"update the firmware: {error}"))

        erase_firmware(device)
        raise error

    device.reset(False, True, 20)
    device.disconnect()

def run_driver(device: goodix.Device):
    tls_server = subprocess.Popen([
        "openssl", "s_server", "-nocert", "-psk",
        PSK.hex(), "-port", "4433", "-quiet"
    ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)

    try:
        success, number = device.reset(True, False, 20)
        if not success:
            raise ValueError("Reset failed")
        if number != 2048:
            raise ValueError("Invalid reset number")

        if device.read_sensor_register(0x0000, 4) != b"\xa2\x04\x25\x00":
            raise ValueError("Invalid chip ID")

        otp = device.read_otp()
        if len(otp) < 64:
            raise ValueError("Invalid OTP")

        if ~crcmod.predefined.mkCrcFun("crc-8")(otp[0:11] +
                                                otp[36:40]) & 0xff != otp[60]:
            raise ValueError("Invalid OTP CP data checksum")

        if ~crcmod.predefined.mkCrcFun("crc-8")(otp[20:28] + otp[29:36] +
                                                otp[40:50] +
                                                otp[54:56]) & 0xff != otp[63]:
            raise ValueError("Invalid OTP MT data checksum")

        if ~crcmod.predefined.mkCrcFun("crc-8")(otp[11:20] + otp[28:29] +
                                                otp[50:54] + otp[56:60] +
                                                otp[62:63]) & 0xff != otp[61]:
            raise ValueError("Invalid OTP FT data checksum")

        if ~crcmod.predefined.mkCrcFun("crc-8")(otp[50:54]) & 0xff != otp[62]:
            raise ValueError("Invalid OTP DAC FT data checksum")

        if ~crcmod.predefined.mkCrcFun("crc-8")(otp[46:50]) & 0xff != otp[22]:
            raise ValueError("Invalid OTP DAC MT data checksum")

        if otp[50:54] != otp[46:50]:
            raise ValueError("Invalid OTP DAC data")

        if otp[42] == 0x00 or otp[42] != ~otp[43] & 0xff:
            if otp[43] == 0x00 or otp[43] != ~otp[43] & 0xff:
                if otp[42] == 0x00 or otp[43] != otp[42]:
                    raise ValueError("Invalid OTP Tcode and threshold data")

        tcode = ((otp[42] >> 4) + 1) * 16 + 64
        delta = int(((otp[42] & 0xf) + 2) * 25600 / tcode / 3) >> 4 & 0xff

        if otp[27] != 0x00:
            if otp[27] & 3 == otp[27] >> 4 & 3:
                fdt_offset = otp[27] & 3
            elif otp[27] & 3 == otp[27] >> 2 & 3:
                fdt_offset = otp[27] & 3
            elif otp[27] >> 4 & 3 == otp[27] >> 2 & 3:
                fdt_offset = otp[27] >> 4 & 3
            else:
                fdt_offset = 0
        else:
            fdt_offset = 0

        success, number = device.reset(True, False, 20)
        if not success:
            raise ValueError("Reset failed")
        if number != 2048:
            raise ValueError("Invalid reset number")

        device.mcu_switch_to_idle_mode(20)

        device.write_sensor_register(0x0220,
                                   struct.pack("<H", otp[46] << 4 | 8))
        device.write_sensor_register(0x0236, struct.pack("<H", otp[47]))
        device.write_sensor_register(0x0238, struct.pack("<H", otp[48]))
        device.write_sensor_register(0x023a, struct.pack("<H", otp[49]))

        if not device.upload_config_mcu(DEVICE_CONFIG):
            raise ValueError("Failed to upload config")

        if not device.set_powerdown_scan_frequency(100):
            raise ValueError("Failed to set powerdown scan frequency")

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))

        try:
            tool.connect_device(device, tls_client)

            device.tls_successfully_established()

            device.query_mcu_state(b"\x55", True)

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\xae\xae\xbf\xbf\xa4\xa4"
                b"\xb8\xb8\xa8\xa8\xb7\xb7", True)

            device.nav()

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x80\xaf\x80\xbf\x80\xa3"
                b"\x80\xb7\x80\xa7\x80\xb6", True)

            device.read_sensor_register(0x0082, 2)

            tls_client.sendall(
                device.mcu_get_image(b"\x01\x00",
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(10573)[8:-5]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear.pgm")

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x80\xaf\x80\xbf\x80\xa4"
                b"\x80\xb8\x80\xa8\x80\xb7", True)

            print("Waiting for finger...")

            device.mcu_switch_to_fdt_down(
                b"\x0c\x01\x80\xaf\x80\xbf\x80\xa4"
                b"\x80\xb8\x80\xa8\x80\xb7", True)

            tls_client.sendall(
                device.mcu_get_image(b"\x01\x00",
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(10573)[8:-5]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "fingerprint.pgm")

        finally:
            tls_client.close()
    finally:
        tls_server.terminate()

def main(product: int):
    print(
        tool.warning(
            "This program might break your device.\n"
            "Consider that it may flash the device firmware.\n"
            "Continue at your own risk.\n"
            "But don't hold us responsible if your device is broken!\n"
            "Don't run this program as part of a regular process."))

    code = random.randint(0, 9999)

    if input(f"Type {code} to continue and confirm that you are not a bot: "
             ) != str(code):
        print("Abort")
        return

    previous_firmware = None
    device = init_device(product)

    while True:
        firmware = device.firmware_version()
        print(f"Firmware: {firmware}")

        valid_psk = check_psk(device)
        print(f"Valid PSK: {valid_psk}")

        if firmware == previous_firmware:
            raise ValueError("Unchanged firmware")

        previous_firmware = firmware

        if re.fullmatch(TARGET_FIRMWARE, firmware):
            if not valid_psk:
                erase_firmware(device)
                device = init_device(product)
                continue

            run_driver(device)
            return

        if re.fullmatch(VALID_FIRMWARE, firmware):
            erase_firmware(device)
            device = init_device(product)
            continue

        if re.fullmatch(IAP_FIRMWARE, firmware):
            if not valid_psk:
                if not write_psk(device):
                    raise ValueError("Failed to write PSK")

            update_firmware(device)
            device = init_device(product)
            continue

        raise ValueError(
            "Invalid firmware\n" +
            tool.warning("Please consider that removing this security "
                         "is a very bad idea!"))
