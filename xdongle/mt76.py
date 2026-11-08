"""MT76x2U radio control for the Xbox Wireless Adapter.

Port of xone's transport/mt76.c (GPL-2.0-or-later, Severin von Wnuck-Lipinski et al.),
which in turn uses register definitions from OpenWrt's mt76 driver (ISC).

SAFETY: the eFuse is only ever *read* (MT_EE_READ mode). Nothing in here writes the
chip's one-time-programmable memory, and firmware is only uploaded to RAM.
"""

import logging
import struct
import time

from .usbdev import le32

log = logging.getLogger("xdongle.mt76")


def BIT(n):
    return 1 << n


def GENMASK(h, l):
    return ((1 << (h - l + 1)) - 1) << l


def FIELD_PREP(mask, val):
    shift = (mask & -mask).bit_length() - 1
    return (val << shift) & mask


def FIELD_GET(mask, val):
    shift = (mask & -mask).bit_length() - 1
    return (val & mask) >> shift


# ---------------------------------------------------------------- vendor requests
MT_VEND_DEV_MODE = 0x01
MT_VEND_MULTI_WRITE = 0x06
MT_VEND_MULTI_READ = 0x07
MT_VEND_WRITE_CFG = 0x46
MT_VEND_READ_CFG = 0x47
MT_VEND_TYPE_CFG = BIT(30)

# ---------------------------------------------------------------- registers
MT_CMB_CTRL = 0x0020
MT_EFUSE_CTRL = 0x0024
MT_EFUSE_CTRL_MODE = GENMASK(7, 6)
MT_EFUSE_CTRL_AIN = GENMASK(25, 16)
MT_EFUSE_CTRL_KICK = BIT(30)
MT_EFUSE_DATA_BASE = 0x0028
MT_LDO_CTRL_1 = 0x0070
MT_XO_CTRL5 = 0x0114
MT_XO_CTRL5_C2_VAL = GENMASK(14, 8)
MT_XO_CTRL6 = 0x0118
MT_XO_CTRL6_C2_CTRL = GENMASK(14, 8)
MT_WPDMA_GLO_CFG = 0x0208
MT_WMM_AIFSN = 0x0214
MT_WMM_CWMIN = 0x0218
MT_WMM_CWMAX = 0x021C
MT_FCE_DMA_ADDR = 0x0230
MT_FCE_DMA_LEN = 0x0234
MT_USB_DMA_CFG = 0x0238
MT_TSO_CTRL = 0x0250
MT_PBF_SYS_CTRL = 0x0400
MT_PBF_CFG = 0x0404
MT_PBF_TX_MAX_PCNT = 0x0408
MT_RF_BYPASS_0 = 0x0504
MT_RF_SETTING_0 = 0x050C
MT_FCE_PSE_CTRL = 0x0800
MT_FCE_L2_STUFF = 0x080C
MT_TX_CPU_FROM_FCE_BASE_PTR = 0x09A0
MT_TX_CPU_FROM_FCE_MAX_COUNT = 0x09A4
MT_TX_CPU_FROM_FCE_CPU_DESC_IDX = 0x09A8
MT_FCE_PDMA_GLOBAL_CONF = 0x09C4
MT_PAUSE_ENABLE_CONTROL1 = 0x0A38
MT_FCE_SKIP_FS = 0x0A6C
MT_MAC_SYS_CTRL = 0x1004
MT_MAC_SYS_CTRL_RESET_CSR = BIT(0)
MT_MAC_SYS_CTRL_RESET_BBP = BIT(1)
MT_MAC_SYS_CTRL_ENABLE_TX = BIT(2)
MT_MAC_SYS_CTRL_ENABLE_RX = BIT(3)
MT_MAC_ADDR_DW0 = 0x1008
MT_MAC_BSSID_DW0 = 0x1010
MT_MAX_LEN_CFG = 0x1018
MT_AMPDU_MAX_LEN_20M1S = 0x1030
MT_AMPDU_MAX_LEN_20M2S = 0x1034
MT_XIFS_TIME_CFG = 0x1100
MT_BKOFF_SLOT_CFG = 0x1104
MT_CH_TIME_CFG = 0x110C
MT_BEACON_TIME_CFG = 0x1114
MT_BEACON_TIME_CFG_INTVAL = GENMASK(15, 0)
MT_BEACON_TIME_CFG_TIMER_EN = BIT(16)
MT_BEACON_TIME_CFG_SYNC_MODE = GENMASK(18, 17)
MT_BEACON_TIME_CFG_TBTT_EN = BIT(19)
MT_BEACON_TIME_CFG_BEACON_TX = BIT(20)
MT_PWR_PIN_CFG = 0x1204
MT_RF_PA_MODE_ADJ0 = 0x1228
MT_RF_PA_MODE_ADJ1 = 0x122C
MT_DACCLK_EN_DLY_CFG = 0x1264
MT_TX_PIN_CFG = 0x1328
MT_TX_SW_CFG0 = 0x1330
MT_TX_SW_CFG1 = 0x1334
MT_TXOP_CTRL_CFG = 0x1340
MT_TX_RTS_CFG = 0x1344
MT_TX_TIMEOUT_CFG = 0x1348
MT_TX_RETRY_CFG = 0x134C
MT_CCK_PROT_CFG = 0x1364
MT_OFDM_PROT_CFG = 0x1368
MT_MM20_PROT_CFG = 0x136C
MT_GF20_PROT_CFG = 0x1374
MT_GF40_PROT_CFG = 0x1378
MT_EXP_ACK_TIME = 0x1380
MT_TX0_RF_GAIN_CORR = 0x13A0
MT_TX1_RF_GAIN_CORR = 0x13A4
MT_TX_ALC_CFG_2 = 0x13A8
MT_TX_ALC_CFG_3 = 0x13AC
MT_TX_ALC_CFG_0 = 0x13B0
MT_TX_ALC_CFG_4 = 0x13C0
MT_TX_PROT_CFG6 = 0x13E0
MT_TX_PROT_CFG7 = 0x13E4
MT_TX_PROT_CFG8 = 0x13E8
MT_PIFS_TX_CFG = 0x13EC
MT_RX_FILTR_CFG = 0x1400
MT_AUTO_RSP_CFG = 0x1404
MT_LEGACY_BASIC_RATE = 0x1408
MT_HT_BASIC_RATE = 0x140C
MT_EXT_CCA_CFG = 0x141C
MT_PN_PAD_MODE = 0x150C
MT_TXOP_HLDR_ET = 0x1608
MT_BBP_AGC_BASE = 0x2300
MT_USB_U3DMA_CFG = 0x9018
MT_USB_DMA_CFG_RX_BULK_EN = BIT(22)
MT_USB_DMA_CFG_TX_BULK_EN = BIT(23)
MT_BEACON_BASE = 0xC000
MT_MCU_MEMMAP_WLAN = 0x410000


def MT_EDCA_CFG_AC(n):
    return 0x1300 + (n << 2)


def MT_BBP_AGC(n):
    return MT_BBP_AGC_BASE + (n << 2)


def MT_WCID_ADDR(n):
    return 0x1800 + n * 8


def MT_WCID_KEY(n):
    return 0x8000 + n * 32


def MT_WCID_IV(n):
    return 0xA000 + n * 8


def MT_WCID_ATTR(n):
    return 0xA800 + n * 4


MT_WCID_ATTR_PAIRWISE = BIT(0)
MT_WCID_ATTR_PKEY_MODE = GENMASK(3, 1)
MT_CIPHER_AES_CCMP = 4

# ---------------------------------------------------------------- eFuse fields
MT_EE_READ = 0
MT_EE_CHIP_ID = 0x0000
MT_EE_MAC_ADDR = 0x0004
MT_EE_XTAL_TRIM_1 = 0x003A
MT_EE_XTAL_TRIM_2 = 0x009E
MT_EE_TX_POWER_0_START_2G = 0x0056
MT_EE_TX_POWER_0_START_5G = 0x0062
MT_TX_POWER_GROUP_SIZE_5G = 5

# ---------------------------------------------------------------- MCU messages
MT_CMD_HDR_LEN = 4
MT_MCU_MSG_LEN = GENMASK(15, 0)
MT_MCU_MSG_CMD_TYPE = GENMASK(26, 20)
MT_MCU_MSG_PORT = GENMASK(29, 27)
MT_MCU_MSG_TYPE_CMD = BIT(30)

MT_TXD_INFO_80211 = BIT(19)
MT_TXD_INFO_WIV = BIT(24)
MT_TXD_INFO_QSEL = GENMASK(26, 25)
MT_TXD_INFO_DPORT = GENMASK(29, 27)

MT_WLAN_PORT = 0
MT_CPU_RX_PORT = 1
MT_CPU_TX_PORT = 2
MT_QSEL_EDCA = 2

MT_CMD_FUN_SET_OP = 1
MT_CMD_LOAD_CR = 2
MT_CMD_INIT_GAIN_OP = 3
MT_CMD_BURST_WRITE = 8
MT_CMD_LED_MODE_OP = 16
MT_CMD_POWER_SAVING_OP = 20
MT_CMD_WOW_FEATURE = 24
MT_CMD_SWITCH_CHANNEL_OP = 30
MT_CMD_CALIBRATION_OP = 31

MT_Q_SELECT = 1
MT_RF_BBP_CR = 2
MT_RADIO_OFF = 0x30
MT_RADIO_ON = 0x31
MT_MCU_CAL_TEMP_SENSOR = 2
MT_MCU_CAL_RXDCOC = 3
MT_MCU_CAL_RC = 4

# TXWI
MT_TXWI_FLAGS_TS = BIT(3)
MT_TXWI_FLAGS_MPDU_DENSITY = GENMASK(7, 5)
IEEE80211_HT_MPDU_DENSITY_4 = 5
MT_RXWI_RATE_PHY = GENMASK(15, 13)
MT_PHY_TYPE_OFDM = 1
MT_TXWI_ACK_CTL_REQ = BIT(0)
MT_TXWI_ACK_CTL_NSEQ = BIT(1)

# bandwidths / channel groups
MT_PHY_BW_20, MT_PHY_BW_40, MT_PHY_BW_80 = 0, 1, 2
MT_CH_5G_UNII_1 = 1
MT_CH_5G_UNII_3 = 5

# ---------------------------------------------------------------- xone specifics
XONE_MT_POLL_RETRIES = 50
XONE_MT_RF_PATCH = 0x0130
XONE_MT_FW_LOAD_IVB = 0x12
XONE_MT_FW_ILM_OFFSET = 0x080000
XONE_MT_FW_DLM_OFFSET = 0x110800
XONE_MT_FW_CHUNK_SIZE = 0x3800
XONE_MT_WCID_KEY_LEN = 16
XONE_MT_WLAN_RESERVED = 0x70

# Microsoft firmware ("MS") commands
XONE_MT_SET_MAC_ADDRESS = 0x00
XONE_MT_ADD_CLIENT = 0x01
XONE_MT_REMOVE_CLIENT = 0x02
XONE_MT_SET_IDLE_TIME = 0x05
XONE_MT_SET_CHAN_CANDIDATES = 0x07

XONE_MT_WOW_ENABLE = 0x01
XONE_MT_WOW_TRAFFIC = 0x03
XONE_MT_WOW_TO_FIRMWARE = 0x00

LED_BLINK, LED_ON, LED_OFF = 0x00, 0x01, 0x02

# client commands (management frames with reserved subtype 0x70)
CLIENT_PAIR_REQ = 0x01
CLIENT_PAIR_RESP = 0x02
CLIENT_ENABLE_ENCRYPTION = 0x10

# 802.11
IEEE80211_FTYPE_MGMT = 0x0000
IEEE80211_FTYPE_DATA = 0x0008
IEEE80211_STYPE_ASSOC_REQ = 0x0000
IEEE80211_STYPE_ASSOC_RESP = 0x0010
IEEE80211_STYPE_BEACON = 0x0080
IEEE80211_STYPE_DISASSOC = 0x00A0
IEEE80211_STYPE_QOS_DATA = 0x0080
IEEE80211_FCTL_FROMDS = 0x0200
IEEE80211_FCTL_PROTECTED = 0x4000


def txwi(flags=0, rate=0, ack_ctl=0, wcid=0, len_ctl=0):
    # struct mt76_txwi: le16 flags, le16 rate, u8 ack_ctl, u8 wcid, le16 len_ctl,
    #                   le32 iv, le32 eiv, u8 aid, u8 txstream, u8 ctl2, u8 pktid  (20 bytes)
    return struct.pack("<HHBBHIIBBBB", flags, rate, ack_ctl, wcid, len_ctl, 0, 0, 0, 0, 0, 0)


def default_txwi(wcid, length):
    """TXWI used for normal acknowledged OFDM frames."""
    return txwi(flags=FIELD_PREP(MT_TXWI_FLAGS_MPDU_DENSITY, IEEE80211_HT_MPDU_DENSITY_4),
                rate=FIELD_PREP(MT_RXWI_RATE_PHY, MT_PHY_TYPE_OFDM),
                ack_ctl=MT_TXWI_ACK_CTL_REQ, wcid=wcid, len_ctl=length)


def hdr_3addr(fc, addr1, addr2, addr3, duration=0):
    return struct.pack("<HH", fc, duration) + bytes(addr1) + bytes(addr2) + bytes(addr3) + b"\0\0"


def prep_message(payload, info):
    """Prepend the 4-byte DMA header and append padding + 4-byte zero trailer."""
    length = (len(payload) + 3) & ~3
    pad = length - len(payload) + MT_CMD_HDR_LEN
    return le32(info | FIELD_PREP(MT_MCU_MSG_LEN, length)) + payload + b"\0" * pad


def prep_command(payload, cmd):
    return prep_message(payload, MT_MCU_MSG_TYPE_CMD |
                        FIELD_PREP(MT_MCU_MSG_PORT, MT_CPU_TX_PORT) |
                        FIELD_PREP(MT_MCU_MSG_CMD_TYPE, cmd))


class Channel:
    __slots__ = ("band", "bandwidth", "group", "index", "power", "scan")

    def __init__(self, index, band, bandwidth, group, scan, power=0):
        self.index, self.band, self.bandwidth = index, band, bandwidth
        self.group, self.scan, self.power = group, scan, power

    def __repr__(self):
        return f"Channel({self.index}, power={self.power})"


def default_channels():
    return [
        Channel(0x01, 1, MT_PHY_BW_20, 0, True),
        Channel(0x06, 2, MT_PHY_BW_20, 0, True),
        Channel(0x0B, 3, MT_PHY_BW_20, 0, True),
        Channel(0x24, 1, MT_PHY_BW_40, MT_CH_5G_UNII_1, True),
        Channel(0x28, 1, MT_PHY_BW_40, MT_CH_5G_UNII_1, False),
        Channel(0x2C, 2, MT_PHY_BW_40, MT_CH_5G_UNII_1, True),
        Channel(0x30, 2, MT_PHY_BW_40, MT_CH_5G_UNII_1, False),
        Channel(0x95, 1, MT_PHY_BW_80, MT_CH_5G_UNII_3, True),
        Channel(0x99, 1, MT_PHY_BW_80, MT_CH_5G_UNII_3, False),
        Channel(0x9D, 2, MT_PHY_BW_80, MT_CH_5G_UNII_3, True),
        Channel(0xA1, 2, MT_PHY_BW_80, MT_CH_5G_UNII_3, False),
        Channel(0xA5, 2, MT_PHY_BW_80, MT_CH_5G_UNII_3, False),
    ]


class Mt76Error(Exception):
    pass


class Mt76:
    def __init__(self, usb):
        self.usb = usb
        self.address = bytes(6)
        self.channels = default_channels()
        self.channel = None

    # ------------------------------------------------------------ register access
    def read_register(self, addr):
        req = MT_VEND_MULTI_READ
        if addr & MT_VEND_TYPE_CFG:
            req = MT_VEND_READ_CFG
            addr &= ~MT_VEND_TYPE_CFG
        data = self.usb.control_in(req, addr >> 16, addr & 0xFFFF, 4)
        if len(data) != 4:
            log.error("register read 0x%x returned %d bytes", addr, len(data))
            return 0
        return struct.unpack("<I", data)[0]

    def write_register(self, addr, val):
        req = MT_VEND_MULTI_WRITE
        if addr & MT_VEND_TYPE_CFG:
            req = MT_VEND_WRITE_CFG
            addr &= ~MT_VEND_TYPE_CFG
        self.usb.control_out(req, addr >> 16, addr & 0xFFFF, le32(val))

    def load_ivb(self):
        # load interrupt vector block (starts the MCU)
        self.usb.control_out(MT_VEND_DEV_MODE, XONE_MT_FW_LOAD_IVB, 0, b"")

    def poll(self, offset, mask, val):
        for _ in range(XONE_MT_POLL_RETRIES):
            if (self.read_register(offset) & mask) == val:
                return True
            time.sleep(0.015)
        return False

    def read_efuse(self, addr, length):
        ctrl = self.read_register(MT_EFUSE_CTRL)
        ctrl &= ~(MT_EFUSE_CTRL_AIN | MT_EFUSE_CTRL_MODE)
        ctrl |= MT_EFUSE_CTRL_KICK
        ctrl |= FIELD_PREP(MT_EFUSE_CTRL_AIN, addr & ~0x0F)
        ctrl |= FIELD_PREP(MT_EFUSE_CTRL_MODE, MT_EE_READ)   # read mode only, never write
        self.write_register(MT_EFUSE_CTRL, ctrl)
        if not self.poll(MT_EFUSE_CTRL, MT_EFUSE_CTRL_KICK, 0):
            raise Mt76Error(f"eFuse read at 0x{addr:x} timed out")
        out = b""
        for i in range(0, length, 4):
            offset = (addr & GENMASK(3, 2)) + i
            val = self.read_register(MT_EFUSE_DATA_BASE + offset)
            out += le32(val)[: min(length - i, 4)]
        return out

    # ------------------------------------------------------------ MCU commands
    def send_command(self, payload, cmd):
        self.usb.bulk_write(prep_command(payload, cmd))

    def send_wlan(self, frame):
        data = default_txwi(0xFF, len(frame)) + frame
        self.usb.bulk_write(prep_message(data, FIELD_PREP(MT_TXD_INFO_DPORT, MT_WLAN_PORT) |
                                         FIELD_PREP(MT_TXD_INFO_QSEL, MT_QSEL_EDCA) |
                                         MT_TXD_INFO_WIV | MT_TXD_INFO_80211))

    def select_function(self, func, val):
        self.send_command(le32(func) + le32(val), MT_CMD_FUN_SET_OP)

    def load_cr(self, mode):
        self.send_command(bytes([mode, 0, 0, 0]), MT_CMD_LOAD_CR)

    def send_ms_command(self, cmd, data):
        # commands for Microsoft's proprietary firmware
        self.send_command(le32(cmd) + bytes(data), MT_CMD_INIT_GAIN_OP)

    def write_burst(self, idx, data):
        self.send_command(le32(idx + MT_MCU_MEMMAP_WLAN) + bytes(data), MT_CMD_BURST_WRITE)

    def set_led_mode(self, mode):
        self.send_command(le32(mode), MT_CMD_LED_MODE_OP)

    def set_power_mode(self, mode):
        self.send_command(le32(mode), MT_CMD_POWER_SAVING_OP)

    def set_wow_enable(self, enable):
        self.send_command(le32(XONE_MT_WOW_ENABLE) + bytes([1 if enable else 0, self.channel.index]),
                          MT_CMD_WOW_FEATURE)

    def set_wow_traffic(self, traffic):
        self.send_command(le32(XONE_MT_WOW_TRAFFIC) + bytes([traffic]), MT_CMD_WOW_FEATURE)

    def switch_channel(self, chan):
        msg = struct.pack("<B3xH10xBBBB", chan.index, 0x0101, chan.bandwidth, chan.power & 0xFF,
                          1 if chan.scan else 0, 0)
        self.send_command(msg, MT_CMD_SWITCH_CHANNEL_OP)

    def calibrate(self, calib, val):
        self.send_command(le32(calib) + le32(val), MT_CMD_CALIBRATION_OP)

    # ------------------------------------------------------------ firmware
    def _send_firmware_part(self, offset, data):
        for pos in range(0, len(data), XONE_MT_FW_CHUNK_SIZE):
            chunk = data[pos:pos + XONE_MT_FW_CHUNK_SIZE]
            chunk_len = (len(chunk) + 3) & ~3
            self.write_register(MT_FCE_DMA_ADDR | MT_VEND_TYPE_CFG, offset + pos)
            self.write_register(MT_FCE_DMA_LEN | MT_VEND_TYPE_CFG, chunk_len << 16)
            self.send_command(chunk, 0)
            complete = 0xC0000000 | (chunk_len << 16)
            if not self.poll(MT_FCE_DMA_LEN | MT_VEND_TYPE_CFG, 0xFFFFFFFF, complete):
                raise Mt76Error(f"firmware chunk at 0x{offset + pos:x} not acknowledged")

    def _send_firmware(self, fw):
        if len(fw) < 32:
            raise Mt76Error("firmware file too small")
        ilm_len, dlm_len, build_ver, fw_ver = struct.unpack_from("<IIHH", fw, 0)
        build_time = fw[16:32].split(b"\0")[0].decode(errors="replace")
        if len(fw) != 32 + ilm_len + dlm_len:
            raise Mt76Error("firmware size does not match its header")
        log.info("Uploading dongle firmware (build %s, ILM %d bytes, DLM %d bytes)",
                 build_time, ilm_len, dlm_len)
        # configure DMA, enable FCE and packet DMA
        self.write_register(MT_USB_U3DMA_CFG | MT_VEND_TYPE_CFG,
                            MT_USB_DMA_CFG_TX_BULK_EN | MT_USB_DMA_CFG_RX_BULK_EN)
        self.write_register(MT_FCE_PSE_CTRL, 0x01)
        self.write_register(MT_TX_CPU_FROM_FCE_BASE_PTR, 0x00400230)
        self.write_register(MT_TX_CPU_FROM_FCE_MAX_COUNT, 0x01)
        self.write_register(MT_TX_CPU_FROM_FCE_CPU_DESC_IDX, 0x01)
        self.write_register(MT_FCE_PDMA_GLOBAL_CONF, 0x44)
        self.write_register(MT_FCE_SKIP_FS, 0x03)
        self._send_firmware_part(XONE_MT_FW_ILM_OFFSET, fw[32:32 + ilm_len])
        self._send_firmware_part(XONE_MT_FW_DLM_OFFSET, fw[32 + ilm_len:])

    def _apply_rf_patch(self):
        val = self.read_register(XONE_MT_RF_PATCH | MT_VEND_TYPE_CFG)
        self.write_register(XONE_MT_RF_PATCH | MT_VEND_TYPE_CFG, val & ~BIT(19))

    def firmware_running(self):
        return self.read_register(MT_FCE_DMA_ADDR | MT_VEND_TYPE_CFG) != 0

    def load_firmware(self, fw):
        """Returns 'warm' if firmware was already in RAM (MCU reset only), else 'cold'."""
        if self.firmware_running():
            log.info("Firmware already running, resetting MCU")
            self._apply_rf_patch()
            self.load_ivb()
            if not self.poll(MT_FCE_DMA_ADDR | MT_VEND_TYPE_CFG, 0x80000000, 0x80000000):
                raise Mt76Error("MCU reset timed out")
            time.sleep(0.5)
            return "warm"

        self._send_firmware(fw)
        self.write_register(MT_FCE_DMA_ADDR | MT_VEND_TYPE_CFG, 0)
        self._apply_rf_patch()
        self.load_ivb()
        # the chip may drop off the bus briefly while the firmware starts
        time.sleep(0.5)
        if not self.poll(MT_FCE_DMA_ADDR | MT_VEND_TYPE_CFG, 0x01, 0x01):
            raise Mt76Error("firmware did not start")
        return "cold"

    # ------------------------------------------------------------ channels
    def _get_channel_power(self, chan):
        if chan.bandwidth == MT_PHY_BW_20:
            addr, idx = MT_EE_TX_POWER_0_START_2G, 4
        else:
            addr = MT_EE_TX_POWER_0_START_5G + chan.group * MT_TX_POWER_GROUP_SIZE_5G
            idx = 5
        entry = self.read_efuse(addr, 8)
        target = entry[idx]
        offset = entry[idx + chan.band]
        if offset & BIT(7):
            if offset & BIT(6):
                chan.power = (target + (offset & 0x3F)) & 0xFF
            else:
                chan.power = (target - (offset & 0x3F)) & 0xFF
        else:
            chan.power = target

    def _evaluate_channels(self):
        self.channel = None
        self.channels = default_channels()
        best = 0
        for chan in self.channels:
            self._get_channel_power(chan)
            self.switch_channel(chan)
            if chan.power > best:
                self.channel = chan
                best = chan.power
            log.debug("channel %d power %d", chan.index, chan.power)
        if self.channel is None:
            self.channel = self.channels[-1]

    def _set_channel_candidates(self):
        best = self.channel.index
        data = le32(1) + le32(best) + le32(len(self.channels) - 1)
        for chan in self.channels:
            if chan.index != best:
                data += le32(chan.index)
        self.send_ms_command(XONE_MT_SET_CHAN_CANDIDATES, data)

    def _init_channels(self):
        self.write_register(MT_RX_FILTR_CFG, 0x014F13)   # promiscuous
        self._evaluate_channels()
        self.write_register(MT_RX_FILTR_CFG, 0x017F17)
        log.info("Selected channel %d", self.channel.index)
        self.channel.scan = True
        self.switch_channel(self.channel)
        self.set_power_mode(MT_RADIO_OFF)
        time.sleep(0.05)
        self.set_power_mode(MT_RADIO_ON)
        self.channel.scan = False
        self.switch_channel(self.channel)
        self._set_channel_candidates()

    # ------------------------------------------------------------ init pieces
    def _init_address(self, override=None):
        addr = bytearray(self.read_efuse(MT_EE_MAC_ADDR, 6))
        log.debug("eFuse address %s", addr.hex(":"))
        if override:
            addr = bytearray(override)
        # clients only connect to 62:45:bx:xx:xx:xx
        if addr[0] != 0x62:
            addr[0:3] = b"\x62\x45\xbd"
        self.address = bytes(addr)
        self.write_burst(MT_MAC_ADDR_DW0, self.address)
        self.write_burst(MT_MAC_BSSID_DW0, self.address)
        self.send_ms_command(XONE_MT_SET_MAC_ADDRESS, self.address)
        log.info("Dongle wireless address %s", self.address.hex(":"))

    def _calibrate_crystal(self):
        trim = self.read_efuse(MT_EE_XTAL_TRIM_2, 4)
        val = (trim[3] << 8) | trim[2]
        offset = val & GENMASK(6, 0)
        if (val & 0xFF) == 0xFF:
            offset = 0
        elif val & BIT(7):
            offset = -offset
        val >>= 8
        if not val or val == 0xFF:
            trim = self.read_efuse(MT_EE_XTAL_TRIM_1, 4)
            val = ((trim[3] << 8) | trim[2]) & 0xFF
            if not val or val == 0xFF:
                val = 0x14
        val = ((val & GENMASK(6, 0)) + offset) & 0xFFFF
        ctrl = self.read_register(MT_XO_CTRL5 | MT_VEND_TYPE_CFG)
        self.write_register(MT_XO_CTRL5 | MT_VEND_TYPE_CFG,
                            (ctrl & ~MT_XO_CTRL5_C2_VAL) | ((val << 8) & 0xFFFFFFFF))
        self.write_register(MT_XO_CTRL6 | MT_VEND_TYPE_CFG, MT_XO_CTRL6_C2_CTRL)
        self.write_register(MT_CMB_CTRL, 0x0091A7FF)

    def _calibrate_radio(self):
        self.write_register(MT_BBP_AGC(8), 0x18365EFA)
        self.write_register(MT_BBP_AGC(9), 0x18365EFA)
        # reset required for reliable WLAN associations
        self.write_register(MT_MAC_SYS_CTRL, 0)
        self.write_register(MT_RF_BYPASS_0, 0)
        self.write_register(MT_RF_SETTING_0, 0)
        self.calibrate(MT_MCU_CAL_TEMP_SENSOR, 0)
        self.calibrate(MT_MCU_CAL_RXDCOC, 1)
        self.calibrate(MT_MCU_CAL_RC, 0)
        self.write_register(MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_ENABLE_RX | MT_MAC_SYS_CTRL_ENABLE_TX)

    def _init_registers(self):
        w = self.write_register
        w(MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_RESET_BBP | MT_MAC_SYS_CTRL_RESET_CSR)
        w(MT_USB_DMA_CFG, 0)
        w(MT_MAC_SYS_CTRL, 0)
        w(MT_PWR_PIN_CFG, 0)
        w(MT_LDO_CTRL_1, 0x6B006464)
        w(MT_WPDMA_GLO_CFG, 0x70)
        w(MT_WMM_AIFSN, 0x2273)
        w(MT_WMM_CWMIN, 0x2344)
        w(MT_WMM_CWMAX, 0x34AA)
        w(MT_FCE_DMA_ADDR, 0x041200)
        w(MT_TSO_CTRL, 0)
        w(MT_PBF_SYS_CTRL, 0x080C00)
        w(MT_PBF_TX_MAX_PCNT, 0x1FBF1F1F)
        w(MT_FCE_PSE_CTRL, 0x01)
        w(MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_ENABLE_RX | MT_MAC_SYS_CTRL_ENABLE_TX)
        w(MT_AUTO_RSP_CFG, 0x13)
        w(MT_MAX_LEN_CFG, 0x3E3FFF)
        w(MT_AMPDU_MAX_LEN_20M1S, 0xFFFC9855)
        w(MT_AMPDU_MAX_LEN_20M2S, 0xFF)
        w(MT_BKOFF_SLOT_CFG, 0x0109)
        w(MT_PWR_PIN_CFG, 0)
        w(MT_EDCA_CFG_AC(0), 0x064320)
        w(MT_EDCA_CFG_AC(1), 0x0A4700)
        w(MT_EDCA_CFG_AC(2), 0x043238)
        w(MT_EDCA_CFG_AC(3), 0x03212F)
        w(MT_TX_PIN_CFG, 0x150F0F)
        w(MT_TX_SW_CFG0, 0x101001)
        w(MT_TX_SW_CFG1, 0x010000)
        w(MT_TXOP_CTRL_CFG, 0x10583F)
        w(MT_TX_TIMEOUT_CFG, 0x0A0F90)
        w(MT_TX_RETRY_CFG, 0x47D01F0F)
        w(MT_CCK_PROT_CFG, 0x03F40003)
        w(MT_OFDM_PROT_CFG, 0x03F40003)
        w(MT_MM20_PROT_CFG, 0x01742004)
        w(MT_GF20_PROT_CFG, 0x01742004)
        w(MT_GF40_PROT_CFG, 0x03F42084)
        w(MT_EXP_ACK_TIME, 0x2C00DC)
        w(MT_TX_ALC_CFG_2, 0x22160A00)
        w(MT_TX_ALC_CFG_3, 0x22160A76)
        w(MT_TX_ALC_CFG_0, 0x3F3F1818)
        w(MT_TX_ALC_CFG_4, 0x0606)
        w(MT_PIFS_TX_CFG, 0x060FFF)
        w(MT_RX_FILTR_CFG, 0x017F17)
        w(MT_LEGACY_BASIC_RATE, 0x017F)
        w(MT_HT_BASIC_RATE, 0x8003)
        w(MT_PN_PAD_MODE, 0x02)
        w(MT_TXOP_HLDR_ET, 0x02)
        w(MT_TX_PROT_CFG6, 0xE3F42004)
        w(MT_TX_PROT_CFG7, 0xE3F42084)
        w(MT_TX_PROT_CFG8, 0xE3F42104)
        w(MT_DACCLK_EN_DLY_CFG, 0)
        w(MT_RF_PA_MODE_ADJ0, 0xEE000000)
        w(MT_RF_PA_MODE_ADJ1, 0xEE000000)
        w(MT_TX0_RF_GAIN_CORR, 0x0F3C3C3C)
        w(MT_TX1_RF_GAIN_CORR, 0x0F3C3C3C)
        w(MT_PBF_CFG, 0x1EFEBCF5)
        w(MT_PAUSE_ENABLE_CONTROL1, 0x0A)
        w(MT_RF_BYPASS_0, 0x7F000000)
        w(MT_RF_SETTING_0, 0x1A800000)
        w(MT_XIFS_TIME_CFG, 0x33A40E0A)
        w(MT_FCE_L2_STUFF, 0x03FF0223)
        w(MT_TX_RTS_CFG, 0)
        w(MT_BEACON_TIME_CFG, 0x0640)
        w(MT_EXT_CCA_CFG, 0xF0E4)
        w(MT_CH_TIME_CFG, 0x015F)

    def chip_id(self):
        cid = self.read_efuse(MT_EE_CHIP_ID, 4)
        return (cid[1] << 8) | cid[2]

    def init_radio(self, override_mac=None):
        log.debug("chip id 0x%04x", self.chip_id())
        self.select_function(MT_Q_SELECT, 1)
        self.set_power_mode(MT_RADIO_ON)
        self.load_cr(MT_RF_BBP_CR)
        self._init_registers()
        self._calibrate_crystal()
        self._init_address(override_mac)
        # prevent wireless clients from disconnecting when idle
        self.send_ms_command(XONE_MT_SET_IDLE_TIME, le32(64))
        self._calibrate_radio()
        self._init_channels()
        time.sleep(1.0)   # mandatory delay after channel change
        self.set_wow_traffic(XONE_MT_WOW_TO_FIRMWARE)
        self.set_wow_enable(False)
        self.set_pairing(False)

    # ------------------------------------------------------------ beacon / pairing
    def _write_beacon(self, pair):
        chan = self.channel.index if self.channel else 1
        data = bytes([
            # empty SSID + vendor IE with Microsoft's OUI (00:50:f2)
            0x00, 0x00, 0xDD, 0x10, 0x00, 0x50, 0xF2, 0x11,
            0x01, 0x10, 1 if pair else 0, 0xA5, 0x30, 0x99, chan, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])
        mgmt = hdr_3addr(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON,
                         b"\xff" * 6, self.address, self.address)
        mgmt += struct.pack("<QHH", 0, 100, 0xC631)   # timestamp, interval, capabilities
        tw = txwi(flags=MT_TXWI_FLAGS_TS, rate=FIELD_PREP(MT_RXWI_RATE_PHY, MT_PHY_TYPE_OFDM),
                  ack_ctl=MT_TXWI_ACK_CTL_NSEQ, wcid=0, len_ctl=len(mgmt) + len(data))
        self.write_burst(MT_BEACON_BASE, tw + mgmt + data)

    def set_pairing(self, enable):
        self.write_register(MT_RX_FILTR_CFG, 0x014F13 if enable else 0x017F17)
        self._write_beacon(enable)
        self.write_register(MT_BEACON_TIME_CFG,
                            MT_BEACON_TIME_CFG_BEACON_TX | MT_BEACON_TIME_CFG_TBTT_EN |
                            MT_BEACON_TIME_CFG_SYNC_MODE | MT_BEACON_TIME_CFG_TIMER_EN |
                            FIELD_PREP(MT_BEACON_TIME_CFG_INTVAL, 0x0640))

    # ------------------------------------------------------------ clients
    def pair_client(self, addr):
        hdr = hdr_3addr(IEEE80211_FTYPE_MGMT | XONE_MT_WLAN_RESERVED, addr, self.address,
                        self.address)
        body = bytes([XONE_MT_WLAN_RESERVED, CLIENT_PAIR_RESP,
                      0x00, 0x45, 0x55, 0x01, 0x0F, 0x8F, 0xFF, 0x87, 0x1F])
        self.send_wlan(hdr + body)

    def associate_client(self, wcid, addr):
        mgmt = hdr_3addr(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_RESP, addr, self.address,
                         self.address)
        mgmt += struct.pack("<HHH", 0, 0x0110, 0x0F00)   # capab, status, aid (original values)
        mgmt += bytes(8)
        self.write_burst(MT_WCID_ADDR(wcid), addr)
        self.send_ms_command(XONE_MT_ADD_CLIENT, bytes([wcid - 1, 0, 0, 0, 0x40, 0x1F, 0, 0]))
        self.send_wlan(mgmt)

    def send_client_command(self, wcid, addr, cmd, data=b""):
        info = bytes([0, 0, 0, wcid - 1, 0, 0, 0, 0])
        hdr = hdr_3addr(IEEE80211_FTYPE_MGMT | XONE_MT_WLAN_RESERVED, addr, self.address,
                        self.address)
        body = bytes([XONE_MT_WLAN_RESERVED, cmd]) + bytes(data)
        tw = default_txwi(wcid - 1, len(hdr) + len(body))
        self.send_command(info + tw + hdr + body, 0)

    def set_client_key(self, wcid, key):
        if len(key) != XONE_MT_WCID_KEY_LEN:
            raise ValueError("bad key length")
        self.write_burst(MT_WCID_KEY(wcid), key)
        self.write_burst(MT_WCID_IV(wcid), bytes([0x01, 0x00, 0x00, 0x20, 0, 0, 0, 0]))
        attr = FIELD_PREP(MT_WCID_ATTR_PKEY_MODE, MT_CIPHER_AES_CCMP) | MT_WCID_ATTR_PAIRWISE
        self.write_burst(MT_WCID_ATTR(wcid), le32(attr))

    def remove_client(self, wcid):
        self.send_ms_command(XONE_MT_REMOVE_CLIENT, bytes([wcid - 1, 0, 0, 0]))
        self.write_burst(MT_WCID_ADDR(wcid), bytes(6))
        self.write_burst(MT_WCID_IV(wcid), bytes(8))
        self.write_burst(MT_WCID_ATTR(wcid), le32(0))
        self.write_burst(MT_WCID_KEY(wcid), bytes(XONE_MT_WCID_KEY_LEN))
