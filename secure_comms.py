"""AES-256-GCM secured messaging over a simulated LoRa channel."""
import os, math, random, struct

LORA_MAX_PAYLOAD = 255  # bytes per LoRa packet


def airtime_ms(payload_len, sf=9, bw=125_000, cr=1, preamble=8):
    """Standard Semtech LoRa time-on-air formula (explicit header, CRC on)."""
    tsym = (2 ** sf) / bw * 1000
    de = 1 if tsym > 16 else 0
    n = 8 + max(math.ceil((8 * payload_len - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return round((preamble + 4.25) * tsym + n * tsym, 1)


class LoRaChannel:
    """Lossy radio link: drops packets and can flip bits in transit."""
    def __init__(self, loss=0.0, bit_error=0.0, seed=None):
        self.loss, self.bit_error, self.rng = loss, bit_error, random.Random(seed)

    def transmit(self, packet: bytes):
        if len(packet) > LORA_MAX_PAYLOAD:
            raise ValueError("Packet exceeds LoRa 255-byte limit")
        if self.rng.random() < self.loss:
            return None
        if self.rng.random() < self.bit_error:
            b = bytearray(packet); i = self.rng.randrange(len(b)); b[i] ^= 1 << self.rng.randrange(8)
            return bytes(b)
        return packet


class SecureNode:
    """Packet = unit_id(1) | seq(4) | nonce(12) | AES-GCM(ciphertext+tag).
    Header is authenticated (AAD) so spoofed IDs / altered seq numbers fail."""
    def __init__(self, unit_id: int, key: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        assert len(key) == 32, "AES-256 needs a 32-byte key"
        self.unit_id, self.aes, self.seq, self.last_seen = unit_id, AESGCM(key), 0, {}

    def seal(self, text: str) -> bytes:
        self.seq += 1
        header = struct.pack(">BI", self.unit_id, self.seq)
        nonce = os.urandom(12)
        return header + nonce + self.aes.encrypt(nonce, text.encode(), header)

    def open(self, packet: bytes):
        """Returns (unit_id, text) or raises ValueError with the reason."""
        from cryptography.exceptions import InvalidTag
        if len(packet) < 5 + 12 + 16:
            raise ValueError("truncated packet")
        header, nonce, body = packet[:5], packet[5:17], packet[17:]
        uid, seq = struct.unpack(">BI", header)
        try:
            text = self.aes.decrypt(nonce, body, header).decode()
        except InvalidTag:
            raise ValueError("authentication failed (corrupted or forged)")
        if seq <= self.last_seen.get(uid, 0):
            raise ValueError(f"replay detected (seq {seq})")
        self.last_seen[uid] = seq
        return uid, text
