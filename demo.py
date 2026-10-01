"""Secure Military Communication & TDSS - presentation demo.
Run:  python demo.py            (scripted demo)
      python demo.py --live     (type your own field reports)"""
import os, sys
from secure_comms import SecureNode, LoRaChannel, airtime_ms
from tdss import TDSS

KEY = os.urandom(32)  # in the field this is the pre-shared key loaded on each radio


def show(tag, msg):
    print(f"  [{tag}] {msg}")


def main():
    live = "--live" in sys.argv
    command = SecureNode(0, KEY)
    units = {i: SecureNode(i, KEY) for i in (1, 2, 3)}
    chan = LoRaChannel(loss=0.0, seed=7)
    tdss = TDSS()

    def deliver(pkt):
        rx = chan.transmit(pkt)
        if rx is None:
            show("RADIO", "packet lost in transit"); return
        try:
            uid, text = command.open(rx)
        except ValueError as e:
            show("COMMAND", f"REJECTED - {e}"); return
        show("COMMAND", f"unit {uid} -> '{text}'")
        tdss.ingest(uid, text)
        if text.startswith("CONTACT"):
            show("TDSS", tdss.recommend(tdss.contacts[-1]))

    print("=== Secure LoRa / AES-256-GCM link + Tactical Decision Support ===\n")
    if live:
        print("Enter: <unit 1-3> <POS x y strength status | CONTACT x y size kind>  (blank to quit)")
        while (line := input("> ").strip()):
            try:
                u, msg = line.split(" ", 1)
                pkt = units[int(u)].seal(msg)
                print(f"  ciphertext: {pkt.hex()[:48]}...  ({len(pkt)} B, airtime {airtime_ms(len(pkt))} ms)")
                deliver(pkt)
            except (ValueError, KeyError) as e:
                print("  bad input:", e)
        return

    print("1) Units report positions (encrypted)")
    for i, (x, y, s) in {1: (2, 3, 12), 2: (4, 4, 10), 3: (9, 1, 8)}.items():
        pkt = units[i].seal(f"POS {x} {y} {s} OK")
        print(f"  unit {i} ciphertext: {pkt.hex()[:40]}...  ({len(pkt)} B, airtime {airtime_ms(len(pkt))} ms)")
        deliver(pkt)

    print("\n2) Unit 2 reports an enemy contact -> decision support")
    deliver(units[2].seal("CONTACT 5 5 10 infantry"))
    print("\n3) Larger contact near the units")
    deliver(units[1].seal("CONTACT 3 4 30 armour"))

    print("\n4) Attack: attacker flips one bit of an intercepted packet")
    pkt = bytearray(units[1].seal("POS 2 3 12 OK")); pkt[-3] ^= 0x01
    deliver(bytes(pkt))

    print("\n5) Attack: attacker replays an old valid packet")
    old = units[3].seal("POS 9 1 8 OK"); deliver(old); deliver(old)

    print("\n6) Attack: attacker without the key forges a packet as unit 1")
    deliver(SecureNode(1, os.urandom(32)).seal("CONTACT 0 0 1 decoy"))

    print("\n7) Noisy channel (30% loss, 20% bit errors), 6 reports from unit 3")
    chan.loss, chan.bit_error = 0.3, 0.2
    for k in range(6):
        deliver(units[3].seal(f"POS {9-k} 1 8 OK"))


if __name__ == "__main__":
    main()
