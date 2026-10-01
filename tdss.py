"""Tactical Decision Support: fuses unit reports and recommends actions."""
import math
from dataclasses import dataclass, field


@dataclass
class Unit:
    uid: int
    callsign: str
    x: float
    y: float
    strength: int
    status: str = "OK"


@dataclass
class Contact:
    x: float
    y: float
    size: int
    kind: str
    reported_by: int


@dataclass
class TDSS:
    units: dict = field(default_factory=dict)
    contacts: list = field(default_factory=list)

    def ingest(self, uid, message: str):
        """Message formats:  POS x y strength status | CONTACT x y size kind"""
        p = message.split()
        if p[0] == "POS":
            u = self.units.get(uid) or Unit(uid, f"ALPHA-{uid}", 0, 0, 0)
            u.x, u.y, u.strength, u.status = float(p[1]), float(p[2]), int(p[3]), p[4]
            self.units[uid] = u
        elif p[0] == "CONTACT":
            self.contacts.append(Contact(float(p[1]), float(p[2]), int(p[3]), p[4], uid))
        else:
            raise ValueError("unknown message type")

    @staticmethod
    def dist(a, b):
        return math.hypot(a.x - b.x, a.y - b.y)

    def recommend(self, c: Contact):
        friends = sorted((u for u in self.units.values() if u.status != "DOWN"),
                         key=lambda u: self.dist(u, c))
        if not friends:
            return "No friendly units available."
        near = friends[0]
        d = self.dist(near, c)
        local = sum(u.strength for u in friends if self.dist(u, c) <= 3.0)
        ratio = local / c.size if c.size else 99
        if ratio >= 1.5:
            act = f"ENGAGE - local superiority {ratio:.1f}:1"
        elif ratio >= 0.8:
            act = f"HOLD and REQUEST SUPPORT - even odds ({ratio:.1f}:1)"
        else:
            act = f"WITHDRAW / AVOID - outnumbered ({ratio:.1f}:1)"
        return (f"Contact {c.kind} x{c.size} at ({c.x:.0f},{c.y:.0f}) | closest: "
                f"{near.callsign} {d:.1f} km | {act}")
