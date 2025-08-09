from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime
from core.db import Base


class Setting(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, index=True)
    value = Column(String, nullable=True)

    def __init__(self, key=None, value=None):
        self.key = key
        self.value = value
class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True)
    mac = Column(String, index=True, nullable=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    ports = relationship("Port", back_populates="device", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "ip": self.ip, "mac": self.mac, "hostname": self.hostname, "vendor": self.vendor,
            "os": self.os_name, "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "ports": [p.to_dict() for p in self.ports],
        }

class Port(Base):
    __tablename__ = "ports"
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"))
    port = Column(Integer)
    proto = Column(String, default="tcp")
    state = Column(String, default="open")
    service = Column(String, nullable=True)
    version = Column(String, nullable=True)

    device = relationship("Device", back_populates="ports")

    def to_dict(self):
        return {"port": self.port, "proto": self.proto, "state": self.state, "service": self.service, "version": self.version}

class TrafficStat(Base):
    __tablename__ = "traffic"
    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True)
    packets = Column(BigInteger, default=0)
    bytes = Column(BigInteger, default=0)
    last_updated = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"ip": self.ip, "packets": int(self.packets), "bytes": int(self.bytes), "last_updated": self.last_updated.isoformat()}

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String, default="info")
    message = Column(String)
    meta = Column(String, nullable=True)

    def to_dict(self):
        return {"ts": self.ts.isoformat(), "severity": self.severity, "message": self.message, "meta": self.meta}
# This file defines the database models used in the application.
# It includes models for settings, devices, ports, traffic statistics, and alerts.
