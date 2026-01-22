"""
Packet information types and utilities.
Corresponds to packet_info.hpp in the C++ implementation.
"""

from enum import IntEnum
from typing import Tuple
from dataclasses import dataclass


class PacketType(IntEnum):
    """Packet type enumeration."""
    IPv4 = 0
    IPv6 = 1
    ICMP = 2
    IGMP = 3
    TCP_SYN = 4
    TCP_ACK = 5
    TCP_FIN = 6
    TCP_RST = 7
    UDP = 8
    UNKNOWN = 9


class StackType(IntEnum):
    """Protocol stack type enumeration."""
    F_ICMP = 0
    F_IGMP = 1
    F_TCP = 2
    F_UDP = 3
    F_UNKNOWN = 4


# Type names for display
TYPE_NAMES = ["IPv4", "IPv6", "ICMP", "IGMP", "TCP_SYN", "TCP_ACK", "TCP_FIN", "TCP_RST", "UDP", "UNKNOWN"]
STACK_NAMES = ["ICMP", "IGMP", "TCP", "UDP", "UNKNOWN"]


def set_pkt_type_code(code: int, pkt_type: PacketType) -> int:
    """Set packet type in code."""
    return code | (1 << pkt_type)


def get_pkt_type_code(pkt_type: PacketType) -> int:
    """Get packet type code."""
    return 1 << pkt_type


def test_pkt_type_code(code: int, pkt_type: PacketType) -> bool:
    """Test if packet type is set in code."""
    return bool(code & (1 << pkt_type))


def get_pkt_stack_code(stack_type: StackType) -> int:
    """Get stack type code."""
    return 1 << stack_type


def convert_packet2stack_code(pkt_code: int) -> int:
    """Convert packet code to stack code."""
    if test_pkt_type_code(pkt_code, PacketType.ICMP):
        return get_pkt_stack_code(StackType.F_ICMP)
    if test_pkt_type_code(pkt_code, PacketType.IGMP):
        return get_pkt_stack_code(StackType.F_IGMP)
    if test_pkt_type_code(pkt_code, PacketType.UDP):
        return get_pkt_stack_code(StackType.F_UDP)
    if test_pkt_type_code(pkt_code, PacketType.UNKNOWN):
        return get_pkt_stack_code(StackType.F_UNKNOWN)
    # Default to TCP
    return get_pkt_stack_code(StackType.F_TCP)


# Connection tuple types
# tuple4_conn4: (src_ip, dst_ip, src_port, dst_port) for IPv4
# tuple4_conn6: (src_ip, dst_ip, src_port, dst_port) for IPv6
# tuple5_conn4: (src_ip, dst_ip, src_port, dst_port, stack_code) for IPv4
# tuple5_conn6: (src_ip, dst_ip, src_port, dst_port, stack_code) for IPv6

@dataclass(frozen=True)
class Tuple4Conn4:
    """4-tuple connection for IPv4."""
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int


@dataclass(frozen=True)
class Tuple4Conn6:
    """4-tuple connection for IPv6."""
    src_ip: int  # 128-bit integer
    dst_ip: int
    src_port: int
    dst_port: int


@dataclass(frozen=True)
class Tuple5Conn4:
    """5-tuple connection for IPv4."""
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    stack_code: int


@dataclass(frozen=True)
class Tuple5Conn6:
    """5-tuple connection for IPv6."""
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    stack_code: int


def tuple4_extend(conn, stack_code: int):
    """Extend tuple4 to tuple5 with stack code."""
    if isinstance(conn, Tuple4Conn4):
        return Tuple5Conn4(conn.src_ip, conn.dst_ip, conn.src_port, conn.dst_port, stack_code)
    elif isinstance(conn, Tuple4Conn6):
        return Tuple5Conn6(conn.src_ip, conn.dst_ip, conn.src_port, conn.dst_port, stack_code)
    raise TypeError(f"Unknown connection type: {type(conn)}")


def tuple_conn_reverse(conn):
    """Reverse source and destination in connection tuple."""
    if isinstance(conn, Tuple5Conn4):
        return Tuple5Conn4(conn.dst_ip, conn.src_ip, conn.dst_port, conn.src_port, conn.stack_code)
    elif isinstance(conn, Tuple5Conn6):
        return Tuple5Conn6(conn.dst_ip, conn.src_ip, conn.dst_port, conn.src_port, conn.stack_code)
    raise TypeError(f"Unknown connection type: {type(conn)}")


def ip_to_str(ip: int, is_ipv6: bool = False) -> str:
    """Convert IP address integer to string."""
    if is_ipv6:
        # Convert 128-bit integer to IPv6 string
        hex_str = format(ip, '032x')
        groups = [hex_str[i:i+4] for i in range(0, 32, 4)]
        return ':'.join(groups)
    else:
        # Convert 32-bit integer to IPv4 string
        return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"


def str_to_ip4(s: str) -> int:
    """Convert IPv4 string to integer."""
    parts = s.split('.')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def str_to_ip6(s: str) -> int:
    """Convert IPv6 string to 128-bit integer."""
    import ipaddress
    return int(ipaddress.IPv6Address(s))
