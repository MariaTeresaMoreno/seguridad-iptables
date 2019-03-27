#!/bin/sh

# Configurar como un enrutador, habilitando el reenvío de paquetes (forwarding)
echo "1" > /proc/sys/net/ipv4/ip_forward

# Protección contra el flood de tcp_syn
echo "1" > /proc/sys/net/ipv4/tcp_syncookies

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Habilitar la interfaz loopback para algunos servicios internos
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Vulnerabilidad mDNS
iptables -A FORWARD -p udp --dport 5353 -d 192.168.111.109 -j DROP   

# Habilitar el reenvio de paquetes a las tres subredes
iptables -A FORWARD -s 192.168.111.0/24 -j ACCEPT
iptables -A FORWARD -d 192.168.111.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.112.0/24 -j ACCEPT
iptables -A FORWARD -d 192.168.112.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.110.0/24 -j ACCEPT
iptables -A FORWARD -d 192.168.110.0/24 -j ACCEPT

# Prohibir la comunicación entre concejalías (solo salida nat)
i​ptables -t mangle -A PREROUTING -s 192.168.111.0/24 -d 192.168.112.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.112.0/24 -d 192.168.111.0/24 -j DROP

#Activa el NAT para todas las organizaciones
iptables -t nat -A POSTROUTING -s 192.168.110.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.111.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.112.0/24 -o eth0 -j MASQUERADE

# Redireccionar solicitudes web entrantes al servidor web en 192.168.111.109
iptables -t nat -A PREROUTING -p tcp -d 10.0.2.15 --dport 80 -j DNAT --to-dest 192.168.111.109 
iptables -t nat -A POSTROUTING -p tcp -d 192.168.111.109 --dport 80 -j SNAT --to-source 10.0.2.15

# Permitir acceso ssh para configuración remota
iptables -A INPUT -p tcp -s 192.168.110.0/24 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Habilitar resolución dns (tcp/udp)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -j ACCEPT

# Habilitar conexión web
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT

#Habilitar FTP
iptables -A INPUT -p tcp --dport 20 -d 192.168.111.109 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 20 -m state --state ESTABLISHED -j ACCEPT

#Mejoras
#TCP no válidos
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
# XMAS Scan
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
# NULL Scan
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
# SYN/RST Scan
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# SYN/FIN Scan
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
# FIN Scan
iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
#Paquetes con MSS no válido 
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

#bloquear fuerza bruta ssh
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

# Descartar ICMP
iptables -t mangle -A PREROUTING -p icmp -j DROP

#Bloquear conexiones masivas TCP(no + de 80conexiones/user)
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

#Limitar conexiones tcp por min a 20 conexiones
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

# Inundación paquetes RST, rechazo de smurf attack.

iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Bloqueo de la ip del ataque 24h.
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Eliminar ip tras 24h.
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# Registro de scanners en puerto 139.
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

#Establecimiento de la política por defecto
iptables -A INPUT -j DROP 
iptables -A FORDWARD -j DROP
iptables -A OUTPUT -j ACCEPT

# guardar
iptables-save > mi_cortafuegos