#!/bin/sh
# Primero limpiamos cualquier regla haciendo un flush
# tambien reseteamos contadores (-Z) y las Chain personalizadas
# que se hayan creado (-X)
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F 
iptables -X 
iptables -Z 

# Habilitar la interfaz loopback para algunos servicios internos
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Habilitar resolución dns (tcp/udp)
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -j ACCEPT

# Habilitar conexión web
iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Habilitar conexión web segura (HTTPS)
iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

#Habilitar tráfico VoIP
iptables -A INPUT -p udp --dport 5060 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 5060 -m state --state ESTABLISHED,RELATED -j ACCEPT

# RTP - the media stream
# (related to the port range in /etc/asterisk/rtp.conf) 
 iptables -A INPUT -p udp -m udp --dport 10000:20000 -j ACCEPT

# Habilitar SNMP
iptables -A INPUT -p udp --dport 161 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --sport 161 -m state --state ESTABLISHED -j ACCEPT

# Rechazar todo el tráfico udp que no cumpla la regla anterior
iptables A INPUT -p udp -j REJECT

# Habilitar FTP
iptables -A INPUT -p tcp --dport 20 state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 20 -m state --state ESTABLISHED -j ACCEPT

# Permitir acceso ssh para configuración remota
iptables -A INPUT -p tcp -s 192.168.110.0/24 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Habilitar RPCBind
iptables -A INPUT -p tcp --dport 111 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 111 -j ACCEPT

# Habilitar NETBIOS solo para dep-central
iptables -A INPUT -s 192.168.110.0/24 -p tcp -m multiport --dports 445,139 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -s 192.168.110.0/24 -p udp -m multiport --dports 445,139 -m state --state ESTABLISHED -j ACCEPT

# Habilitar servidor web
iptables -A INPUT -p tcp --dport 8081 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8081 -m state --state ESTABLISHED -j ACCEPT

# Poner limite a PING para evitar DDoS (acceso solo a dep-central)
iptables -A INPUT -p icmp -s 192.168.110.0/24 -j --icmp-type echo-request -m limit --limit 5/s ACCEPT

# No aceptar paquetes que no estén bien formados
iptables -A INPUT -p tcp -m tcp ! --tcp-flags SYN,RST,ACK SYN -j ACCEPT 

#Bloquear ping para todo lo que no sea dep-central
iptables -A INPUT --p icmp -j DROP


# Prevención contra SYN Dos
iptables -N SYN_DOS
iptables -A INPUT -p tcp --syn -j SYN_DOS
iptables -A SYN_DOS -m limit --limit 5/s --limit-burst 10 -j RETURN
iptables -A SYN_DOS -j DROP

# Rechazar tráfico tcp que no cumpla las condiciones anteriores
iptables -A INPUT -p tcp --syn -j REJECT

#Establecimiento de la política por defecto
iptables -A INPUT -j DROP  #trafico entrante rechazado
iptables -A FORDWARD -j ACCEPT
iptables -A OUTPUT -j ACCEPT

# Guardar las reglas
iptables-save