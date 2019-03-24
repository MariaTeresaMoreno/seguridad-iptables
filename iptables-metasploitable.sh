#!/bin/sh
# Primero limpiamos cualquier regla haciendo un flush
# tambien reseteamos contadores (-Z) y las Chain personalizadas
# que se hayan creado (-X)
sudo iptables -F 
sudo iptables -X 
sudo iptables -Z 

#Establecimiento de la política por defecto
sudo iptables -A INPUT -j DROP  #trafico entrante rechazado
sudo iptables -A FORDWARD -j ACCEPT
sudo iptables -A OUTPUT -j ACCEPT

# Habilitar la interfaz loopback para algunos servicios internos
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT


# Habilitar resolución dns (tcp/udp)
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p udp --sport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 53 -j ACCEPT

#Habilitar tráfico VoIP
sudo iptables -A INPUT -p udp --dport 5060 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5060 -m state --state NEW,ESTABLISHED -j ACCEPT

# RTP - the media stream
# (related to the port range in /etc/asterisk/rtp.conf) 
 iptables -A INPUT -p udp -m udp --dport 10000:20000 -j ACCEPT

# Rechazar todo el tráfico udp que no cumpla la regla anterior
sudo iptables A INPUT -p udp -j REJECT

# Habilitar conexión web
sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Habilitar conexión web segura (HTTPS)
sudo iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Habilitar SNMP
sudo iptables -A INPUT -p udp --dport 161 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 161 -m state --state ESTABLISHED-j ACCEPT


# Permitir acceso ssh para configuración remota
sudo iptables -A INPUT -p tcp -s 192.168.110.0/24 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Poner limite a PING para evitar DDoS
sudo iptables -A INPUT -p icmp -j --icmp-type echo-request -m limit --limit 5/s ACCEPT

# Prevención contra SYN Dos
sudo iptables -N SYN_DOS
sudo iptables -A INPUT -p tcp --syn -j SYN_DOS
sudo iptables -A SYN_DOS -m limit --limit 5/s --limit-burst 10 -j RETURN
sudo iptables -A SYN_DOS -j DROP

# Rechazar tráfico tcp que no cumpla las condiciones anteriores
sudo iptables -A INPUT -p tcp --syn -j REJECT

# Guardar las reglas
iptables-save