#!/bin/sh
# Primero limpiamos cualquier regla haciendo un flush
# tambien reseteamos contadores (-Z) y las Chain personalizadas
# que se hayan creado (-X)
sudo iptables -F 
sudo iptables -X 
sudo iptables -Z 

# Habilitar la interfaz loopback para servicios internos
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Habilitar solicitudes udp de tipo dns
iptables -A OUTPUT -p udp --dport 53  -m state --stateNEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# Rechazar todo el tráfico udp entrante
iptables -A INPUT -p udp -j REJECT

# Rechazar todo el tráfico tcp de entrada que quiera iniciar una conexión tcp

iptables -A INPUT -p tcp --syn -j REJECT

# El resto de tráfico de red es permitido por la política por defecto aceptar
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
