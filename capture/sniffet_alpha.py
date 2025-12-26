# capture/sniffer_alpha.py
from scapy.all import sniff, IP

# Le nom de l'interface à écouter. 
# Utilisez celui qui est connecté à KALI (ex: enp0s8)
INTERFACE_TO_SNIFF = "enp0s8" 

def packet_callback(packet):
    """Fonction appelée pour chaque paquet capturé."""
    # On vérifie si c'est un paquet IP (pour ignorer l'ARP, etc.)
    if IP in packet:
        print(f"[{packet[IP].proto}] {packet[IP].src} -> {packet[IP].dst} | {packet.summary()}")
    else:
        # Affiche les autres paquets (ARP, etc.)
        print(f"[NON-IP] {packet.summary()}")


print(f"🚀 Démarrage du sniffer sur {INTERFACE_TO_SNIFF}. Capture de 10 paquets...")
# store=0 pour ne pas saturer la RAM, prn=packet_callback pour appeler la fonction
sniff(iface=INTERFACE_TO_SNIFF, prn=packet_callback, count=10, store=0) 
print("✅ Capture terminée.")
