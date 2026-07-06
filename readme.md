# Projet de Pare-feu SDN - Bachelor Firewall

Ce dépôt contient l'implémentation d'un pare-feu pour un réseau défini par logiciel (SDN) en utilisant le contrôleur POX et le protocole OpenFlow. Le trafic est filtré selon des règles définies dans le fichier `firewallpolicies.csv`, portant sur trois niveaux :

- **les adresses MAC** (couche 2),
- **les adresses IP** (couche 3),
- **les ports et protocoles** TCP/UDP/ICMP (couche 4).

## Table des matières

- [Aperçu](#aperçu)
- [Fichiers](#fichiers)
- [Format des règles](#format-des-règles)
- [Installation](#installation)
- [Exécution](#exécution)
- [Tests](#tests)

## Aperçu

Le module `myfirewall.py` fonctionne en deux phases :

1. **Installation des règles (au démarrage)** : à la connexion du commutateur OpenFlow, le module lit `firewallpolicies.csv` et installe, pour chaque règle, une entrée de flux de priorité 1000 sans action (suppression du paquet). Une règle par défaut de priorité 0 autorise tout autre trafic.
2. **Traitement des paquets (par le commutateur)** : chaque paquet est comparé à la table de flux ; s'il correspond à une règle de blocage il est supprimé, sinon il est transmis normalement. Le contrôleur n'est pas sollicité pour le trafic courant.

La topologie de test est simulée via Mininet (1 commutateur, 4 hôtes).

## Fichiers

- **firewallpolicies.csv** : les règles de restriction (MAC, IP, ports, protocoles).
- **myfirewall.py** : le module de pare-feu pour POX.
- **topology.py** : la topologie Mininet (1 commutateur et 4 hôtes, adresses IP 10.0.0.1-4 et MAC 00:00:00:00:00:01-04).

## Format des règles

```csv
id,src_ip,dst_ip,src_mac,dst_mac,src_port,dst_port,protocol
1,10.0.0.1,10.0.0.2,*,*,*,*,ICMP
2,10.0.0.1,10.0.0.4,*,*,*,*,ICMP
3,*,*,00:00:00:00:00:03,00:00:00:00:00:02,*,*,ALL
4,10.0.0.1,10.0.0.3,*,*,*,80,TCP
5,10.0.0.2,10.0.0.4,*,*,*,22,TCP
6,10.0.0.4,10.0.0.2,*,*,*,53,UDP
```

- Chaque champ accepte le joker `*` (« toute valeur »).
- `protocol` accepte `TCP`, `UDP`, `ICMP` ou `ALL` (tous les protocoles).
- La règle 3 bloque par exemple **tout** le trafic de l'hôte H3 vers l'hôte H2 sur la seule base de leurs adresses MAC.

## Installation

Environnement recommandé : Ubuntu 20.04 LTS (par exemple l'image officielle de la VM Mininet 2.3.0), Python 3.

### 1. Installer Mininet

```bash
git clone https://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -a
```

### 2. Installer POX

```bash
git clone http://github.com/noxrepo/pox
```

### 3. Cloner ce dépôt et installer le module

```bash
git clone https://github.com/abiotov/bachelor_firewall.git
cp bachelor_firewall/myfirewall.py pox/pox/misc/
cp bachelor_firewall/firewallpolicies.csv pox/pox/misc/
```

## Exécution

### 1. Démarrer le contrôleur POX avec le pare-feu

```bash
cd pox
./pox.py log.level --DEBUG openflow.of_01 forwarding.l2_learning misc.myfirewall
```

Le journal affiche une ligne `Adding firewall rule` par règle du CSV, puis `Firewall rules installed`.

### 2. Démarrer la topologie Mininet (dans un second terminal)

```bash
sudo python3 topology.py
```

## Tests

### 1. Connectivité ICMP avec `pingall`

```bash
mininet> pingall
```

Avec la grille de règles fournie, résultat attendu : les paires H1-H2 et H1-H4 sont bloquées (règles ICMP), la paire H2-H3 est bloquée dans les deux sens (règle MAC), soit **50 % de pertes (6/12)**.

### 2. Granularité par port

```bash
mininet> h3 python3 -m http.server 80 &
mininet> h1 nc -zv -w 3 10.0.0.3 80    # bloqué (règle 4), alors que h1 ping h3 fonctionne
mininet> h4 nc -zv -w 3 10.0.0.3 80    # autorisé (aucune règle H4->H3)
mininet> h2 nc -zv -w 3 10.0.0.4 22    # bloqué (règle 5) : expire sans réponse
mininet> h2 nc -zv -w 3 10.0.0.4 8080  # port non filtré : refus immédiat de l'hôte
```

La différence entre « expiration » (paquet supprimé par le pare-feu) et « refus immédiat » (port fermé sur l'hôte) montre que c'est bien le pare-feu qui agit.

### 3. Flux installés sur le commutateur

```bash
mininet> sh ovs-ofctl dump-flows s1
```

Résultat attendu : six entrées `priority=1000 ... actions=drop` reflétant le CSV (on y distingue les critères MAC `dl_src/dl_dst`, IP `nw_src/nw_dst` et ports `tp_dst`), plus une entrée `priority=0 actions=NORMAL`.
