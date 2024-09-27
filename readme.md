# Projet de Pare-feu SDN - Bachelor Firewall

Ce dépôt contient l'implémentation d'un pare-feu pour un réseau défini par logiciel (SDN) en utilisant le contrôleur POX et le protocole OpenFlow. Ce projet vise à démontrer comment gérer et filtrer le trafic réseau en fonction de règles de sécurité définies dans le fichier `firewallpolicies.csv`.

## Table des matières

- [Aperçu](#aperçu)
- [Fichiers](#fichiers)
- [Installation](#installation)
- [Exécution](#exécution)
- [Tests](#tests)


## Aperçu

Ce projet met en œuvre une solution de pare-feu centralisée pour le SDN. En utilisant le contrôleur POX, le projet permet d'appliquer des règles de sécurité en temps réel sur le trafic réseau. Le trafic est filtré selon les adresses IP, les ports et les protocoles définis dans le fichier `firewallpolicies.csv`.

La topologie réseau est simulée via Mininet, et le pare-feu est implémenté en tant que script Python qui s'exécute dans le contrôleur POX.

## Fichiers

Voici les fichiers principaux du projet :

- **firewallpolicies.csv** : Contient les règles de sécurité, définies par les adresses IP, les ports et les protocoles.
- **myfirewall.py** : Script Python qui implémente la logique du pare-feu sur POX.
- **topology.py** : Script Python pour créer la topologie réseau dans Mininet (1 commutateur et 4 hôtes).

## Installation

Suivez les étapes ci-dessous pour installer et configurer le projet :

### 1. Installer Mininet

Clonez le dépôt Mininet et installez-le avec les commandes suivantes :

```bash
git clone https://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -a
```

### 2. Installer POX

Clonez le dépôt du contrôleur POX :

```bash
git clone http://github.com/noxrepo/pox
cd pox
```

### 3. Cloner ce dépôt

Clonez le dépôt du projet dans votre répertoire local :

```bash
git clone https://github.com/etienne-tov/bachelor_firewall.git
cd bachelor_firewall
```

### 4. S'assurer des dépendances

POX utilise Python 2.x, assurez-vous donc que Python 2.x est installé sur votre système, car POX ne supporte pas complètement Python 3.x.

## Exécution

### 1. Démarrer Mininet

Créez la topologie réseau définie dans `topology.py` en exécutant la commande suivante :

```bash
sudo python topology.py
```

Cela génère un réseau avec 1 commutateur et 4 hôtes connectés.

### 2. Démarrer le contrôleur POX avec le pare-feu

Dans une nouvelle fenêtre de terminal, démarrez le contrôleur POX avec le module de pare-feu personnalisé :

```bash
cd pox
./pox.py log.level --DEBUG openflow.of_01 forwarding.l2_learning misc.myfirewall
```

Le contrôleur POX appliquera automatiquement les règles définies dans le fichier `firewallpolicies.csv` et installera les flux sur le commutateur OpenFlow.

## Tests

Une fois que le pare-feu est en marche, utilisez les outils suivants pour tester la connectivité et vérifier si les règles du pare-feu sont appliquées correctement :

### 1. Tester la connectivité avec `pingall`

Dans l'interface CLI de Mininet, utilisez la commande `pingall` pour vérifier la connectivité ICMP entre les hôtes du réseau :

```bash
mininet> pingall
```

### 2. Tester les connexions TCP et HTTP avec `netcat` et `curl`

Utilisez les commandes `nc` (netcat) et `curl` pour simuler des connexions entre hôtes et tester si les règles du pare-feu sont bien appliquées :

```bash
h1 nc -zv 10.0.0.2 22
h2 curl http://10.0.0.3:8080
```

Ces commandes permettront de vérifier si les connexions sont bloquées ou autorisées, selon les règles spécifiées dans `firewallpolicies.csv`.

### 3. Vérifier les règles de flux sur le commutateur

Vous pouvez utiliser la commande suivante pour vérifier les flux installés sur le commutateur OpenFlow :

```bash
mininet> sh ovs-ofctl dump-flows s1
```

Cela affichera les flux actifs sur le commutateur et montrera les actions (acceptation ou blocage) basées sur les règles appliquées par le pare-feu.
