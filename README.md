# Simple Shannon Baseband Loader for IDA Pro

Il s'agit d'un simple plugin de chargement de firmware pour charger les images du modem Samsung Exynos "Shannon" dans [IDA Pro](https://hex-rays.com/ida-pro/) or [IDA Home ARM](https://hex-rays.com/ida-home/). Ce chargeur est conçu pour effectuer la tâche la plus importante pour charger une image Shannon, de plus, il doit être facile à comprendre et à personnaliser.

Le chargeur devrait fonctionner avec la plupart des images de modem Samsung Exynos contenant une table des matières incluant les vidages sur incident. Des images compatibles sont disponibles, par exemple, dans les mises à jour des téléphones Exynos. Le nom de fichier typique est « modem.bin ». Les images sont parfois compressées avec lz4. Décompressez-les avant le chargement à l'aide de l'utilitaire lz4 présent sur la plupart des distributions Linux.

Le chargeur a été testé avec un ensemble plus large d'images, des plus anciennes (par exemple, G8700, S7) aux plus récentes (par exemple, S22, S24). Le chargement des images récemment créées fonctionne correctement, y compris l'identification des tâches.

# Comment utiliser ce chargeur

Pour utiliser le chargeur, installez simplement `shannon_load.py` dans votre [IDA Pro](https://hex-rays.com/ida-pro/) ou [IDA Home ARM](https://hex-rays.com/ida-home/) dossier loader et les autres fichiers python dans le dossier python IDA. `install.sh` vous aidera dans cette tâche, si vous souhaitez le faire manuellement, veuillez jeter un œil à l'intérieur. Pour [IDA Pro](https://hex-rays.com/ida-pro/) 9.0, 8.3 et 8.4 and [IDA Home ARM](https://hex-rays.com/ida-home/) exécutez le programme d'installation avec l'une des options de ligne de commande suivantes :

```
-d <dir> spécifie le répertoire d'installation d'IDA
-r exécuter IDA après l'installation
-a mode automatique, recherche automatique du répertoire d'installation d'IDA
-t mode test, combine -a -r et activation de la journalisation dans IDA
-h afficher l'aide
```

Une fois l'installation terminée, ouvrez un fichier « modem.bin » extrait d'une mise à jour OTA dans IDA. Le chargeur devrait détecter le format de la table des matières et charger l'image en conséquence. Le script de post-processeur ajoutera des informations de segment supplémentaires une fois l'analyse initiale terminée. Ajouter les segments dès le début perturberait et ralentirait le processus d'analyse.

Le module de post-traitement effectue la majeure partie du travail et son exécution prendra un certain temps ; soyez patient. Toutes les étapes effectuées par le post-processeur se trouvent dans des fichiers individuels copiés dans « <IDAHOME>/python/ ». Vous pouvez les utiliser comme modules Python individuels si nécessaire. Consultez le post-processeur pour plus de détails. L'analyse complète d'une image de modem prend environ 10 minutes avec un matériel standard.

## Comment fonctionne le chargeur

L'en-tête de la table des matières est une structure simple que le chargeur lit pour créer une base de données du fichier avec des segments et des points d'entrée correctement alignés. Pour plus d'informations, consultez le code contenu dans ce référentiel.

Le chargeur reconnaîtra un binaire de modem Shannon basé sur la table des matières et le chargera. Après le traitement de base et l'analyse automatique initiale, un post-traitement approfondi est effectué. Le flux de travail de post-traitement effectuera les tâches suivantes :

* Restaurer les entrées et structures de trace de débogage
* Renommer les fonctions en fonction de diverses références de chaîne
* Renommer les fonctions de services supplémentaires (`ss_*`) en fonction des fonctions du journal de débogage
* Identifier le matériel et la fonction d'initialisation du processeur
* Restaurer la table du processeur et mapper la mémoire en conséquence
* Identifier les mnémoniques liés à la MMU et les étiqueter
* Identifier le chargeur de dispersion
* Effectuer le chargement et la décompression de dispersion ([LZ77-like](https://developer.arm.com/documentation/dui0474/j/linker-optimization-features/how-compression-is-applied) schéma de compression)
* identifier les fonctions importantes de la couche d'abstraction de la plateforme
* identifier et étiqueter toutes les fonctions d'initialisation des tâches 

Après cela, votre « idb » ou « i64 » devrait être prêt à fonctionner afin que vous puissiez vous concentrer sur la rétro-ingénierie du modem.

# À propos de Samsung Shannon

## Histoire

Shannon est une série de circuits intégrés de Samsung LSI. Le produit le plus remarquable de cette série est le processeur de bande de base Shannon. Shannon est le nom d'une gamme de circuits intégrés et non celui du modem lui-même. Vous trouverez peut-être d'autres circuits intégrés Shannon fabriqués par Samsung. Un ensemble typique de circuits intégrés Shannon comprend un circuit de bande de base, un émetteur-récepteur RF, un circuit de gestion de l'alimentation et un circuit de suivi d'enveloppe. Tous portent des références différentes. Par exemple, la bande de base Shannon est 5300, l'émetteur-récepteur RF est 5510, le PMIC est 5200, etc. Attention, il s'agit de composants différents. Vous trouverez peu d'informations sur Shannon sur le site web de Samsung ; la bande de base est désignée par le terme « bande de base ». [Exynos Modem](https://semiconductor.samsung.com/emea/processor/modem/) plutôt.

Aujourd'hui, le circuit intégré de bande de base est généralement intégré directement au système sur puce Exynos. Pour des configurations spécifiques, des circuits intégrés de bande de base autonomes sont encore commercialisés. Les utilisateurs de ces solutions autonomes sont notamment les constructeurs automobiles ou les fournisseurs d'IoT.

Historiquement, la bande de base Shannon a été développée au moins depuis 2005. À ses débuts, elle portait le nom de CMC. Le CMC220 était la première version LTE du circuit intégré, lancée en 2011, peu après le premier processeur Exynos. Samsung la célèbre encore aujourd'hui dans certains de ses produits. [company presentations](https://images.samsung.com/is/content/samsung/assets/global/ir/docs/business-introduction/Samsung_Investor_Presentation_SLSI_2020_v1.pdf). 

Le nom « Shannon » est un hommage à [Claude Shannon](https://en.wikipedia.org/wiki/Claude_Shannon), Père de la théorie de l'information et de l'ère de l'information. D'autres références à des scientifiques importants du domaine sont présentes dans les matériels et les micrologiciels Samsung. Par exemple, certains composants radio sont appelés Marconi, en référence à [Guglielmo Marconi](https://en.wikipedia.org/wiki/Guglielmo_Marconi) un pionnier dans le domaine de la transmission radio et inventeur de la première antenne fonctionnelle.

## RTOS

Le RTOS utilisé par Samsung pour les circuits intégrés Shannon s'appelle ShannonOS. Il me semble que ShannonOS est un cœur Nucleus rebaptisé. Les anciennes versions de CMC l'identifient même par son nom d'origine. Le système est développé à l'aide du compilateur ARM RVCT, dont les numéros de version augmentent progressivement.

Au-dessus du RTOS, Samsung a créé une couche d'abstraction de plateforme (PAL) servant d'interface aux fonctionnalités de bas niveau gérant le matériel. Les couches d'abstraction de plateforme sont un modèle de conception courant dans de nombreux projets de développement embarqué. Généralement, la couche matérielle est appelée couche d'abstraction matérielle (HAL). Sur les anciens modems, la HAL n'était jamais explicitement mentionnée ni étiquetée comme telle ; les nouveaux modems (à partir de 2023) disposent même de tâches de gestion HAL et d'une séparation claire. Cela est peut-être dû au fait que les fonctionnalités de bas niveau/de base ont été reprises de Nucleus et n'ont jamais fait partie de la conception interne initiale.

La PAL exécute des fonctionnalités telles que la gestion des tâches et d'autres opérations de gestion de haut niveau. Les fonctionnalités les plus intéressantes de la bande de base, telles que les analyseurs de paquets pour GSM/LTE/5G ou la journalisation (DM), sont exécutées dans des tâches individuelles planifiées par le PAL. Le chargeur identifie les tâches individuelles et les étiquette. Voir « shannon_pal_reconstructor.py » pour plus de détails.

Si vous consultez un vidage sur incident ou recherchez la fonctionnalité correspondante dans « modem.bin », vous verrez la bannière de journal suivante. Elle fournit des informations sur le système et le processeur :

```
===================================================
            DEVELOPMENT PLATFORM
 - ARM Emulation Baseboard | Cortex-R7
 - Software Build Date : 
 - Software Builder    : 
 - Compiler Version    : ARM RVCT 50.6 [Build 422]
    Platform Abstraction Layer (PAL) Powered by
               CP Platform Part
===================================================
```

L'image du modem est créée avec ARM RVCT, comme illustré ci-dessus. Correspondance entre la version RVCT et la chaîne d'outils utilisée. [can be found here](https://developer.arm.com/documentation/ka005901/1-0?lang=en&rev=3). La build 422 ci-dessus correspond à Keil MDK 5.22, version 5.06u4 du compilateur RVCT/Arm. Cette version de RCVT est disponible sur le site [ARM website here](https://developer.arm.com/downloads/view/ACOMP5?entitled=true&term=rvct&revision=r5p6-04rel1). Ce chargeur détecte les compilateurs ARM hérités installés sous Linux et demande de définir leurs inclusions comme options de compilation pour une analyse plus approfondie. De plus, plusieurs signatures FLIRT prédéfinies sont incluses pour identifier les fonctions RVCT dans le binaire.

## Cortex-R and Cortex-A

Quelques changements ont eu lieu autour de la sortie de la S20 : les bandes de base Shannon ont été mises à niveau de Cortex-R vers Cortex-A. Parallèlement, des vérifications de pile supplémentaires ont été introduites. Cependant, les cookies de pile semblent statiques ; compte tenu des valeurs aléatoires utilisées, il est difficile de savoir si les développeurs ont réellement compris la raison de cette atténuation.

Une autre nouveauté issue de la modification principale est l'unité de gestion de la mémoire (MMU). Techniquement, la MMU assure la sécurité du domaine et des capacités de gestion avancées, tandis que le MPU n'offre qu'un mappage et une protection de base. Pour de nombreuses images plus anciennes, les fonctionnalités avancées de la MMU sont désactivées en définissant la table de traduction à zéro et la sécurité du domaine à -1. Les images Tensor et S22+ récentes semblent utiliser davantage la MMU. ShannonOS utilise encore un espace d'adressage continu.

Le chargeur identifie les instructions MRC/MCR dans l'image et les commente. Voir « shannon_mpu.py » pour plus de détails.

## IDA Compatibility And Installation

Testé avec [IDA Pro](https://hex-rays.com/ida-pro/) 9.x (9.0), 8.x (8.3 to 8.4 SP2) ainsi que [IDA Home ARM](https://hex-rays.com/ida-home/). Peut fonctionner sur les versions à partir de 7.x en utilisant l'API idapython remaniée.

Comme je travaille sous Linux, le fichier « install.sh » est un script Bash. Si vous utilisez OS X ou Windows, vous pouvez effectuer l'installation manuellement en copiant les fichiers dans leurs répertoires respectifs pour installer le chargeur manuellement :

Script | Installation Directory
|---|---|
shannon_load.py | IDADIR/loaders/
shannon_postprocess.py | IDADIR/python/
shannon_pal_reconstructor.py | IDADIR/python/
shannon_mpu.py | IDADIR/python/
shannon_scatterload.py | IDADIR/python/
shannon_generic.py | IDADIR/python/
shannon_structs.py | IDADIR/python/
shannon_names.py | IDADIR/python/
shannon_debug_traces.py | IDADIR/python/
shannon_funcs.py | IDADIR/python/

## Bugs

Ce code est en cours de développement et doit être utilisé tel quel. Si vous rencontrez une image de modem mal traitée, veuillez remplir un rapport de bug afin que je puisse corriger le chargeur. Assurez-vous de noter la version exacte de l'image de modem que vous essayez de traiter afin que je puisse localiser le fichier.

## Motivation

J'ai suivi une formation sur Shannon et j'ai dû travailler avec Ghidra. Après 20 ans d'expérience avec IDA, je me sens beaucoup plus à l'aise avec ce moteur que le moteur Dragon. J'ai donc commencé à travailler sur ce chargeur avant une autre formation sur Shannon cette année. Partir de zéro m'a permis d'approfondir chaque aspect. Le chargeur tel qu'il est correspond à l'idée que je me fais de son fonctionnement et aux fonctionnalités que je considère nécessaires pour mener des recherches approfondies sur le moteur binaire.

### Formations fortement recommandées

Pour ceux d'entre vous qui souhaitent approfondir leurs connaissances en bande de base, je recommande vivement les formations suivantes. S'agissant de conférences, elles ne sont pas régulières. Restez à l'écoute : elles auront lieu à nouveau.

* https://hardwear.io/netherlands-2022/training/reverse-engineering-emulation-dynamic-testing-cellular-baseband-firmware.php
* https://www.offensivecon.org/trainings/2024/exploiting-basebands-and-application-processors.html

## Travaux remarquables

Quelques liens vers des travaux remarquables liés à la bande de base Shannon :

| Name | URL |
|---|---|
KAIST BaseSpec  | https://github.com/SysSec-KAIST/BaseSpec
Comsecuris ShannonRE | https://github.com/Comsecuris/shannonRE
Hernandez Shannon Ghidra Scripts |https://github.com/grant-h/ShannonBaseband
FirmWire | https://github.com/FirmWire/FirmWire

## License

MIT License, have fun.
