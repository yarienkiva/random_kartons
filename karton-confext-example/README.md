# Karton-Confext

Ce README détaille les étapes pour créer et déployer un nouvel extracteur de config Karton (désigné dans ce document par l'abréviation "Confext").

Ces 4 fichiers sont nécessaires et constitue la base de tous les Confext. Ils doivent tous (à l'exception de `karton.ini`) être modifier en conséquence. Les exemples ci-dessous sont tirés du Confext `njrat`.

```
karton-confext-EXAMPLE
├── Dockerfile
├── karton.ini
├── karton.py
└── requirements.txt
```

## karton.py

### Imports

Les Confext se basant sur des extracteurs préexistants pour extraire les configurations, il faut les importer dans notre `karton.py`.

Exemple :

```py
from karton.core import Config, Karton, Task
from mwdblib import MWDB
import yara

# Custom imports
import subprocess
from main import NjRAT
from config import TREE_PARSER
```

### Constantes

Deux constantes sont utilisées dans les Confext, `FAMILY` et `YARA_RULE` :
- `FAMILY` est une string non-nulle en minuscule qui désigne la famille du malware et `YARA_RULE` 
- `YARA_RULE` peut être soit `None` soit un string désignant le chemin de la règle yara sur disque (`'/path/to/rule.yar'`). Si la valeur est `None` la vérification via "match" yara ne sera pas utilisée.


Exemple :
```py
FAMILY = 'njrat'
YARA_RULE = None
```

### Documentation

Cette documentation apparait en haut de la page de chaque Karton sur le `karton-dashboard`. Ce n'est pas obligatoire mais fortement recommandé ;)

Un bon exemple de documentation à utiliser est celle du [MWDB Reporter](https://github.com/CERT-Polska/karton-mwdb-reporter/blob/master/karton/mwdb_reporter/mwdb_reporter.py#L14).

Exemple :

```py
class Confextractor(Karton):

    """
    Confextractor for NjRAT.

    Example output:
    
    ```
    {
      "host": "0.tcp.sa.ngrok.io",
      "port": "11048",
      "version": "0.7d",
      "campaign": "teste",
      "separator": "|'|'|",
      "install_dir": "%TEMP%",
      "install_name": "server.exe"
    }
    ```

    """

    identity = f"karton.confext.{FAMILY}"
    version = "0.1.0"
```

### Méthode

La seule fonction à modifier est `Confextractor.process_sample`, c'est dans celle-ci que toute la logique d'extraction de config se situe. Elle prend en paramètre le chemin du sample (sur disque) et renvoie la config correspondante **sous forme de `dict`**.


Exemple :

```py
    def process_sample(self, sample_path: str) -> dict:
        output = subprocess.run(["ilspycmd", sample_path], capture_output=True)
        assert output.returncode == 0, "return code should be 0"
        
        tree = TREE_PARSER.parse(output.stdout)
        nj_sample = NjRAT(sample_name=sample_path, tree=tree)
        nj_sample.extract()
        
        assert any(nj_sample.config.values()), "Config is empty"

        return nj_sample.config
```



## requirements.txt

Toutes les dépendances nécessaires au Confext sont à rajouter dans le `requirements.txt`.

Si un `venv` a été utilisé pendant le développement du script d'extraction de base, il suffit simplement d'activer le `venv` puis de `pip freeze >> requirements.txt`. À des fins de lisibilité, il faudra vérifier que `requirements.txt` ne contienne **que les librairies strictement nécessaires et rien d'autre** (librairies non-utilisées, librairies de debug comme IPython, ...).

Un tuto vidéo sur les `python-venv` est disponible [au lien suivant](https://realpython.com/lessons/setting-up-environment-pandas-venv/).

Exemple :

```
# required
karton-core>=4.2.0,<5.0.0
yara-python
mwdblib

# custom
tree-sitter==0.20.1
```



## Dockerfile

Le `Dockerfile` est utilisé pour déployer rapidement un nouveau `Confext`.  Celui-ci se base sur deux choses : les multi-stage builds ([documentation officielle](https://docs.docker.com/build/building/multi-stage/) et [explications complémentaires](https://devopscube.com/reduce-docker-image-size/)]) et une image "Distroless".

**Multi-stage builds** : Les outils de builds, les librairies et autres dépendances sont d'abord installées sur des images intermédiaires avant que seuls les artefacts finaux (sources installées et/ou compilées, rien d'autre) soient copiés sur une image finale. 

**Distroless** : Image sans OS, réduit fortement la taille des images Docker au détriment de certaines fonctionnalités (qui sont inutiles dans notre cas).

```dockerfile
# ...

# Intermidiary build image for ilspycmd
FROM build AS build-ilspycmd
RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && apt-get update -y && apt-get install -y dotnet-sdk-6.0 \
    && dotnet tool install ilspycmd -g

# ...

# Ajouts des variables ENV nécessaires
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 
ENV PATH="$PATH:/root/.dotnet/tools/"

# Copie depuis les images build intermédiaires des sources/librairies
COPY --from=build-ilspycmd /usr/share/dotnet/ /usr/share/dotnet
COPY --from=build-ilspycmd /root/.dotnet/tools/ /root/.dotnet/tools/
```





