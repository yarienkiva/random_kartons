FROM python:3.11-slim-bullseye

COPY . .

# Install DIE
RUN apt update \
        && apt install -y wget \
        && wget -O- https://api.github.com/repos/horsicq/DIE-engine/releases/latest | \
                grep -oE 'https://github.com/horsicq/DIE-engine/releases/download/[0-9\.]+/die_[0-9\.]+_Debian_11_amd64.deb'| \
                uniq | wget -i - \
        && apt install -y ./die*.deb \
	&& pip install --no-cache-dir -r requirements.txt

CMD ["python3", "karton-die.py"]
