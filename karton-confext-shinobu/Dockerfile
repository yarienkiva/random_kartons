# basé sur https://devopscube.com/reduce-docker-image-size/
# et sur https://github.com/GoogleContainerTools/distroless/blob/main/examples/python3-requirements/Dockerfile

# on fait des crasseries dans une image de build puis on déploie la version propre, pas mal non ?
FROM debian:11-slim AS build
RUN apt-get update -y \
    && apt-get install --no-install-suggests --no-install-recommends -y wget git gcc libssl-dev python3-venv libpython3-dev \
    && python3 -m venv /venv \
    && /venv/bin/pip install --upgrade pip setuptools wheel

# Intermidiary build image for python requirements
FROM build AS build-venv
COPY requirements.txt /requirements.txt
RUN /venv/bin/pip install --disable-pip-version-check -r /requirements.txt

# Intermidiary build image for dnlib
FROM build AS build-dnlib
RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && apt-get update -y && apt-get install -y dotnet-sdk-6.0 \
    && git clone https://github.com/0xd4d/dnlib \
    && cd dnlib \
    && dotnet build

# Final image
FROM gcr.io/distroless/python3-debian11
WORKDIR /app

# Fucking M$
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 
ENV PATH="$PATH:/usr/share/dotnet"

COPY --from=build-dnlib /usr/share/dotnet/ /usr/share/dotnet
COPY --from=build-dnlib /dnlib/Examples/bin/Debug/net6.0/dnlib.dll .
COPY --from=build-venv /venv /venv
COPY . .

WORKDIR /app

ENTRYPOINT ["/venv/bin/python3" , "karton.py"]
