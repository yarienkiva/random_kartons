# Example Dockerfile for the Confextractors
#
# Build : docker build --tag karton-confext-EXAMPLE .
# Run   : docker run --rm -d --network=MWDB-NETWORK --name=karton-confext-EXAMPLE karton-confext-EXAMPLE
#
# based on: - https://devopscube.com/reduce-docker-image-size/
#           - https://github.com/GoogleContainerTools/distroless/blob/main/examples/python3-requirements/Dockerfile

# Base build image: Installs python and build tools
FROM debian:11-slim AS build
RUN apt-get update -y \
    && apt-get install --no-install-suggests --no-install-recommends -y wget git gcc libssl-dev python3-venv libpython3-dev \
    && python3 -m venv /venv \
    && /venv/bin/pip install --upgrade pip setuptools wheel

# Intermidiary build image: installs python requirements to /venv
FROM build AS build-venv
COPY requirements.txt /requirements.txt
RUN /venv/bin/pip install --disable-pip-version-check -r /requirements.txt

# # Example other Intermidiary build image: installs dotnet-sdk-6.0 and ilspycmd
# FROM build AS build-ilspycmd
# RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb \
#     && dpkg -i packages-microsoft-prod.deb \
#     && apt-get update -y && apt-get install -y dotnet-sdk-6.0 \
#     && dotnet tool install ilspycmd -g

# Final image: distroless image, debian11 and python3.9
FROM gcr.io/distroless/python3-debian11
WORKDIR /app

# # Set required ENV variables 
# ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
# ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 
# ENV PATH="$PATH:/root/.dotnet/tools/"

# Copy over source and built  dependencies
COPY --from=build-venv /venv /venv
# COPY --from=build-ilspycmd /usr/share/dotnet/ /usr/share/dotnet
# COPY --from=build-ilspycmd /root/.dotnet/tools/ /root/.dotnet/tools/
COPY . .

WORKDIR /app

ENTRYPOINT ["/venv/bin/python3" , "karton.py"]
