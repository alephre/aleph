FROM python:3.5-slim
MAINTAINER Jan Seidl <jseidl@wroot.org>

ENV INSTALL_PATH /aleph
RUN mkdir -p $INSTALL_PATH

WORKDIR $INSTALL_PATH

RUN apt-get -qq update
RUN apt-get -qq install python3-dev build-essential
# Uncomment the line below if using MySQL as a database backend
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY aleph/ aleph/
COPY config.yaml.docker config.yaml

ENV FOLDER_PATH /opt/aleph
RUN mkdir -p $FOLDER_PATH/storage
RUN mkdir -p $FOLDER_PATH/relay
