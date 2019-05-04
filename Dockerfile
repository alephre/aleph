FROM python:3.5-slim
MAINTAINER Jan Seidl <jseidl@wroot.org>

ENV INSTALL_PATH /aleph
ENV USER aleph

RUN mkdir -p $INSTALL_PATH
RUN useradd -ms /bin/bash $USER

WORKDIR $INSTALL_PATH

RUN chown -R $USER:$USER $INSTALL_PATH
RUN chmod 755 $INSTALL_PATH

RUN apt-get -qq update
RUN apt-get -qq install build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev
# Uncomment the line below if using MySQL as a database backend
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY aleph/ $INSTALL_PATH/aleph
COPY config.yaml.docker $INSTALL_PATH/config.yaml

ENV FOLDER_PATH /opt/aleph
RUN mkdir -p $FOLDER_PATH/storage
RUN chown -R $USER:$USER $FOLDER_PATH
