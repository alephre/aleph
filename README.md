# Aleph Artifact Inspection Pipeline
This is the Aleph core. Responsible for processing samples and extracting artifacts and intelligence.

[![CircleCI](https://circleci.com/bb/janseidl/aleph2/tree/master.svg?style=svg&circle-token=2adb3b96d890b4a256555e3bb5b8552e5efac0cc)](https://circleci.com/bb/janseidl/aleph2/tree/master)

# Installing
I'm running on a debian VM. Current install expects everything running locally but you can edit config.yaml to whatever you want.

## To install rabbitmq-server

    $ sudo apt-get install rabbitmq-server

## To install elasticsearch    
See: https://www.elastic.co/guide/en/elasticsearch/reference/current/deb.html

## Create a folder for aleph
    mkdir -p /opt/aleph
    cd /opt/aleph

## Create a virtual environment
    $ python3 -m .venv

Then clone git repo to same folder and copy over the sample config
    git clone git@bitbucket.org:janseidl/aleph2.git

## Set up the config.yaml file
    $ cp config.yaml.example config.yaml
    $ vim config.yaml

## Activate virtual environment
    $ source .venv/bin/activate

## Install python dependencies
    $ pip3 install -r requirements.txt

# Creating the index
The index must be created on ES and the aleph mapping applied to the index. This must be done prior to running Aleph. Aleph won't try to create any indexes nor configure ES.

The example below creates and applies the mapping(assuming ES is on localhost):

    $ curl -X PUT http://localhost:9200/aleph
    $ curl -X PUT http://localhost:9200/aleph/_mapping/sample -d @mapping.json --header 'Content-Type: application/json'

# Running
The example config file uses a local collector and local file storage. Please set the appropriate paths before launching Aleph

## Standalone
To run aleph in a single worker, use the following celery command

    $ celery worker -A aleph -B -c 1
    
## Distributed
In the distributed configuration, you can run any combination of workers and queues you want. Just bind the worker to a queue with _-Q queue_ option. 

**Don't forget to give each worker a different name otherwise they will conflict and die.**

#### Default Queues
- collector: Collector agents recieve the collect and ingest commands from the scheduler.
- manager: Perform management tasks such as recieving process requests and dispatching to appropriate plugin queues.
- store: Performs both sample storage and metadata storage requests.
- plugins.generic: Pure-python plugins are routed to this queue. Any worker should be able to handle those plugins 
- plugins.windows: Plugins that require running external PE tools are routed to this queue. Only workers running on Windows platforms should consume this queue.
- plugins.linux: Plugins that require running external ELF tools are routed to this queue. Only workers running on Linux platforms should consume this queue.
- plugins.macos: Plugins that require running external MachO tools are routed to this queue. Only workers running on MacOS platforms should consume this queue.
- plugins.sandbox: Plugins that perform actions that take a long time to run such as sandbox send/recieve are routed to this queue to avoid hogging the pipeline.

### Running

    $  celery worker -A aleph -Q collector -n worker1@%h -c 1
    $  celery worker -A aleph -Q manager,store -n worker2@%h
    $  celery worker -A aleph -Q plugins.generic -n worker3@%h  
    $  celery worker -A aleph -Q plugins.sandbox -n worker4@%h  
    ...
    $  celery -A aleph beat # Scheduler

And that should have you up and running

## Concurrency / Number of concurrent workers

Each `celery` command can run under multiple forked() processes by using the `-c N` parameter.

**DO NOT RUN MORE THAN 1 WORKER (-c 1) FOR COLLECTORS OR GOD WILL MURDER ALL FIRSTBORNS**

## Logging
So far it is configured to pipe log entries to both stdout and *aleph.log*. If you want to suppress file-logging, just omit the *path* directive in the *logging* section of the config file. Also all logger calls are doing *debug* entries, which we must fix (promote some of them to INFO). Error logging is a @TODO as well.

**In order to see the debug log, you must set the log level to debug on the worker**

    $ celery worker -A aleph -B -l debug

# Using Docker

The docker-compose.yml will spawn both rabbitmq and elasticsearch dockers, alongside the 4 aleph machines with the same worker configuration as in the "Distributed" example.

Create a `samples` folder in the same folder of the Dockerfile and call `docker-compose up` to bring them up to speed.

