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

# Running
The example config file uses a local collector and local file storage. Please set the appropriate paths before launching Aleph

## Standalone
To run aleph in a single worker, use the following celery command

    $ celery -A aleph worker -B
    
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

    $  celery -A aleph worker -Q collector -n worker1@%h
    $  celery -A aleph worker -Q manager,store -n worker2@%h
    $  celery -A aleph worker -Q plugins.generic -n worker3@%h  
    $  celery -A aleph worker -Q plugins.sandbox -n worker4@%h  
    ...
    $  celery -A aleph beat # Scheduler

And that should have you up and running
