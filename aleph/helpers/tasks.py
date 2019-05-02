from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

def call_task(task_name, args, routing_key='celery'):

    from aleph import app

    try:
        app.send_task(task_name, args=args, routing_key=routing_key)
    except Exception as e:
        logger.error("Error dispatching task %s: %s" % (task_name, str(e)))
