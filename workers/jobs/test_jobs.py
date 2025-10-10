from workers.config import celery, shared_task


@shared_task
def test_cron():
    print("test_cron")
    return True
