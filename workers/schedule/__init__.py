from celery.schedules import crontab


imports = ("workers.jobs.test_jobs",)
task_result_expires = 30
timezone = "Africa/Lagos"

accept_content = ["json", "msgpack", "yaml"]
task_serializer = "json"
result_serializer = "json"

beat_schedule = {
    "test_cron": {
        "task": "workers.jobs.test_jobs.test_cron",
        "schedule": crontab(minute="29", hour="11"),
    },
}
