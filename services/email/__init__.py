import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv
from logger import logger
from environmentals import EMAIL_USER, EMAIL_PASSWORD

load_dotenv()


templates_path = os.path.join(os.getcwd(), "templates")
jinja_env = Environment(loader=FileSystemLoader(templates_path))


def send_email(context):
    try:
        logger.info("Sending Mail")
        smtp_host = "smtp.gmail.com"
        smtp_port = 587
        smtp_user = EMAIL_USER
        smtp_password = EMAIL_PASSWORD

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)

        from_email = "support@teamflow.com"
        to_email = context["email"]
        subject = context["subject"]

        # Load the HTML template
        template = jinja_env.get_template(context["template_name"])

        # Render the template with the context
        body = template.render(**context)

        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject

        # Attach the rendered HTML content
        msg.attach(MIMEText(body, "html"))

        server.sendmail(from_email, to_email, msg.as_string())

        server.quit()
        return "Mail sent successfully"

    except Exception as e:
        logger.exception("Failed to send mail from celery")
        logger.error(f"{e}: error@celery/send_mail")
        return "Failed to send mail"
