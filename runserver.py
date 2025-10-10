if __name__ == "__main__":
    import os

    os.system(
        "uvicorn settings:create_app --host 0.0.0.0 --port 7000 --reload --factory"
        # "uvicorn settings:create_app --host 0.0.0.0 --port 7000 --workers 4 --factory"
    )
