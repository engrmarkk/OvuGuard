def return_response(
    message: str = "success",
    data=None,
):
    return {"msg": message, "data": data}
