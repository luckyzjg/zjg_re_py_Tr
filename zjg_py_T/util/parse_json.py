def util_TryGetParsedJson(data):
    json_data = None
    try:
        json_data = eval(data)
    except SyntaxError, e:
        json_data = None
    return json_data