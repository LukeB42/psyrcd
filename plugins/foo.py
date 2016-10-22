__package__ = [{"name": "foo", "type": "command", "description": "Test plugin."}]

def foo(ctx):
    print(dir())
    print(ctx)
    return "42"
    return str(ctx)

def __init__(ctx):
    """
    Mainly for modifying the server instance.



    Possible to define __package__ earlier than this point, enclose some
    variables in a callable and then modify __package__.
    """
    __package__[0]["callable"] = foo

def __del__(ctx):
    print(ctx)


# Note that by this point, after __init__ has been invoked, __package__ is equal to the following:
# __package__ = [{"name": "foo", "type": "command", "description": "Test plugin.", "callable": foo}]
