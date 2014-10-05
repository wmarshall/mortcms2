class ValidationError(Exception):
    def __init__(self, property, message = ''):
        self.property = property
        self.message = message

    def get_message(self):
        return "Error validating %s" % self.property

class LoginError(Exception):
    pass