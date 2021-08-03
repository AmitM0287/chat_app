from django.contrib.auth.models import User


def get_object_by_username(username):
    """
        This method is used to get object according to that username.
        :param id: It's accept username as parameter.
        :return: It's return that object.
    """
    try:
        return User.objects.get(username=username)
    except User.DoesNotExist as e:
        raise User.DoesNotExist
