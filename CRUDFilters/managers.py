import inspect
from django.db import models
from django.conf import settings
from django.core.urlresolvers import resolve


class CRUDException(Exception):
    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class CRUDManager(models.Manager):
    # Class variables, default to none
    auth_function = None
    filter_set = {}
    # Get roles from settings
    all_roles = settings.CRUD_ALL_ROLES
    # Add 'anonymous' and 'authenticated' if they're not in all_roles yet.
    for required_role in ['anonymous', 'authenticated']:
        if required_role not in all_roles:
            all_roles.append(required_role)

    @classmethod
    def all_objects(cls, queryset, user, request):
        """
        Returns all objects for this model.
        """
        return queryset

    @classmethod
    def single_read(cls, original_function):
        def single_read_function(queryset, user, request):
            if hasattr(request, '_request'):
                wsgi_request = request._request
            else:
                wsgi_request = request

            if wsgi_request.method == "GET":
                # 404 error is alright here...
                path = resolve(request.path)
                viewset = path.func.cls()
                # Check request URL for ID, or throw a CRUDException
                viewset.check_request_url_for_id(request)
                kwargs = {'{0}'.format(viewset.lookup_field): viewset.obj_id}
                queryset = queryset.filter(**kwargs)

            return original_function(queryset, user, request)

        # Transfer docstring to this new method
        single_read_function.__doc__ = original_function.__doc__
        return single_read_function

    @classmethod
    def init_filter_set_for_model(cls, model):
        # Init filter_set with None default values.
        cls.filter_set[str(model)] = {}
        for category in ['allowed_methods', 'filter']:
            cls.filter_set[str(model)][category] = {}
            for role in cls.all_roles:
                # We won't fill out any defaults here- by default, we should return no objects.
                cls.filter_set[str(model)][category][role] = {'__default': None}

    @classmethod
    def get_filter_set_for_model(cls, model):
        try:
            model_filter_set = cls.filter_set[str(model)]
        except KeyError:
            cls.init_filter_set_for_model(model)
            model_filter_set = cls.filter_set[str(model)]
        return model_filter_set

    @classmethod
    def set_authorization_function(cls, func):
        cls.auth_function = func

    @classmethod
    def add_permissions(cls, model, permissions, role, func, filter_str='__default'):
        # print("Add permissions for model ", str(model), " | permissions ", permissions, " | role ", role, " | func ", str(func), " | filter_str ", filter_str)
        # 'C' does not require a function. If we have any other permissions, check to make sure func is a function.
        if permissions.upper() != 'C':
            if not inspect.ismethod(func) and not inspect.isfunction(func):
                raise CRUDException("func must be a valid function or bound method", 500)

            if inspect.isfunction(func):
                # Make sure this function accepts the correct arguments in the correct order
                func_args = inspect.getargspec(func)[0]
                acceptable_args = [
                    ['self', 'queryset', 'user', 'request'],
                    ['cls', 'queryset', 'user', 'request'],
                    ['queryset', 'user', 'request']
                ]
                if func_args not in acceptable_args:
                    raise CRUDException("func must accept arguments self (optional), user, queryset", 500)

        # TODO: Do this for as_manager() methods, too. as_manager magic seems to convert
        # args/kwargs to positional params in a way that's not visible to introspection tools.

        valid_permissions = ['C', 'R', 'U', 'D']
        for char in permissions:
            if char.upper() not in valid_permissions:
                raise CRUDException(char + " is not a valid permission (must be one of " + str(valid_permissions) + ")", 500)

        # Make sure we have an index for this model in the filter_set table
        model_filter_set = cls.get_filter_set_for_model(model)

        # Make sure this role is valid.
        try:
            model_filter_set['allowed_methods'][role]
            model_filter_set['filter'][role]
        except KeyError:
            raise CRUDException(role + " is not a valid role", 500)

        cls.filter_set[str(model)]['allowed_methods'][role][filter_str] = permissions.upper()
        cls.filter_set[str(model)]['filter'][role][filter_str] = func

        # print("After: ", cls.filter_set)
