from django.db import models
from .managers import CRUDManager, CRUDException


class CRUDFilterModel(models.Model):

    class Meta:
        abstract = True

    @classmethod
    def verify_user_has_role(cls, user, role, request):
        """
        Call user-defined auth function to determine if this user can use this role.
        """
        if role in ['anonymous', 'authenticated']:
            return True
        elif role == "admin":
            return user.is_superuser

        if CRUDManager.auth_function is None:
            raise CRUDException("You must define an auth_function for CRUDManagerMixin", 500)
        try:
            value = CRUDManager.auth_function(role, user, request)
        except Exception as exc:
            raise CRUDException("Your auth_function in CRUDManager threw an exception: " + str(exc), 500)
        if not value:
            raise CRUDException("This user is not authorized to use this role", 403)

        return True

    @classmethod
    def role_can_perform_operation_with_filter(cls, role, operation, filter_str):
        """
        For this class, make sure this role can perform this operation (with this filter)
        """
        # print("Check cls ", str(cls), " role ", role, " operation ", operation, " filter_str ", filter_str)
        if operation.upper() not in ['C', 'R', 'U', 'D']:
            raise CRUDException("Operation must be one of: 'C', 'R', 'U', 'D'", 500)

        try:
            filters = CRUDManager.get_filter_set_for_model(cls)['allowed_methods'][role]
        except KeyError:
            # Users that are simply authenticated are not allowed:
            # DUBIOUS LOGIC  -- return this if filters is {'__default': None} and role is authenticated. anonymous = 401
            if role == "authenticated":
                raise CRUDException("You must specify a role for this endpoint in the ROLE header", 400)
            # Invalid role:
            else:
                raise CRUDException(role + " is not a valid role", 400)
        try:
            allowed_methods = filters[filter_str]
        except KeyError:
            # print(filter_str, " not a valid filter for cls ", str(cls), ", role ", role, " -- ", filters)
            raise CRUDException(filter_str + " is not a valid filter here", 400)

        # print("Role: ", role, ", allowed_methods: ", str(allowed_methods), " operation: ", operation)
        if allowed_methods is not None and operation.upper() in [method.upper() for method in allowed_methods]:
            return True
        else:
            return False

    @classmethod
    def __get_objects(cls, user, role, operation, filters=['__default'], request=None):
        """
        Return queryset that this user/role has access to (given these filters)
        """
        # UNSAFE to call this function from outside of the "get_queryset_or_false" function.
        # If this is not an abstract class, start with all objects, and filter down.
        if hasattr(cls, 'objects'):
            object_set = cls.objects.all()
        else:
            object_set = []

        try:
            for filter_str in filters:
                # print("__get_objects with role ", role, " operation ", operation, " filter ", filter_str, " func: ", str(CRUDManager.get_filter_set_for_model(cls)['filter'][role][filter_str]))
                object_set = CRUDManager.get_filter_set_for_model(cls)['filter'][role][filter_str](object_set, user, request)
        except CRUDException:
            # Elevate CRUDExceptions to be caught by middleware
            raise
        except Exception:
            raise CRUDException("Error calling filter functions. Please see the 'QuerySet vs Manager Methods' section of the documentation.", 400)

        return object_set

    @classmethod
    def check_for_permissions(cls, user, role, operation, request, filters=['__default']):
        """
        Make sure this role can perform this operation
        """
        cls.verify_user_has_role(user, role, request)
        for filter_str in filters:
            if not cls.role_can_perform_operation_with_filter(role, operation, filter_str):
                raise CRUDException("Cannot perform this operation with this role.", status_code=403)

    @classmethod
    def get_queryset_or_false(cls, user, role, operation, filters=['__default'], request=None, _id=-1, lookup_field='pk'):
        """
        Return queryset (and make sure this item is in the queryset)
        """
        # Redundant?
        print("Make sure request is not none here")
        cls.check_for_permissions(user, role, operation, request, filters)
        # Get our objects:
        object_set = cls.__get_objects(user, role, operation, filters, request)

        # If this is a single-object operation, we have to have a valid ID
        if operation.upper() in ['U', 'D']:
            if _id == -1:
                raise CRUDException("ID must be specified for Update and Delete", 400)
            else:
                kwargs = {'{0}'.format(lookup_field): _id}
                if object_set.filter(**kwargs).count() == 0:
                    # It's possible that the object just doesn't exist... but we'll return a 403 to obfuscate
                    raise CRUDException("Cannot perform this operation on this object.", status_code=403)

        # Later, we can start to perform different operations here:
        # if operation == 'R':
        #    return object_set
        # elif operation == "C":
        #    ....

        return object_set
