
In settings, add CRUD_ALL_ROLES, like this:
    CRUD_ALL_ROLES = ['admin', 'customer']
And add this to MIDDLEWARE_CLASSES:
    'CRUDFilters.managers.CRUDMiddleware',

In your API view...



---QuerySet vs Manager Methods---
There's an exception that references this ^ header, so keep it intact.

Queryset methods should raise exceptions if they've received an invalid request. That exception will
be returned with a 400 status code.

DO NOT define a queryset on your model, or that will override the "get_queryset" function for R operations.

Test all API endpoints to make sure we have role coverage on all.
Test all API endpoints to alert when a role is exposing all records.

Check permission classes- AllowAny shouldn't be enabled unless you have an anonymous role defined, and IsAuthenticated shouldn't be enabled if you have anonymous role

TODO:
Add a method CRUDManager.all_records function, that just returns queryset. Use that in place of any "all" functions
