=====
CRUDFilters
=====

The CRUDFilters package provides an easy, semantic way to do authorization on API endpoints. 
It locks all users out by default, and only allows specified actions for specified "roles." 
For each endpoint, you can specify which roles can perform which actions on which querysets.

You now have to pass a "Role" header on most requests.
"anonymous" and "authenticated" are valid roles, and don't require the Role header. Every other role has to be specified in the header.
Filters can be passed as comma-separated values in the "Filters" header, or as get parameters (e.g. /api/v1_3/orders/?claimable).

Quick start
-----------

1. Add "django-crud-filters" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
        ...
        'django-crud-filters',
    )

2. Include the polls URLconf in your project urls.py like this::

    url(r'^crud-filters/', include('django-crud-filters.urls')),

3. Run `python manage.py migrate` to create the CRUD filter models.