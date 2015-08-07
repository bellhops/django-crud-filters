"""
Views that allow a user to pick the CRUDFilters Role they want to use on
the browable django-rest-framework pages.

Add these to your root URLconf to enable role switching:
    urlpatterns = [
        ...
        url(r'^choose_role/', include('CRUDFilters.urls', namespace='CRUDFilters'))
    ]
Make sure your authentication settings include `SessionAuthentication`.

"""

from __future__ import unicode_literals
from django.conf.urls import url
from .views import choose_role, choose_filters

role_template_name = {'template_name': 'choose_role.html'}
filters_template_name = {'template_name': 'choose_filters.html'}

urlpatterns = [
    url(r'^choose_role/$', choose_role, role_template_name, name='choose_role'),
    url(r'^choose_filters/$', choose_filters, filters_template_name, name='choose_filters'),
]
