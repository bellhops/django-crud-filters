from django.db import models

from CRUDFilters.models import CRUDFilterModel
from .managers import TestManager


# PRO TIPS!
# If you change this model, you should do the following.
#   - Add CRUDFilters.tests to settings.INSTALLED_APPS.
#   - Run makemigrations
#   - Move migrations from CRUDFilters/migrations/* to CRUDFilters/tests/migrations/
#   - Remove CRUDFilters.tests from settings.INSTALLED_APPS
#
# Because of the way we made migrations, this package might only be Django 1.7+ compatible
#
class TestClass(CRUDFilterModel):
    field_one = models.BooleanField(default=False)
    field_two = models.BooleanField(default=False)
    field_three = models.BooleanField(default=False)
    field_four = models.BooleanField(default=False)
    field_five = models.BooleanField(default=False)

    objects = TestManager

    class Meta:
        app_label = 'testapp'
