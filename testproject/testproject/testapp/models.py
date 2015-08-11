from django.db import models

from CRUDFilters.models import CRUDFilterModel
from .managers import TestManager


class TestClass(CRUDFilterModel):
    field_one = models.BooleanField(default=False)
    field_two = models.BooleanField(default=False)
    field_three = models.BooleanField(default=False)
    field_four = models.BooleanField(default=False)
    field_five = models.BooleanField(default=False)

    objects = TestManager

    class Meta:
        app_label = 'testapp'
