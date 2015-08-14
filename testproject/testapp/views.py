from django.http import HttpResponse
from rest_framework import permissions

from CRUDFilters.views import CRUDFilterModelViewSet

from .models import TestClass
from .serializers import TestClassSerializer


class TestClassViewset(CRUDFilterModelViewSet):
    serializer_class = TestClassSerializer
    crud_model = TestClass

    permission_classes = (permissions.AllowAny,)

    def create(self, request, *args, **kwargs):
        return HttpResponse("Everything's fine here", status=200)

    def update(self, request, *args, **kwargs):
        return HttpResponse("Everything's fine here", status=200)

    def partial_update(self, request, *args, **kwargs):
        return HttpResponse("Everything's fine here", status=200)

    def destroy(self, request, *args, **kwargs):
        return HttpResponse("Everything's fine here", status=200)

    def patch(self, request, *args, **kwargs):
        return HttpResponse("Everything's fine here", status=200)
