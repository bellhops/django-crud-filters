from rest_framework import routers

from .views import TestClassViewset

router = routers.DefaultRouter()
router.register(r'test', TestClassViewset, base_name='api-test')

urlpatterns = router.urls
