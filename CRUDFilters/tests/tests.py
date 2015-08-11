import json
import base64
import random
from PIL import Image
from rest_framework_expiring_authtoken.models import ExpiringToken
import tempfile
from unittest import skip

from rest_framework import HTTP_HEADER_ENCODING
from rest_framework.test import APIClient
from rest_framework.reverse import reverse
from rest_framework import permissions
from rest_framework.test import APIRequestFactory

from django_dynamic_fixture import G
from django.contrib.auth.models import User
from django.core.urlresolvers import resolve

from django.conf import settings
from django.test import TransactionTestCase
from django.core.management import call_command

from ..models import CRUDFilterModel
from ..managers import CRUDManager, CRUDException
from .models import TestClass
from .views import TestClassViewset

# settings.configure()

test_roles = settings.CRUD_ALL_ROLES


def default_auth_function(role, user):
    return True


def always_fail_auth_function(role, user):
    return False


class CRUDFilterTestCase(TransactionTestCase):
    client = APIClient()

    def _pre_setup(self):
        self.expected_output = {}
        for role in CRUDManager.all_roles:
            self.expected_output[role] = {}
            for operation in ['C', 'R', 'U', 'D']:
                self.expected_output[role][operation] = {'__default': None}
        self.client = APIClient()

    def setUp(self):
        # If you override this test class, remember to set the following:
        CRUDManager.set_authorization_function(default_auth_function)


@skip("Interfering with other tests")
class CRUDFilterModelTests(CRUDFilterTestCase):

    def auth_function_returns_true(self, user, role):
        return True

    def auth_function_returns_false(self, user, role):
        return False

    def auth_function_throws_exception(self, user, role):
        raise Exception("Auth function exception")

    def test_verify_user_has_role_without_auth_function(self):
        CRUDManager.auth_function = None
        with self.assertRaises(CRUDException):
            TestClass.verify_user_has_role(test_roles[0], 'C')

    def test_verify_user_has_role_auth_function_throws_exception(self):
        CRUDManager.auth_function = self.auth_function_throws_exception
        with self.assertRaises(CRUDException):
            TestClass.verify_user_has_role(test_roles[0], 'C')

    def test_verify_user_has_role_auth_function_false(self):
        CRUDManager.auth_function = self.auth_function_returns_false
        with self.assertRaises(CRUDException):
            self.assertEqual(False, TestClass.verify_user_has_role(test_roles[0], 'C'))

    def test_verify_user_has_role_auth_function_true(self):
        CRUDManager.auth_function = self.auth_function_returns_true
        self.assertEqual(True, TestClass.verify_user_has_role(test_roles[0], 'C'))

    def test_role_can_perform_operation_with_bad_filter(self):
        with self.assertRaises(CRUDException):
            TestClass.role_can_perform_operation_with_filter('role', 'K', 'filter')


@skip("Interfering with other tests")
class CRUDFilterModelViewSetTests(CRUDFilterTestCase):

    def test_check_request_body_for_id_json(self):
        view = TestClassViewset()
        factory = APIRequestFactory()
        image = Image.new('RGB', (100, 100))
        self.tmp_file = tempfile.NamedTemporaryFile(suffix='.png')
        image.save(self.tmp_file)
        valid_creation_json = {"id": 1}

        request = factory.put(
            "url",
            data=valid_creation_json,
            format="json"
        )

        view.check_request_body_for_id(request)
        self.assertEquals(view.obj_id, 1)

    def test_check_request_body_for_id_json_dumps(self):
        view = TestClassViewset()
        factory = APIRequestFactory()
        image = Image.new('RGB', (100, 100))
        self.tmp_file = tempfile.NamedTemporaryFile(suffix='.png')
        image.save(self.tmp_file)
        valid_creation_json = {"id": 1}

        request = factory.put(
            "url",
            data=json.dumps(valid_creation_json),
            format="json"
        )

        view.check_request_body_for_id(request)
        self.assertEquals(view.obj_id, 1)

    def test_check_request_body_for_id_json_multipart(self):
        view = TestClassViewset()
        factory = APIRequestFactory()
        image = Image.new('RGB', (100, 100))
        self.tmp_file = tempfile.NamedTemporaryFile(suffix='.png')
        image.save(self.tmp_file)
        valid_creation_json = {'image': self.tmp_file, "id": 1}

        request = factory.put(
            "url",
            data=valid_creation_json,
            format="multipart"
        )

        view.check_request_body_for_id(request)
        self.assertEquals(view.obj_id, "1")


@skip("Interfering with other tests")
class CRUDManagerTests(CRUDFilterTestCase):

    model = CRUDFilterModel()

    def setUp(self):
        # Reset CRUDManager variables
        CRUDManager.auth_function = None
        CRUDManager.filter_set = {}

        for count in range(100):
            TestClass.objects.create(
                field_one=count % 1 == 0,
                field_two=count % 2 == 0,
                field_three=count % 3 == 0,
                field_four=count % 4 == 0,
                field_five=count % 5 == 0
            )

    def test_init_filter_set_for_model(self):
        # TestClass shouldn't be represented in filter_set yet.
        self.assertTrue(str(TestClass) not in CRUDManager.filter_set.keys())

        # Call init
        CRUDManager.init_filter_set_for_model(TestClass)

        # Look for model filter_set
        self.assertTrue(str(TestClass) in CRUDManager.filter_set.keys())
        model_filter_set = CRUDManager.filter_set[str(TestClass)]
        self.verify_model_filter_set_structure(model_filter_set)

    def test_get_filter_set_for_model_before_init(self):
        # TestClass shouldn't be represented in filter_set yet.
        self.assertTrue(str(TestClass) not in CRUDManager.filter_set.keys())

        # Call get_filter_set_for_model, and verify that this initializes filter_set for this model
        model_filter_set = CRUDManager.get_filter_set_for_model(TestClass)
        self.verify_model_filter_set_structure(model_filter_set)

    def verify_model_filter_set_structure(self, model_filter_set):
        # Look for 'filter' dict
        self.assertTrue('filter' in model_filter_set.keys())
        filters = model_filter_set['filter']
        # Look for 'allowed_method' dict
        self.assertTrue('allowed_methods' in model_filter_set.keys())
        allowed_methods = model_filter_set['allowed_methods']
        # Look for all roles, and check for '__default' = None
        default = '__default'
        for role in test_roles:
            self.assertTrue(role in filters.keys())
            filters_role = filters[role]
            self.assertTrue(default in filters_role.keys())
            self.assertEqual(filters_role[default], None)

            self.assertTrue(role in allowed_methods.keys())
            allowed_methods_role = allowed_methods[role]
            self.assertTrue(default in allowed_methods_role.keys())
            self.assertEqual(allowed_methods_role[default], None)

    def test_set_authorization_function(self):
        self.assertEqual(CRUDManager.auth_function, None)
        CRUDManager.set_authorization_function(always_fail_auth_function)
        self.assertEqual(CRUDManager.auth_function, always_fail_auth_function)

    def test_add_permissions_invalid_permission(self):
        with self.assertRaises(CRUDException):
            CRUDManager.add_permissions(TestClass, 'NOT_A_VALID_PERMISSION', test_roles[0], TestClass.objects.field_one_true)

    def test_add_permissions_non_function(self):
        not_a_function = 3.14159
        with self.assertRaises(CRUDException):
            CRUDManager.add_permissions(TestClass, 'R', test_roles[0], not_a_function)

    def test_add_permissions_invalid_role(self):
        with self.assertRaises(CRUDException):
            CRUDManager.add_permissions(TestClass, 'C', 'NOT_A_VALID_ROLE', TestClass.objects.field_one_true)

    def test_add_permissions_succeeds_with_default_filter(self):
        CRUDManager.add_permissions(TestClass, 'C', test_roles[0], TestClass.objects.field_one_true)
        CRUDManager.filter_set[str(TestClass)]['allowed_methods'][test_roles[0]]['__default'] = TestClass.objects.field_one_true

    def test_add_permissions_succeeds_with_explicit_filter(self):
        CRUDManager.add_permissions(TestClass, 'CR', test_roles[0], TestClass.objects.field_one_true, 'filter_string')
        self.assertEqual(CRUDManager.filter_set[str(TestClass)]['filter'][test_roles[0]]['filter_string'], TestClass.objects.field_one_true)
        self.assertEqual(CRUDManager.filter_set[str(TestClass)]['allowed_methods'][test_roles[0]]['filter_string'], 'CR')


@skip("Interfering with other tests")
class CRUDFilterIntegrationTestClass(CRUDFilterTestCase):
    """
    This test class checks for permissions on models.
    By default, it uses an auth function that will always return True, so that
    setting up a test user is not a concern. This can be overridden in "setUp".
    By default, it uses django_dynamic_fixture to create a User, creates an auth
    token for that user, and uses Token authentication. This can be overridden by
    passing an auth header to the verify_requests_against_expectations() function.
    """
    authentication_header = None

    # Status code groups
    success_status_codes = {'start': 200, 'end': 206}
    failure_status_codes = {'start': 403, 'end': 404}

    valid_creation_json = None

    def _pre_setup(self):
        CRUDManager.set_authorization_function(default_auth_function)
        self.user = G(User)
        self.token, created = ExpiringToken.objects.get_or_create(user=self.user)

        self.expected_output = {}
        for role in CRUDManager.all_roles:
            self.expected_output[role] = {}
            for operation in ['C', 'R', 'U', 'D']:
                self.expected_output[role][operation] = {'__default': None}
        self.client = APIClient()

        # Disable REST_FRAMEWORK pagination, if it exists.
        try:
            rest_framework_settings = settings.REST_FRAMEWORK
            rest_framework_settings['PAGINATE_BY'] = None
            rest_framework_settings['DEFAULT_PERMISSION_CLASSES'] = ('rest_framework.permissions.AllowAny',)
        except (AttributeError, KeyError):
            pass

    def verify_requests_against_expectations(self, object_class, base_url, auth_header=None, id_name="id", nested_key="results", operations_to_test=['C', 'R', 'U', 'D'], content_type='application/json'):
        """
        Test all roles and filters against expectations.
        """
        # First, remove any pagination on the viewset (for tests only)
        # TODO: this won't work if a pagination_class is set.
        view_class, view_args, view_kwargs = resolve(base_url)
        view_class.cls.paginate_by = None
        # Remove any permissions, so we're testing the full range of filters
        view_class.cls.permission_classes = (permissions.AllowAny,)

        if not base_url.endswith('/'):
            base_url += "/"

        # If the user didn't specify an auth header, use the default:
        if auth_header is None:
            self.authentication_header = 'Token ' + self.token.key
        else:
            self.authentication_header = auth_header
        for role in CRUDManager.all_roles:
            for operation in operations_to_test:
                write_operation_performed = False

                if role != 'anonymous':
                    self.client.credentials(HTTP_AUTHORIZATION=self.authentication_header)
                    # print("Reset auth header to ", self.authentication_header)
                else:
                    self.client.credentials(HTTP_AUTHORIZATION=None)

                for filter_str in self.expected_output[role][operation].keys():
                    expected_object_set = self.expected_output[role][operation][filter_str]
                    if expected_object_set is not None:
                        expected_object_ids = [getattr(inst, id_name) for inst in expected_object_set]
                        expected_status_code_group = self.success_status_codes
                        if operation != 'R':
                            write_operation_performed = True
                    else:
                        expected_object_ids = []
                        expected_status_code_group = self.failure_status_codes

                    headers = {'HTTP_ROLE': role}
                    if filter_str != "__default":
                        # This hasn't been working when setting APIClient headers:
                        headers.update({'HTTP_FILTER': filter_str})
                        # So we'll add the GET param later, too.
                        url_filter_str = "?" + filter_str
                    else:
                        url_filter_str = ""

                    if operation == 'C':
                        response = self.client.post(
                            base_url + url_filter_str,
                            data=self.valid_creation_json,
                            content_type=content_type,
                            **headers
                        )
                        self.assertTrue(self.check_status_code_in_group(response.status_code, expected_status_code_group))
                        # logic check here
                        write_operation_performed = True

                    elif operation == 'R':
                        # Make sure the "list" view returns all the objects we want it to.
                        response = self.client.get(
                            base_url + url_filter_str,
                            **headers
                        )
                        self.assertTrue(self.check_status_code_in_group(response.status_code, expected_status_code_group))

                        if expected_object_set is None:
                            pass
                        else:
                            if nested_key is not None:
                                response_ids = set([inst[id_name] for inst in response.data[nested_key]])
                            else:
                                response_ids = set([inst[id_name] for inst in response.data])
                            self.assertEqual(
                                response_ids,
                                set(expected_object_ids),
                                "Make sure object is in queryset, and make sure your filter function returns a Django Model, Manager, or QuerySet"
                            )

                        # For each object, make sure the "detail" view is only returning the objects we can view.
                        if hasattr(object_class, 'objects'):
                            for obj in object_class.objects.all():
                                url = base_url + "{id}/".format(id=getattr(obj, id_name))
                                response = self.client.get(
                                    url + url_filter_str,
                                    **headers
                                )

                                if getattr(obj, id_name) in expected_object_ids:
                                    self.assertTrue(self.check_status_code_in_group(response.status_code, expected_status_code_group))
                                    # Single-object GET requests aren't nested under nested_key
                                    response_id = response.data[id_name]
                                    self.assertEqual(response_id, getattr(obj, id_name))
                                    # check for 200 response code
                                else:
                                    if not self.check_status_code_in_group(response.status_code, self.failure_status_codes):
                                        pass
                                    self.assertTrue(self.check_status_code_in_group(response.status_code, self.failure_status_codes))

                    elif operation == 'U':
                        # For each object, make sure we can update.
                        if hasattr(object_class, 'objects'):
                            for obj in object_class.objects.all():
                                update_json = self.valid_creation_json.copy()
                                update_json.update({id_name: getattr(obj, id_name)})

                                patch_response = self.client.patch(
                                    base_url + url_filter_str,
                                    data=update_json,
                                    content_type=content_type,
                                    **headers
                                )

                                url = base_url + "{id}/".format(id=getattr(obj, id_name))
                                put_response = self.client.put(
                                    url + url_filter_str,
                                    data=update_json,
                                    content_type=content_type,
                                    **headers
                                )

                                # Should be: at least one passed, or both failed
                                if getattr(obj, id_name) in expected_object_ids:
                                    expected_status_code_group = self.success_status_codes
                                    self.assertTrue(
                                        self.check_status_code_in_group(patch_response.status_code, expected_status_code_group) or
                                        self.check_status_code_in_group(put_response.status_code, expected_status_code_group)
                                    )
                                    write_operation_performed = True
                                else:
                                    expected_status_code_group = self.failure_status_codes
                                    self.assertTrue(
                                        self.check_status_code_in_group(patch_response.status_code, expected_status_code_group) and
                                        self.check_status_code_in_group(put_response.status_code, expected_status_code_group)
                                    )

                    elif operation == 'D':
                        # For each object, make sure we can delete.
                        if hasattr(object_class, 'objects'):
                            for obj in object_class.objects.all():
                                url = base_url + "{id}/".format(id=getattr(obj, id_name))
                                response = self.client.delete(
                                    url + url_filter_str,
                                    **headers
                                )
                                if getattr(obj, id_name) in expected_object_ids:
                                    self.assertTrue(self.check_status_code_in_group(response.status_code, expected_status_code_group))
                                    write_operation_performed = True
                                else:
                                    self.assertTrue(self.check_status_code_in_group(response.status_code, self.failure_status_codes))

                    if write_operation_performed:
                        old_auth_header = self.authentication_header
                        call_command('flush', interactive=False, reset_sequences=False)
                        self.setUp()
                        assert self.authentication_header != old_auth_header, "Must reset self.authentication_header in setup()"

    def check_status_code_in_group(self, status_code, group):
        return int(status_code) >= group['start'] and int(status_code) <= group['end']


@skip("Interfering with other tests")
class ExampleIntegrationTests(CRUDFilterIntegrationTestClass):
    def setUp(self):
        username = "user@name.com"
        password = ''.join(random.choice("abcdefghijklm1234567890") for _ in range(20))
        self.superuser = G(User, is_superuser=True, username=username)
        self.superuser.set_password(password)
        self.superuser.save()
        assert(self.superuser.check_password(password))

        credentials = ('%s:%s' % (username, password))
        base64_credentials = base64.b64encode(credentials.encode(HTTP_HEADER_ENCODING)).decode(HTTP_HEADER_ENCODING)
        self.authentication_header = 'Basic %s' % base64_credentials
        self.client.credentials(HTTP_AUTHORIZATION=self.authentication_header)

        # Reset CRUDManager variables
        CRUDManager.auth_function = default_auth_function

        # Make a whole bunch of objects
        for count in range(100):
            TestClass.objects.create(
                field_one=count % 1 == 0,
                field_two=count % 2 == 0,
                field_three=count % 3 == 0,
                field_four=count % 4 == 0,
                field_five=count % 5 == 0
            )

    def test_nothing_allowed(self):
        # Don't add model permissions, and don't add expectations.
        CRUDManager.filter_set = {}
        url = reverse('api-test-list')
        self.verify_requests_against_expectations(TestClass, url, self.authentication_header, nested_key=None)

    def test_only_anon_allowed(self):
        CRUDManager.filter_set = {}
        CRUDManager.add_permissions(TestClass, 'R', 'anonymous', TestClass.objects.field_three_true)

        # Set expectations:
        self.expected_output['anonymous']['R']['__default'] = TestClass.objects.field_three_true(TestClass.objects.all(), self.user, None)

        url = reverse('api-test-list')
        self.verify_requests_against_expectations(TestClass, url, self.authentication_header, nested_key=None)

    def test_random_combinations(self):
        CRUDManager.filter_set = {}
        CRUDManager.add_permissions(TestClass, 'RD', 'anonymous', TestClass.objects.field_three_true)
        CRUDManager.add_permissions(TestClass, 'R', 'authenticated', TestClass.objects.field_one_true)
        CRUDManager.add_permissions(TestClass, 'CRU', test_roles[0], CRUDManager.all_objects)
        CRUDManager.add_permissions(TestClass, 'UD', test_roles[1], TestClass.objects.field_two_true)
        CRUDManager.add_permissions(TestClass, 'CR', test_roles[2], TestClass.objects.field_four_true)
        CRUDManager.add_permissions(TestClass, 'CD', test_roles[3], TestClass.objects.field_five_true)
        CRUDManager.add_permissions(TestClass, 'CRUD', test_roles[4], TestClass.objects.no_objects)

        # Set expectations:
        self.expected_output['anonymous']['R']['__default'] = TestClass.objects.field_three_true(TestClass.objects.all(), self.user, None)
        self.expected_output['anonymous']['D']['__default'] = TestClass.objects.field_three_true(TestClass.objects.all(), self.user, None)

        self.expected_output['authenticated']['R']['__default'] = TestClass.objects.field_one_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[0]]['C']['__default'] = TestClass.objects.all()
        self.expected_output[test_roles[0]]['R']['__default'] = TestClass.objects.all()
        self.expected_output[test_roles[0]]['U']['__default'] = TestClass.objects.all()

        self.expected_output[test_roles[1]]['U']['__default'] = TestClass.objects.field_two_true(TestClass.objects.all(), self.user, None)
        self.expected_output[test_roles[1]]['D']['__default'] = TestClass.objects.field_two_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[2]]['C']['__default'] = TestClass.objects.field_four_true(TestClass.objects.all(), self.user, None)
        self.expected_output[test_roles[2]]['R']['__default'] = TestClass.objects.field_four_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[3]]['C']['__default'] = TestClass.objects.field_five_true(TestClass.objects.all(), self.user, None)
        self.expected_output[test_roles[3]]['D']['__default'] = TestClass.objects.field_five_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[4]]['C']['__default'] = TestClass.objects.none()
        self.expected_output[test_roles[4]]['R']['__default'] = TestClass.objects.none()
        self.expected_output[test_roles[4]]['U']['__default'] = TestClass.objects.none()
        self.expected_output[test_roles[4]]['D']['__default'] = TestClass.objects.none()

        url = reverse('api-test-list')
        self.verify_requests_against_expectations(TestClass, url, self.authentication_header, nested_key=None)

    def test_random_combinations_with_filters(self):
        CRUDManager.filter_set = {}
        CRUDManager.add_permissions(TestClass, 'RD', 'anonymous', TestClass.objects.field_three_true, 'three')
        CRUDManager.add_permissions(TestClass, 'R', 'authenticated', TestClass.objects.field_one_true, 'one')
        CRUDManager.add_permissions(TestClass, 'CRU', test_roles[0], CRUDManager.all_objects, 'all')
        CRUDManager.add_permissions(TestClass, 'UD', test_roles[1], TestClass.objects.field_two_true)
        CRUDManager.add_permissions(TestClass, 'CR', test_roles[2], TestClass.objects.field_four_true, 'four')
        CRUDManager.add_permissions(TestClass, 'CD', test_roles[3], TestClass.objects.field_five_true)
        CRUDManager.add_permissions(TestClass, 'CRUD', test_roles[4], TestClass.objects.no_objects, 'none')

        # Set expectations:
        self.expected_output['anonymous']['R']['three'] = TestClass.objects.field_three_true(TestClass.objects.all(), self.user, None)
        self.expected_output['anonymous']['D']['three'] = TestClass.objects.field_three_true(TestClass.objects.all(), self.user, None)

        self.expected_output['authenticated']['R']['one'] = TestClass.objects.field_one_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[0]]['C']['all'] = TestClass.objects.all()
        self.expected_output[test_roles[0]]['R']['all'] = TestClass.objects.all()
        self.expected_output[test_roles[0]]['U']['all'] = TestClass.objects.all()

        self.expected_output[test_roles[1]]['U']['__default'] = TestClass.objects.field_two_true(TestClass.objects.all(), self.user, None)
        self.expected_output[test_roles[1]]['D']['__default'] = TestClass.objects.field_two_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[2]]['C']['four'] = TestClass.objects.field_four_true(TestClass.objects.all(), self.user, None)
        self.expected_output[test_roles[2]]['R']['four'] = TestClass.objects.field_four_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[3]]['C']['__default'] = TestClass.objects.field_five_true(TestClass.objects.all(), self.user, None)
        self.expected_output[test_roles[3]]['D']['__default'] = TestClass.objects.field_five_true(TestClass.objects.all(), self.user, None)

        self.expected_output[test_roles[4]]['C']['none'] = TestClass.objects.none()
        self.expected_output[test_roles[4]]['R']['none'] = TestClass.objects.none()
        self.expected_output[test_roles[4]]['U']['none'] = TestClass.objects.none()
        self.expected_output[test_roles[4]]['D']['none'] = TestClass.objects.none()

        url = reverse('api-test-list')
        self.verify_requests_against_expectations(TestClass, url, self.authentication_header, nested_key=None)
