import logging
import base64
import json
import re

from django.core.urlresolvers import resolve
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, REDIRECT_FIELD_NAME, logout
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.six.moves import StringIO
from django.conf import settings
from django.template.response import TemplateResponse
from django.contrib.auth.models import User
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.core.urlresolvers import Resolver404

from rest_framework import viewsets
from rest_framework.parsers import FormParser
from rest_framework.renderers import JSONRenderer
from rest_framework_expiring_authtoken.models import ExpiringToken

from .models import CRUDFilterModel, CRUDException
from .serializers import AbstractModelSerializer
from .forms import RoleForm
from .managers import CRUDManager
from django.contrib.sites.shortcuts import get_current_site

logger = logging.getLogger('crud_filters')

@sensitive_post_parameters()
@csrf_protect
@never_cache
def choose_role(request, template_name='choose_role.html',
                redirect_field_name=REDIRECT_FIELD_NAME,
                role_form=RoleForm,
                current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.POST.get(redirect_field_name,
                                   request.GET.get(redirect_field_name, ''))

    if request.method == "POST":
        form = role_form(request, data=request.POST)
        if form.is_valid():
            if form.data['role'].lower() == "anonymous":
                logout(request)
            request.session.update({'crud-role': form.data['role']})

            # Redirect to the "choose_filters" page, preserving the "?next=" GET params.
            url = "/choose_filters/?" + redirect_field_name + "=" + redirect_to
            return HttpResponseRedirect(url)
    else:
        form = role_form(request)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)


@sensitive_post_parameters()
@csrf_protect
@never_cache
def choose_filters(request, template_name='choose_filters.html',
                   redirect_field_name=REDIRECT_FIELD_NAME,
                   role_form=RoleForm,
                   current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.POST.get(redirect_field_name,
                                   request.GET.get(redirect_field_name, ''))

    if request.method == "POST":
        form = role_form(request, data=request.POST)
        if form.is_valid():
            if 'filter' in form.data.keys():
                filter_string = form.data['filter']
            else:
                filter_string = "__default"
            request.session.update({'crud-filters': filter_string})
            return HttpResponseRedirect(redirect_to)
    else:
        form = role_form(request)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)


class CRUDFilterModelViewSet(viewsets.ModelViewSet):
    # Defaults to none, and must be set by child class
    crud_model = None

    obj_id = None

    # By default, we implement an empty serializer. If the overriding crud_model is not an abstract model,
    # the user should override this variable or provide a get_serializer() function.
    serializer_class = AbstractModelSerializer

    # Allow the user to pass the "Role" header as a GET parameter (e.g. "?as_admin").
    # Insecure, and not recommended in the least.
    ALLOW_ROLE_GET_PARAMS = getattr(settings, "CRUD_ALLOW_ROLE_GET_PARAMS", False)

    def _parse_authentication(self):
        """
        Parse the authentication method and update the request object
        to include appropriately parsed authorization information
        """
        self.header_token = self.request.META.get('HTTP_AUTHORIZATION', None)
        if self.header_token is not None:
            auth = self.request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2:
                if auth[0].lower() == 'basic':
                    uname, colon, passwd = base64.b64decode(auth[1]).decode("utf-8").partition(':')
                    print("Logging in with email {email}, pwd {pwd}".format(email=uname, pwd=passwd))
                    self.user = authenticate(username=uname, password=passwd)
                    if self.user is None:
                        # Credentials were provided, but they were invalid (bad username/password).
                        logger.exception("User with username '{}' attempted to login with basic auth, but their credentials were invalid. ".format(uname))
                        raise CRUDException("Bad credentials", 401)
                elif auth[0].lower() == "token":
                    try:
                        token = auth[1]
                        token_obj = ExpiringToken.objects.get(key=token)
                        if token_obj.expired():
                            self.user = None
                            # Credentials were provided, but they were invalid (expired token).
                            logger.exception("Attempted login with expired token.")
                            raise CRUDException("Token has expired", 401)
                        else:
                            self.user = token_obj.user
                    except ExpiringToken.DoesNotExist:
                        self.user = None
                        # Credentials were provided, but they were invalid (bad or expired token).
                        logger.exception("User attempted to login with token auth, but their credentials were invalid. ")
                        raise CRUDException("Bad credentials", 401)
        elif '_auth_user_id' in self.request.session.keys():
            self.user = User.objects.get(id=self.request.session['_auth_user_id'])

    def _enforce_role_access_control(self):
        try:
            self.request.crud_filters = self.request.META['HTTP_FILTERS'].strip(" ").split(",")
        except KeyError:
            try:
                self.request.crud_filters = self.request.META['HTTP_CRUD_FILTERS'].strip(" ").split(",")
            except KeyError:
                # Check session for filters
                self.request.crud_filters = []
                if 'crud-filters' in self.request.session.keys():
                    self.request.crud_filters.append(self.request.session['crud-filters'])
                else:
                    # We didn't find any filters in the headers, let's look at GET params
                    for key in self.request.GET.keys():
                        # Only grab filters that are legit CRUDFilters (soon, we'll remove this and rely solely on
                        # the crud_filters header):
                        filters_for_this_role = CRUDManager.get_filter_set_for_model(self.crud_model)['filter'][self.request.crud_role]
                        valid_filters_for_this_role = [filter_name for filter_name, filter_value in filters_for_this_role.items() if filter_value is not None and filter_name != "__default"]
                        if key in valid_filters_for_this_role:
                            self.request.crud_filters.append(key)
        # Lowercase the filters:
        if not hasattr(self.request, 'crud_filters') or len(self.request.crud_filters) == 0:
            self.request.crud_filters = ['__default']
        else:
            self.request.crud_filters = [f.lower() for f in self.request.crud_filters]

        # For Update and Delete requests, make sure we have an ID (properly formed request)
        # TODO: update should be able to touch multiple objects, or update entire querysets
        if self.request.crud_operation == 'U':
            self.check_request_body_for_id(self.request)
        elif self.request.crud_operation == 'D':
            self.check_request_url_for_id(self.request)

        # Cursory check to make sure we have permissions on this view:
        self.crud_model.check_for_permissions(self.request.user, self.request.crud_role, self.request.crud_operation, self.request, self.request.crud_filters)

        # Retrieve (GET) operations will perform get_queryset later
        # Create (POST) operations don't need to get a queryset
        if self.request.crud_operation in ['U', 'D']:
            # Check that the object in question is in the queryset
            if not self.check_object_for_permissions(self.request):
                logger.exception("Operation {} cannot be performed on requested object".format(self.request.crud_operation))
                raise CRUDException("Cannot perform this operation on this object.", status_code=403)

    # For the time being, this only works with token and basic auth.
    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Perform simple authentication, then check that this user can use this role
        to perform this action (on this item).
        """
        if not hasattr(view_func, 'cls'):
            return None
        if not isinstance(view_func.cls(), CRUDFilterModelViewSet):
            return None
        # Create an instance of the ViewSet and get some variables from it.
        self.crud_model = view_func.cls().crud_model
        self.lookup_field = view_func.cls().lookup_field

        # Perform some authentication (Token and Basic).
        # TODO: figure out how to go AFTER DRF auth, so we have an authenticated user.
        self.request = request
        self.user = None
        # CAUTION!!!
        try:
            self._parse_authentication()
        except CRUDException as exception:
            return HttpResponse(exception.message, status=exception.status_code)

        if self.user is None:
            self.request.crud_role = "anonymous"
        else:
            # Default to "authenticated"
            self.request.crud_role = "authenticated"
            self.request.user = self.user
            try:
                self.request.crud_role = self.request.META['HTTP_ROLE'].lower()
            except KeyError:
                try:
                    self.request.crud_role = self.request.META['HTTP_CRUD_ROLE'].lower()
                except KeyError:
                    if 'crud-role' in request.session.keys():
                        self.request.crud_role = self.request.session['crud-role']
                    # We didn't find a role in the headers or session, let's look in the GET params.
                    elif self.ALLOW_ROLE_GET_PARAMS:
                        for key in self.request.GET.keys():
                            if key.startswith("as_"):
                                self.request.crud_role = key[3:].lower()

        if self.crud_model is None:
            logger.exception("CRUDFilterModel not specified on CRUDFilterModelViewSet {}".format(self))
            raise CRUDException("You must specify a CRUDFilterModel for this CRUDFilterModelViewSet", 500)
            return
        elif not issubclass(self.crud_model, CRUDFilterModel):
            logger.exception("CRUDFilterModel specified on CRUDFilterModelViewSet {} does not extend the CRUDFilter model".format(self))
            raise CRUDException("crud_model for CRUDFilterModelViewSet must extend CRUDFilterModel", 500)
        method = self.request.method
        if method == 'POST':
            self.request.crud_operation = 'C'
        elif method in ['GET', 'HEAD']:
            self.request.crud_operation = 'R'
        elif method in ['PUT', 'PATCH']:
            self.request.crud_operation = 'U'
        elif method == 'DELETE':
            self.request.crud_operation = 'D'
        elif method == 'OPTIONS':
            # TODO: tell the user what their options are here, given their desired role.
            # e.g. return_options_menu_for_this_user()
            return HttpResponse("Coming soon", status=405)
        else:
            return HttpResponse("Method not allowed", status=405)

        try:
            self._enforce_role_access_control()
        except CRUDException as exception:
            return HttpResponse(exception.message, status=exception.status_code)

        # We're good, let's move on!
        return None

    def process_exception(self, request, exception):
        """
        Middleware method to turn CRUDExceptions into proper HTTPResponses.
        """
        # TODO: why is this not catching CRUD exceptions?? We shouldn't have to catch exceptions in process_view
        if isinstance(exception, CRUDException):
            return HttpResponse(exception.message, status=exception.status_code)
        return None

    def process_response(self, request, response):
        if 'HTTP_ACCEPT' in request.META.keys() and 'text/html' in request.META['HTTP_ACCEPT']:
            try:
                path = resolve(request.path)
            except Resolver404:
                pass
            else:
                if hasattr(path.func, 'cls') and hasattr(path.func.cls, 'crud_model'):
                    request._request = request

                    if not hasattr(response, 'data'):
                        content = {"Error": response.content}
                    else:
                        renderer = JSONRenderer()
                        renderer_context = {'indent': 4}
                        content = renderer.render(response.data, "application/json", renderer_context)

                    renderer_context = {
                        'content': content,
                        'request': request,
                        'response': response,
                        'args': {},
                        'kwargs': {}
                    }
                    return TemplateResponse(request, "api.html", renderer_context).render()
        return response

    def get_queryset(self):
        """
        Overrides get_queryset for the ViewSet.
        TODO: At startup, warn if any views are overriding this function.
        """
        if self.request.crud_operation is None:
            operation = 'R'
        else:
            operation = self.request.crud_operation

        return self.try_to_get_queryset(self.request, operation)

    def try_to_get_queryset(self, request, operation):
        """
        Function to actually get queryset from the model. This is used by get_queryset, and
        separately to check if Update and Delete operations can act on the object in question.
        """
        if operation.upper() in ['U', 'D']:
            if not self.obj_id:
                self.check_request_url_for_id(request)
            queryset = self.crud_model.get_queryset_or_false(request.user, request.crud_role, operation, filters=request.crud_filters, request=request, _id=self.obj_id, lookup_field=self.lookup_field)
        else:
            queryset = self.crud_model.get_queryset_or_false(request.user, request.crud_role, operation, filters=request.crud_filters, request=request, lookup_field=self.lookup_field)

        if queryset is False:
            raise CRUDException("Operation is not available for this user", status_code=403)

        else:
            return queryset

    def check_object_for_permissions(self, request):
        """
        If we've gotten this far, this user with this role is allowed to
        use this method on this view. Now we just need to make sure the
        object they're trying to act on is in the queryset we've defined
        for this view.
        """
        if not self.obj_id:
            raise Exception("check_object_for_permissions called without a proper self.obj_id")
        # Build query based on lookup_field
        kwargs = {'{0}'.format(self.lookup_field): self.obj_id}
        if self.get_queryset().filter(**kwargs).count() > 0:
            return True
        else:
            return False

    def check_request_body_for_id(self, request):
        """
        An Update (PUT/PATCH) request must contain the ID of the object
        to be updated. Later, we can allow Update of multiple objects, or the
        entire queryset.
        """
        id = None
        try:
            data = request.data
            id = data[self.lookup_field]
        except (AttributeError, MultiValueDictKeyError):
            try:
                if "application/json" in request.META['CONTENT_TYPE']:
                    str_data = request.body.decode('utf-8')
                    # Make this into a properly-formatted JSON string.
                    id = self.id_from_json(str_data)

                elif "multipart/form-data" in request.META['CONTENT_TYPE']:
                    if self.lookup_field is 'id' or self.lookup_field is 'pk':
                        lookup_field_string = "(?:id|pk)"
                    else:
                        lookup_field_string = self.lookup_field
                    expression = re.compile('name="{lookup_field}"\r\n\r\n([^\r]+)\r\n'.format(lookup_field=lookup_field_string))

                    id_set = False
                    iterator = expression.finditer(request.body.decode('utf-8'))
                    for match in iterator:
                        id = match.groups()[0]
                        id_set = True

                    if not id_set:
                        id = self.id_from_json(request.body.decode('utf-8'))
                elif "application/x-www-form-urlencoded" in request.META['CONTENT_TYPE']:
                    parser = FormParser()
                    stream = StringIO(request.body.decode('utf-8'))
                    data = parser.parse(stream)

                    if self.lookup_field is 'id' or self.lookup_field is 'pk':
                        if 'id' in data:
                            id = data['id']
                        elif 'pk' in data:
                            id = data['pk']
                    else:
                        id = data[self.lookup_field]

            except AttributeError:
                return False
            except KeyError:
                logger.exception("Missing lookup field {} on view {} ".format(self.lookup_field, self))
                raise CRUDException("Missing {lookup_field}".format(lookup_field=self.lookup_field), 400)
            except ValueError:
                logger.exception("CRUDFilters received improper json.")
                raise CRUDException("Improper json", 400)
        try:
            if id is None:
                logger.exception("Missing lookup field {} on view {} ".format(self.lookup_field, self))
                raise CRUDException("Missing {lookup_field}".format(lookup_field=self.lookup_field), 400)

            self.obj_id = id

            return self.obj_id
        except KeyError:
            logger.exception("Update Operations must include {} in the request body.".format(self.lookup_field))
            raise CRUDException("Update operations must include " + self.lookup_field + " in the request body.", status_code=400)

    def id_from_json(self, str_data):
        id = None
        str_data = '{str_data}'.format(str_data=str_data.replace("'", '"'))
        try:
            data = json.loads(str_data)

            # Handle the json.dumps case, until we remove it from testing:
            if isinstance(data, str):
                data = json.loads(data)

            if self.lookup_field is 'pk' or self.lookup_field is 'id':
                if 'id' in data.keys():
                    id = data['id']
                else:
                    id = data['pk']
            else:
                id = data[self.lookup_field]
        except Exception:
            return None
        return id

    def check_request_url_for_id(self, request):
        """
        Make sure this request has id (or pk field) in request URL. Required for DRF deletion,
        and for single_read GET requests.
        """
        try:
            self.obj_id = request.resolver_match.kwargs[self.lookup_field]
            return self.obj_id
        except KeyError:
            logger.exception("Malformed request at URL {url}. CRUD role ({role}), filters ({filters}), operation ({operation}). Desired role {desired_role}. User {user}.".format(
                url=request.path,
                role=request.crud_role,
                filters=str(request.crud_filters),
                operation=request.crud_operation,
                desired_role=request.META.get('HTTP_CRUD_ROLE', '(none)'),
                user=str(request.user)
            ))
            raise CRUDException(request.method + " operations on this endpoint must include /" + self.lookup_field + "/ in the request URL.", status_code=400)

    def create(self, request, *args, **kwargs):
        """
        Default empty implementation of create(). User must override this function to get
        create functionality.
        """
        return HttpResponse("Method create not implemented by default", status=405)

    def update(self, request, *args, **kwargs):
        """
        Default empty implementation of update(). User must override this function to get
        update functionality.
        """
        return HttpResponse("Method update not implemented by default", status=405)

    def partial_update(self, request, *args, **kwargs):
        """
        Default empty implementation of partial_update(). User must override this function to get
        partial_update functionality.
        """
        return HttpResponse("Method partial_update not implemented by default", status=405)

    def patch(self, request, *args, **kwargs):
        """
        Default empty implementation of patch(). User must override this function to get
        patch functionality.
        """
        return HttpResponse("Method patch not implemented by default", status=405)

    def retrieve(self, request, *args, **kwargs):
        """
        Default implementation of retrieve(). Relies on our implementation of get_queryset.
        """
        # We implement GET functions by default, since we override get_queryset.
        return super(CRUDFilterModelViewSet, self).retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        """
        Default implementation of list(). Relies on our implementation of get_queryset.
        """
        # We implement GET functions by default, since we override get_queryset.
        return super(CRUDFilterModelViewSet, self).list(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        Default implementation of delete().
        """
        # We implement DELETE by default, but still check for permissions.
        return super(CRUDFilterModelViewSet, self).destroy(request, *args, **kwargs)
