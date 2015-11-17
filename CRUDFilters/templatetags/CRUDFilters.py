import inspect
import re

from django import template
from django.core.urlresolvers import reverse, NoReverseMatch
from django.utils.html import escape
from django.core.urlresolvers import resolve

from rest_framework.authentication import TokenAuthentication, BasicAuthentication

from CRUDFilters.managers import CRUDManager

register = template.Library()


@register.simple_tag
def change_role(request, user):
    """
    Include a menu item for 'Change Role'.
    """
    try:
        choose_role_url = reverse('CRUDFilters:choose_role')
    except NoReverseMatch:
        return ''

    snippet = "<li><a href='{href}?next={next}'>Change Role</a></li>".format(href=choose_role_url, next=escape(request.path))
    return snippet


@register.simple_tag
def print_available_options(request):
    """
    Print the filter set for this model.
    """
    path = resolve(request.path)
    allowed_methods = CRUDManager.get_filter_set_for_model(path.func.cls.crud_model)['allowed_methods']

    htmlLines = []
    all_roles_for_user = ''
    for role in CRUDManager.get_filter_set_for_model(path.func.cls.crud_model)['filter'].keys():
        # Decide if we can show this info to this user.
        if role == 'anonymous':
            can_view_role = True
        elif role == 'authenticated':
            can_view_role = request.user.is_authenticated()
        elif role == "admin":
            can_view_role = request.user.is_superuser
        else:
            can_view_role = CRUDManager.auth_function(role, request.user, request)

        if can_view_role:
            all_roles_for_user += str(allowed_methods[role].values()).replace("dict_values", "")

            if role not in ['authenticated', 'anonymous']:
                header_string = ' -H "CRUD-Role: ' + role + '"'
            else:
                header_string = ''
            if role != 'anonymous' and TokenAuthentication in path.func.cls.authentication_classes:
                auth_string = ' -H "Authorization: Token ' + request.user.auth_token.key + '"'
            elif role != 'anonymous' and BasicAuthentication in path.func.cls.authentication_classes:
                auth_string = ' -H "Authorization: Basic (base64 encoding of "username:password")"'
            else:
                auth_string = ''

            # Make sure this role can perform at least one operation on this view:
            if not all(value is None for value in allowed_methods[role].values()):
                filters = CRUDManager.get_filter_set_for_model(path.func.cls.crud_model)['filter'][role]
                htmlLines.append("<br><b><u> Role " + role + "</b></u>")

                for filter_str in filters.keys():
                    filter_func = filters[filter_str]
                    methods = allowed_methods[role][filter_str]
                    if methods is None:
                        methods = "(none)"

                    if filter_str == '__default':
                        filters_string = ''
                        filter_str = "no filter: "
                    else:
                        filters_string = ' -H "CRUD-Filters: ' + filter_str + '"'
                        filter_str = "filter '{filter_str}': ".format(filter_str=filter_str)
                    htmlLines.append("Operations " + methods + " with " + filter_str)
                    if filter_func is not None and methods != 'C':
                        doc_string = filter_func.__doc__
                        if doc_string is None:
                            doc_string = "(No doc string available for this function)"
                        doc_string = doc_string.replace("\n", "")
                        # Remove all duplicate whitespace
                        doc_string = ' '.join(doc_string.split())
                        htmlLines.append("     Uses objects from function '<i>" + doc_string + "</i>'")
                    try:
                        full_url = request.META['werkzeug.request'].base_url
                        htmlLines.append("     Example using CURL and GET: <i>\'curl -X GET " + full_url + header_string + filters_string + auth_string + '</i>\'')
                    except KeyError:
                        htmlLines.append("     (Could not create example CURL commands)")

    # This sucks, but if any of the users have 'C' as an allowed method (gross),
    # grab the code from our create function (ummm), and use regular expressions
    # (what?!) to find the required_params and optional_params dictionaries (WHY?!).
    #
    # Note: this doesn't work when there's a method decorator like rate_limit.
    #
    # TODO: Extract the required_params and optional_params design pattern up one
    # level, so that (among other things) we can do away with this.
    if 'C' in all_roles_for_user:
        source_string = inspect.getsource(path.func.cls.create)

        required_expression = re.compile('required_params[\s]*=[\s]*(([\[\{]){1}[^\]]*[\]\}]{1})')
        required_iterator = required_expression.finditer(source_string)
        htmlLines.append("<br><b><u>Required 'Create' POST Parameters:</u></b>")
        required_string = "(none)"
        for match in required_iterator:
            required_string = match.groups()[0]
            required_string = ' '.join(required_string.split())
        htmlLines.append(required_string)

        optional_expression = re.compile('optional_params[\s]*=[\s]*(([\[\{]){1}[^\]]*[\]\}]{1})')
        optional_iterator = optional_expression.finditer(source_string)
        htmlLines.append("<br><b><u>Optional 'Create' POST Parameters:</u></b>")
        optional_string = "(none)"
        for match in optional_iterator:
            optional_string = match.groups()[0]
            optional_string = ' '.join(optional_string.split())
        htmlLines.append(optional_string)

    htmlText = '\n'.join(htmlLines)
    return htmlText


def available_roles(user, request):
    """
    Print the available roles for this user
    """
    available_roles = []
    for role in CRUDManager.all_roles:
        if role in ['anonymous', 'authenticated']:
            available_roles.append(role)
        elif role == "admin" and user.is_superuser:
            available_roles.append(role)
        elif CRUDManager.auth_function(role, user, request):
            available_roles.append(role)
    return available_roles


@register.simple_tag
def print_available_roles(request):
    return_string = ""
    for role in available_roles(request.user, request):
        return_string += "<br>    " + role + ": "
    return return_string


@register.simple_tag
def print_roles(request, user):
    """
    Include all roles available for this user
    """
    return_string = ""
    for role in available_roles(user, request):
            return_string += '<input style="width: 20%" type="radio" name="role"  value="' + role + '">' + role.title() + '<br>'
    return return_string


@register.simple_tag
def print_filters(request):
    """
    Include all filters available for this user and role (role is set in session vars)
    """
    redirect_field_name = "next"
    redirect_to = request.POST.get(redirect_field_name,
                                   request.GET.get(redirect_field_name, ''))

    path = resolve(redirect_to)

    role = request.session['crud-role']

    filters = CRUDManager.get_filter_set_for_model(path.func.cls.crud_model)['filter'][role]
    valid_filters = [filter_name for filter_name, filter_value in filters.items() if filter_value is not None]

    return_string = ''
    for filter_str in valid_filters:
        if filter_str == "__default":
            display_str = "(No Filter)"
        else:
            display_str = filter_str.title()
        return_string += '<input style="width: 20%" type="radio" name="filter"  value="' + filter_str + '">' + display_str + '<br>'

    if return_string == '':
        return_string = '(No filters on this view. Click "Continue.")'
    else:
        return_string += "<br> "
    return return_string
